#!/bin/bash
#
# net-proto-sfg-parity: verify PF coverage parity between the two net
# dispatch tables.
#
# Background: net/protocols.c holds net_protocols[TRINITY_PF_MAX], a
# PF-indexed dispatch table of struct netproto handlers used by
# sfg_default_pick_triplet() and sfg_default_bind() to fabricate
# sockaddrs and pick valid (family, type, protocol) triplets.  The
# sibling table net/socket-family-grammar.c::sfg_registry[] holds
# the per-family grammars driven by socket-family-chain childops.
# Both tables are keyed by PF number.
#
# A grammar registered for a PF that has no netproto entry is a
# NULL-deref waiting to happen the first time sfg_default_bind() or
# sfg_default_pick_triplet() runs against it -- both dereference
# net_protocols[family].proto unconditionally after the range check.
# A netproto entry with no grammar is silent coverage: that family's
# fuzz surface never gets driven through the socket-family-chain
# path.  Either direction is a silent divergence today because
# neither table cross-references the other at compile time.
#
# This check parses both tables from source, resolves each
# &grammar_XXX registry entry to its .family by locating the
# grammar's initializer in net/proto-*.c, then diffs the two PF
# sets.  Pre-existing "netproto entry, no grammar" gaps are
# grandfathered via net-proto-sfg-parity.baseline; a fresh gap on
# either side FAILs the check.  A grammar registered for a PF with
# no netproto entry FAILs unconditionally -- there is no correct
# scenario for that direction, so no baseline path exists.
#
# Preprocessor guards are ignored on purpose: source-level presence
# is the parity signal.  If a family is inconsistently guarded
# across the two tables (e.g. `#ifdef X` in one, `#ifdef Y` in the
# other) the divergence surfaces at compile time, not here.

set -u

NAME="net-proto-sfg-parity"
ROOT="${REPO_ROOT:-$(pwd)}"
PROTO_SRC="$ROOT/net/protocols.c"
SFG_SRC="$ROOT/net/socket-family-grammar.c"
BASELINE="$ROOT/scripts/check-static/net-proto-sfg-parity.baseline"

fail() {
	echo "FAIL: $NAME: $1" >&2
	exit 1
}

[ -r "$PROTO_SRC" ] || fail "cannot read $PROTO_SRC"
[ -r "$SFG_SRC" ]   || fail "cannot read $SFG_SRC"

# Extract every `[PF_XXX] = ...` designator from the net_protocols
# initializer.  Multiple designators per line are handled.
proto_pfs=$(awk '
	/const struct protoptr net_protocols\[TRINITY_PF_MAX\][[:space:]]*=[[:space:]]*\{/ {
		in_block = 1; next
	}
	in_block && /^\};/ { in_block = 0; exit }
	in_block {
		line = $0
		while (match(line, /\[[[:space:]]*PF_[A-Z0-9_]+[[:space:]]*\]/)) {
			tok = substr(line, RSTART, RLENGTH)
			gsub(/[][[:space:]]/, "", tok)
			print tok
			line = substr(line, RSTART + RLENGTH)
		}
	}
' "$PROTO_SRC" | sort -u)

[ -n "$proto_pfs" ] || fail "no PF entries parsed from $PROTO_SRC"

# Collect every &grammar_xxx symbol from sfg_registry[].  The
# trailing NULL sentinel is not a symbol reference so is skipped
# naturally.
grammar_names=$(awk '
	/const struct socket_family_grammar \* const sfg_registry\[\][[:space:]]*=[[:space:]]*\{/ {
		in_block = 1; next
	}
	in_block && /^\};/ { in_block = 0; exit }
	in_block {
		line = $0
		while (match(line, /&grammar_[a-z0-9_]+/)) {
			tok = substr(line, RSTART + 1, RLENGTH - 1)
			print tok
			line = substr(line, RSTART + RLENGTH)
		}
	}
' "$SFG_SRC" | sort -u)

[ -n "$grammar_names" ] || fail "no &grammar_* entries parsed from $SFG_SRC"

# Resolve each grammar symbol to its .family by scanning
# net/proto-*.c for the initializer.  Accept AF_ and PF_ prefixes
# (uapi aliases; grammar_packet and grammar_xdp use AF_).  Bare
# integer literals are not accepted -- every in-tree grammar uses
# the macro form.
grammar_pfs_raw=$(
	for gname in $grammar_names; do
		fam=$(awk -v g="$gname" '
			$0 ~ "^const struct socket_family_grammar " g " = \\{" {
				in_block = 1; next
			}
			in_block && /^\};/ { in_block = 0; exit }
			in_block && /\.family[[:space:]]*=/ {
				if (match($0, /(PF|AF)_[A-Z0-9_]+/)) {
					tok = substr($0, RSTART, RLENGTH)
					sub(/^AF_/, "PF_", tok)
					print tok
					exit
				}
			}
		' "$ROOT"/net/proto-*.c 2>/dev/null | head -n1)

		if [ -z "$fam" ]; then
			echo "UNRESOLVED:$gname"
		else
			echo "$fam"
		fi
	done
)

unresolved=$(printf '%s\n' "$grammar_pfs_raw" | grep '^UNRESOLVED:' || true)
if [ -n "$unresolved" ]; then
	{
		echo "  $NAME: could not resolve .family for grammar symbol(s):"
		printf '%s\n' "$unresolved" | sed 's/^UNRESOLVED:/    /'
		echo "  fix: ensure the grammar's .family = PF_XXX (or AF_XXX)"
		echo "       initializer is present in net/proto-*.c and this"
		echo "       check's regex still matches it."
	} >&2
	fail "unresolved grammar symbol(s)"
fi

grammar_pfs=$(printf '%s\n' "$grammar_pfs_raw" | sort -u)

# Load grandfathered "proto entry, no grammar" PFs.  Format is one
# bare PF_XXX per line; everything after the first whitespace is
# reason commentary.
declare -A BASELINED=()
if [ -r "$BASELINE" ]; then
	while IFS= read -r entry; do
		[ -z "$entry" ] && continue
		case "$entry" in \#*) continue ;; esac
		entry="${entry#"${entry%%[![:space:]]*}"}"
		key="${entry%%[[:space:]]*}"
		[ -z "$key" ] && continue
		BASELINED["$key"]=1
	done < "$BASELINE"
fi

# proto_only: PF in net_protocols but no grammar covers it.
# grammar_only: grammar registered whose .family has no netproto
# entry.  Never acceptable.
proto_only=$(comm -23 <(printf '%s\n' "$proto_pfs") <(printf '%s\n' "$grammar_pfs"))
grammar_only=$(comm -13 <(printf '%s\n' "$proto_pfs") <(printf '%s\n' "$grammar_pfs"))

new_gaps=()
still_baselined=0
if [ -n "$proto_only" ]; then
	while IFS= read -r pf; do
		[ -z "$pf" ] && continue
		if [ -n "${BASELINED[$pf]+x}" ]; then
			BASELINED["$pf"]=2
			still_baselined=$((still_baselined + 1))
		else
			new_gaps+=("$pf")
		fi
	done <<< "$proto_only"
fi

stale=()
for key in "${!BASELINED[@]}"; do
	if [ "${BASELINED[$key]}" = "1" ]; then
		stale+=("$key")
	fi
done

grammar_only_arr=()
if [ -n "$grammar_only" ]; then
	while IFS= read -r line; do
		[ -n "$line" ] && grammar_only_arr+=("$line")
	done <<< "$grammar_only"
fi

if [ "${#grammar_only_arr[@]}" -gt 0 ]; then
	{
		echo "  $NAME: grammar registered for PF with no net_protocols entry:"
		for pf in "${grammar_only_arr[@]}"; do
			echo "    $pf"
		done
		echo "  fix: add a [PF_XXX] = { .proto = &proto_<family> } entry"
		echo "       to net_protocols[] in net/protocols.c, or drop the"
		echo "       grammar from sfg_registry[] until a netproto exists."
	} >&2
fi

if [ "${#new_gaps[@]}" -gt 0 ]; then
	{
		echo "  $NAME: net_protocols entry with no grammar in sfg_registry:"
		for pf in "${new_gaps[@]}"; do
			echo "    $pf"
		done
		echo "  fix: add a per-family grammar in net/proto-<family>.c and"
		echo "       register it in sfg_registry[] in"
		echo "       net/socket-family-grammar.c.  If the gap is"
		echo "       intentional (netproto exists purely for triplet or"
		echo "       sockaddr synthesis and no coherent grammar makes"
		echo "       sense), pin the PF in"
		echo "       scripts/check-static/net-proto-sfg-parity.baseline"
		echo "       with a reason."
	} >&2
fi

if [ "${#stale[@]}" -gt 0 ]; then
	{
		echo "  note: ${#stale[@]} baseline entry/entries no longer gap (consider pruning):"
		for e in "${stale[@]}"; do
			echo "    $e"
		done
	} >&2
fi

nproto=$(printf '%s\n' "$proto_pfs" | wc -l)
ngram=$(printf '%s\n' "$grammar_pfs" | wc -l)

if [ "${#grammar_only_arr[@]}" -gt 0 ] || [ "${#new_gaps[@]}" -gt 0 ]; then
	echo "FAIL: $NAME: parity violation(s) (protos=$nproto grammars=$ngram)"
	exit 1
fi

echo "PASS: $NAME (net_protocols=$nproto grammars=$ngram baselined_gaps=$still_baselined)"
exit 0
