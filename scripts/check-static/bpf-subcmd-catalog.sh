#!/bin/bash
#
# bpf-subcmd-catalog: every BPF subcommand the fuzzer can draw for
# bpf(2) must have a matching union_variant entry in the catalog.
#
# Background: syscall_bpf.arg_params[0].list points at bpf_cmds[] in
# syscalls/bpf.c, so the fuzzer only ever emits cmd values drawn from
# that pool.  The catalog side, bpf_attr_variants[] in
# struct_catalog/bpf.c, drives schema-aware fill for union bpf_attr:
# the sanitiser looks up the variant by discrim_value, and each
# variant supplies the effective_size + field set for the payload.
#
# When a subcmd exists in bpf_cmds[] but no matching variant exists
# in bpf_attr_variants[], the sanitiser falls through to the empty
# shared prefix.  The fuzzer then has no schema to constrain payload
# width, so it silently reverts to blind width-guessing for that
# cmd -- exactly the coverage regression the catalog was meant to
# retire.
#
# This check greps both tables and warns / fails on any bpf_cmds[]
# entry with no matching bpf_attr_variants[] .discrim_value.
# Pre-existing known gaps are grandfathered via a .baseline file in
# the same directory; the baseline should shrink over time, never
# grow.  A new subcmd wired into bpf_cmds[] without a variant fails
# the check.

set -u

NAME="bpf-subcmd-catalog"
ROOT="${REPO_ROOT:-$(pwd)}"
CMDS_SRC="$ROOT/syscalls/bpf.c"
CAT_SRC="$ROOT/struct_catalog/bpf.c"
BASELINE="$ROOT/scripts/check-static/bpf-subcmd-catalog.baseline"

fail() {
	echo "FAIL: $NAME: $1" >&2
	exit 1
}

[ -r "$CMDS_SRC" ] || fail "cannot read $CMDS_SRC"
[ -r "$CAT_SRC" ]  || fail "cannot read $CAT_SRC"

# Slurp the bpf_cmds[] initializer body.  The declaration is
# `static unsigned long bpf_cmds[] = {` per syscalls/bpf.c; accept
# an optional `static` for symmetry with future carves.
cmds_block=$(awk '
	/^(static[[:space:]]+)?unsigned long bpf_cmds\[.*\] = \{/ {
		in_block = 1
		next
	}
	in_block && /^\};/ { in_block = 0; exit }
	in_block { print }
' "$CMDS_SRC")

[ -n "$cmds_block" ] || fail "bpf_cmds[] not found in ${CMDS_SRC#"$ROOT"/}"

cmds=$(printf '%s\n' "$cmds_block" \
	| grep -oE 'BPF_[A-Z0-9_]+' \
	| sort -u)

[ -n "$cmds" ] || fail "bpf_cmds[] body contained no BPF_* tokens"

# Slurp the bpf_attr_variants[] initializer body and pull every
# .discrim_value = BPF_* pair.
variants_block=$(awk '
	/^(static[[:space:]]+)?const struct union_variant bpf_attr_variants\[.*\] = \{/ {
		in_block = 1
		next
	}
	in_block && /^\};/ { in_block = 0; exit }
	in_block { print }
' "$CAT_SRC")

[ -n "$variants_block" ] || fail "bpf_attr_variants[] not found in ${CAT_SRC#"$ROOT"/}"

variants=$(printf '%s\n' "$variants_block" \
	| grep -oE '\.discrim_value[[:space:]]*=[[:space:]]*BPF_[A-Z0-9_]+' \
	| grep -oE 'BPF_[A-Z0-9_]+' \
	| sort -u)

[ -n "$variants" ] || fail "bpf_attr_variants[] carried no .discrim_value entries"

# Gaps: cmds present in bpf_cmds[] but not covered by any variant.
gaps=$(comm -23 <(printf '%s\n' "$cmds") <(printf '%s\n' "$variants"))

# Load the grandfathered baseline (one BPF_* token per line, comments/blanks
# ignored).  A gap already present in the baseline is expected debt; a gap
# NOT in the baseline is a new regression.
declare -A GRANDFATHERED=()
if [ -r "$BASELINE" ]; then
	while IFS= read -r entry; do
		[ -z "$entry" ] && continue
		case "$entry" in \#*) continue;; esac
		GRANDFATHERED["$entry"]=1
	done < <(sed -e 's/#.*$//' -e 's/[[:space:]]//g' "$BASELINE")
fi

new_gaps=()
grand_gaps=()
if [ -n "$gaps" ]; then
	while IFS= read -r cmd; do
		[ -z "$cmd" ] && continue
		if [ -n "${GRANDFATHERED[$cmd]+x}" ]; then
			grand_gaps+=("$cmd")
		else
			new_gaps+=("$cmd")
		fi
	done <<< "$gaps"
fi

# Stale baseline entries: listed in .baseline but no longer a gap
# (either the variant was added or the cmd was dropped from
# bpf_cmds[]).  Non-fatal advisory so the same commit that closes a
# gap can also prune the baseline entry without ordering games.
stale_baseline=()
for entry in "${!GRANDFATHERED[@]}"; do
	if ! printf '%s\n' "$gaps" | grep -qxF "$entry"; then
		stale_baseline+=("$entry")
	fi
done

cmds_count=$(printf '%s\n' "$cmds" | wc -l)
variants_count=$(printf '%s\n' "$variants" | wc -l)
grand_count=${#GRANDFATHERED[@]}
covered=$((cmds_count - ${#new_gaps[@]} - ${#grand_gaps[@]}))

if [ "${#new_gaps[@]}" -gt 0 ]; then
	{
		echo "  $NAME: ${#new_gaps[@]} bpf_cmds[] entry/entries have no bpf_attr_variants[] variant:"
		for e in "${new_gaps[@]}"; do echo "    $e"; done
		echo "  fix: add a union_variant to bpf_attr_variants[] in struct_catalog/bpf.c"
		echo "       (see BPF_MAP_CREATE / BPF_PROG_LOAD for reference shape),"
		echo "       OR (only if variant work is deferred) append the token to"
		echo "       scripts/check-static/bpf-subcmd-catalog.baseline"
	} >&2
fi

if [ "${#stale_baseline[@]}" -gt 0 ]; then
	{
		echo "  note: ${#stale_baseline[@]} baseline entry/entries no longer match an uncovered cmd (consider pruning):"
		for e in "${stale_baseline[@]}"; do echo "    $e"; done
	} >&2
fi

if [ "${#new_gaps[@]}" -gt 0 ]; then
	echo "FAIL: $NAME: ${#new_gaps[@]} new gap(s) of $cmds_count cmd(s)"
	exit 1
fi

echo "PASS: $NAME (cmds=$cmds_count, variants=$variants_count, covered=$covered, grandfathered=${#grand_gaps[@]})"
exit 0
