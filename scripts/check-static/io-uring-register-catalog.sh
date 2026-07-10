#!/bin/bash
#
# io-uring-register-catalog: every io_uring_register opcode the fuzzer
# can draw for io_uring_register(2) must have a matching union_variant
# entry in the catalog.
#
# Background: the io_uring_register argument picker draws opcode values
# from io_uring_register_opcodes[] in syscalls/io_uring/io_uring_register.c, so
# the fuzzer only ever emits opcodes drawn from that pool.  The catalog
# side, io_uring_register_variants[] in
# struct_catalog/io_uring_register.c, drives schema-aware fill for the
# per-opcode arg payload: the sanitiser resolves the variant by
# discrim_value and each variant supplies the effective_size + field
# set for that opcode.
#
# When an opcode exists in io_uring_register_opcodes[] but no matching
# variant exists in io_uring_register_variants[], the sanitiser falls
# through to the empty shared prefix.  The fuzzer then has no schema
# to constrain payload width, so it silently reverts to blind
# width-guessing for that opcode -- exactly the coverage regression
# the catalog was meant to retire.
#
# This check greps both tables and warns / fails on any
# io_uring_register_opcodes[] entry with no matching
# io_uring_register_variants[] .discrim_value.  Pre-existing known
# gaps are grandfathered via a .baseline file in the same directory;
# the baseline should shrink over time, never grow.  A new opcode
# wired into io_uring_register_opcodes[] without a variant fails
# the check.

set -u

NAME="io-uring-register-catalog"
ROOT="${REPO_ROOT:-$(pwd)}"
OPCODES_SRC="$ROOT/syscalls/io_uring/io_uring_register.c"
CAT_SRC="$ROOT/struct_catalog/io_uring_register.c"
BASELINE="$ROOT/scripts/check-static/io-uring-register-catalog.baseline"

fail() {
	echo "FAIL: $NAME: $1" >&2
	exit 1
}

[ -r "$OPCODES_SRC" ] || fail "cannot read $OPCODES_SRC"
[ -r "$CAT_SRC" ]     || fail "cannot read $CAT_SRC"

# Slurp the io_uring_register_opcodes[] initializer body.  The
# declaration is `static unsigned long io_uring_register_opcodes[] = {`
# per syscalls/io_uring/io_uring_register.c; accept an optional `static` for
# symmetry with future carves.
opcodes_block=$(awk '
	/^(static[[:space:]]+)?unsigned long io_uring_register_opcodes\[.*\] = \{/ {
		in_block = 1
		next
	}
	in_block && /^\};/ { in_block = 0; exit }
	in_block { print }
' "$OPCODES_SRC")

[ -n "$opcodes_block" ] || fail "io_uring_register_opcodes[] not found in ${OPCODES_SRC#"$ROOT"/}"

opcodes=$(printf '%s\n' "$opcodes_block" \
	| grep -oE 'IORING_[A-Z0-9_]+' \
	| sort -u)

[ -n "$opcodes" ] || fail "io_uring_register_opcodes[] body contained no IORING_* tokens"

# Slurp the io_uring_register_variants[] initializer body and pull
# every .discrim_value = IORING_* pair.
variants_block=$(awk '
	/^(static[[:space:]]+)?const struct union_variant io_uring_register_variants\[.*\] = \{/ {
		in_block = 1
		next
	}
	in_block && /^\};/ { in_block = 0; exit }
	in_block { print }
' "$CAT_SRC")

[ -n "$variants_block" ] || fail "io_uring_register_variants[] not found in ${CAT_SRC#"$ROOT"/}"

variants=$(printf '%s\n' "$variants_block" \
	| grep -oE '\.discrim_value[[:space:]]*=[[:space:]]*IORING_[A-Z0-9_]+' \
	| grep -oE 'IORING_[A-Z0-9_]+' \
	| sort -u)

[ -n "$variants" ] || fail "io_uring_register_variants[] carried no .discrim_value entries"

# Gaps: opcodes present in io_uring_register_opcodes[] but not covered
# by any variant.
gaps=$(comm -23 <(printf '%s\n' "$opcodes") <(printf '%s\n' "$variants"))

# Load the grandfathered baseline (one IORING_* token per line,
# comments/blanks ignored).  A gap already present in the baseline is
# expected debt; a gap NOT in the baseline is a new regression.
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
	while IFS= read -r op; do
		[ -z "$op" ] && continue
		if [ -n "${GRANDFATHERED[$op]+x}" ]; then
			grand_gaps+=("$op")
		else
			new_gaps+=("$op")
		fi
	done <<< "$gaps"
fi

# Stale baseline entries: listed in .baseline but no longer a gap
# (either the variant was added or the opcode was dropped from
# io_uring_register_opcodes[]).  Non-fatal advisory so the same commit
# that closes a gap can also prune the baseline entry without ordering
# games.
stale_baseline=()
for entry in "${!GRANDFATHERED[@]}"; do
	if ! printf '%s\n' "$gaps" | grep -qxF "$entry"; then
		stale_baseline+=("$entry")
	fi
done

opcodes_count=$(printf '%s\n' "$opcodes" | wc -l)
variants_count=$(printf '%s\n' "$variants" | wc -l)
grand_count=${#GRANDFATHERED[@]}
covered=$((opcodes_count - ${#new_gaps[@]} - ${#grand_gaps[@]}))

if [ "${#new_gaps[@]}" -gt 0 ]; then
	{
		echo "  $NAME: ${#new_gaps[@]} io_uring_register_opcodes[] entry/entries have no io_uring_register_variants[] variant:"
		for e in "${new_gaps[@]}"; do echo "    $e"; done
		echo "  fix: add a union_variant to io_uring_register_variants[] in struct_catalog/io_uring_register.c"
		echo "       (see IORING_REGISTER_FILES_UPDATE / IORING_REGISTER_PBUF_RING for reference shape),"
		echo "       OR (only if variant work is deferred) append the token to"
		echo "       scripts/check-static/io-uring-register-catalog.baseline"
	} >&2
fi

if [ "${#stale_baseline[@]}" -gt 0 ]; then
	{
		echo "  note: ${#stale_baseline[@]} baseline entry/entries no longer match an uncovered opcode (consider pruning):"
		for e in "${stale_baseline[@]}"; do echo "    $e"; done
	} >&2
fi

if [ "${#new_gaps[@]}" -gt 0 ]; then
	echo "FAIL: $NAME: ${#new_gaps[@]} new gap(s) of $opcodes_count opcode(s)"
	exit 1
fi

echo "PASS: $NAME (opcodes=$opcodes_count, variants=$variants_count, covered=$covered, grandfathered=${#grand_gaps[@]})"
exit 0
