#!/bin/bash
#
# tipc-addrtype-catalog: every TIPC addrtype the fuzzer can draw for
# sockaddr_tipc.addrtype must have a matching union_variant entry in
# the per-addrtype nested catalog table.
#
# Background: the sockaddr_tipc schema field for addrtype is an
# FT_ENUM sourced from tipc_addrtype_vocab[] in
# struct_catalog/sockaddr-af.c, so the fuzzer only ever picks
# TIPC_ADDR_* values drawn from that pool.  The catalog side,
# sockaddr_tipc_addr_nested[] in the same file, drives schema-aware
# fill for the discriminated inner addr union: the sanitiser looks up
# the variant by addrtype and each variant supplies the effective_size
# + field set for the per-arm addr layout.
#
# When an addrtype exists in tipc_addrtype_vocab[] but no matching
# variant exists in sockaddr_tipc_addr_nested[], the sanitiser has no
# per-arm schema to constrain the payload -- the inner addr union
# stays opaque and its u32 sub-fields never gain the tagged-union
# annotations the catalog was meant to hang off them.
#
# This check greps both arrays and fails on any vocab addrtype with no
# matching variant.  The two arrays are curated in lock-step in the
# same file and are in 1:1 parity today, so no grandfathered baseline
# is needed.  A new TIPC_ADDR_* added to tipc_addrtype_vocab[] without
# a paired sockaddr_tipc_addr_nested[] entry fails the check.

set -u

NAME="tipc-addrtype-catalog"
ROOT="${REPO_ROOT:-$(pwd)}"
SRC="$ROOT/struct_catalog/sockaddr-af.c"

fail() {
	echo "FAIL: $NAME: $1" >&2
	exit 1
}

[ -r "$SRC" ] || fail "cannot read $SRC"

# Slurp the tipc_addrtype_vocab[] initializer body.  Accept an
# optional `static` for symmetry with future carves.
vocab_block=$(awk '
	/^(static[[:space:]]+)?const[[:space:]]+unsigned[[:space:]]+long[[:space:]]+tipc_addrtype_vocab\[.*\][[:space:]]*=[[:space:]]*\{/ {
		in_block = 1
		next
	}
	in_block && /^\};/ { in_block = 0; exit }
	in_block { print }
' "$SRC")

[ -n "$vocab_block" ] || fail "tipc_addrtype_vocab[] not found in ${SRC#"$ROOT"/}"

vocab=$(printf '%s\n' "$vocab_block" \
	| grep -oE 'TIPC_ADDR_[A-Z0-9_]+' \
	| sort -u)

[ -n "$vocab" ] || fail "tipc_addrtype_vocab[] body contained no TIPC_ADDR_* tokens"

# Slurp the sockaddr_tipc_addr_nested[] initializer body and pull
# every .discrim_value = TIPC_ADDR_* pair.
variants_block=$(awk '
	/^(static[[:space:]]+)?const[[:space:]]+struct[[:space:]]+union_variant[[:space:]]+sockaddr_tipc_addr_nested\[.*\][[:space:]]*=[[:space:]]*\{/ {
		in_block = 1
		next
	}
	in_block && /^\};/ { in_block = 0; exit }
	in_block { print }
' "$SRC")

[ -n "$variants_block" ] || fail "sockaddr_tipc_addr_nested[] not found in ${SRC#"$ROOT"/}"

variants=$(printf '%s\n' "$variants_block" \
	| grep -oE '\.discrim_value[[:space:]]*=[[:space:]]*TIPC_ADDR_[A-Z0-9_]+' \
	| grep -oE 'TIPC_ADDR_[A-Z0-9_]+' \
	| sort -u)

[ -n "$variants" ] || fail "sockaddr_tipc_addr_nested[] carried no .discrim_value entries"

# Gaps: addrtypes present in the vocab pool but not covered by any variant.
gaps=$(comm -23 <(printf '%s\n' "$vocab") <(printf '%s\n' "$variants"))

vocab_count=$(printf '%s\n' "$vocab" | wc -l)
variants_count=$(printf '%s\n' "$variants" | wc -l)

if [ -n "$gaps" ]; then
	gap_count=$(printf '%s\n' "$gaps" | wc -l)
	{
		echo "  $NAME: $gap_count vocab addrtype(s) have no sockaddr_tipc_addr_nested[] variant:"
		printf '    %s\n' $gaps
		echo "  fix: add a union_variant to sockaddr_tipc_addr_nested[] in"
		echo "       struct_catalog/sockaddr-af.c (see TIPC_ADDR_ID /"
		echo "       TIPC_ADDR_NAMESEQ for reference shape), or remove the"
		echo "       addrtype from tipc_addrtype_vocab[] if it should not"
		echo "       be drawn."
	} >&2
	echo "FAIL: $NAME: $gap_count new gap(s) of $vocab_count addrtype(s)"
	exit 1
fi

covered=$vocab_count
echo "PASS: $NAME (vocab=$vocab_count, variants=$variants_count, covered=$covered)"
exit 0
