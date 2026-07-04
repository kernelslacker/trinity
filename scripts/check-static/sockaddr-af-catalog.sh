#!/bin/bash
#
# sockaddr-af-catalog: every address family the fuzzer can draw for
# sockaddr_storage.ss_family must have a matching union_variant entry
# in the per-AF catalog table.
#
# Background: the sockaddr_storage schema field for ss_family is an
# FT_ENUM sourced from sockaddr_storage_af_vocab[] in
# struct_catalog/sockaddr-af.c, so the fuzzer only ever picks AF
# values drawn from that pool.  The catalog side,
# sockaddr_storage_variants[] in the same file, drives schema-aware
# fill for the discriminated sockaddr_storage payload: the sanitiser
# looks up the variant by ss_family and each variant supplies the
# effective_size + field set for the per-AF sockaddr layout.
#
# When an AF exists in sockaddr_storage_af_vocab[] but no matching
# variant exists in sockaddr_storage_variants[], the sanitiser has no
# per-AF schema to constrain the payload -- the buffer past ss_family
# stays opaque and the paired msg_namelen reports the full envelope
# size instead of sizeof(struct sockaddr_XX).  That is exactly the
# coverage regression the catalog was meant to retire.
#
# This check greps both arrays and fails on any vocab AF with no
# matching variant.  The two arrays are curated in lock-step in the
# same file and are in 1:1 parity today, so no grandfathered baseline
# is needed.  A new AF added to sockaddr_storage_af_vocab[] without
# a paired sockaddr_storage_variants[] entry fails the check.

set -u

NAME="sockaddr-af-catalog"
ROOT="${REPO_ROOT:-$(pwd)}"
SRC="$ROOT/struct_catalog/sockaddr-af.c"

fail() {
	echo "FAIL: $NAME: $1" >&2
	exit 1
}

[ -r "$SRC" ] || fail "cannot read $SRC"

# Slurp the sockaddr_storage_af_vocab[] initializer body.  Accept an
# optional `static` for symmetry with future carves.
vocab_block=$(awk '
	/^(static[[:space:]]+)?const[[:space:]]+unsigned[[:space:]]+long[[:space:]]+sockaddr_storage_af_vocab\[.*\][[:space:]]*=[[:space:]]*\{/ {
		in_block = 1
		next
	}
	in_block && /^\};/ { in_block = 0; exit }
	in_block { print }
' "$SRC")

[ -n "$vocab_block" ] || fail "sockaddr_storage_af_vocab[] not found in ${SRC#"$ROOT"/}"

vocab=$(printf '%s\n' "$vocab_block" \
	| grep -oE 'AF_[A-Z0-9_]+' \
	| sort -u)

[ -n "$vocab" ] || fail "sockaddr_storage_af_vocab[] body contained no AF_* tokens"

# Slurp the sockaddr_storage_variants[] initializer body and pull
# every .discrim_value = AF_* pair.
variants_block=$(awk '
	/^(static[[:space:]]+)?const[[:space:]]+struct[[:space:]]+union_variant[[:space:]]+sockaddr_storage_variants\[.*\][[:space:]]*=[[:space:]]*\{/ {
		in_block = 1
		next
	}
	in_block && /^\};/ { in_block = 0; exit }
	in_block { print }
' "$SRC")

[ -n "$variants_block" ] || fail "sockaddr_storage_variants[] not found in ${SRC#"$ROOT"/}"

variants=$(printf '%s\n' "$variants_block" \
	| grep -oE '\.discrim_value[[:space:]]*=[[:space:]]*AF_[A-Z0-9_]+' \
	| grep -oE 'AF_[A-Z0-9_]+' \
	| sort -u)

[ -n "$variants" ] || fail "sockaddr_storage_variants[] carried no .discrim_value entries"

# Gaps: AFs present in the vocab pool but not covered by any variant.
gaps=$(comm -23 <(printf '%s\n' "$vocab") <(printf '%s\n' "$variants"))

vocab_count=$(printf '%s\n' "$vocab" | wc -l)
variants_count=$(printf '%s\n' "$variants" | wc -l)

if [ -n "$gaps" ]; then
	gap_count=$(printf '%s\n' "$gaps" | wc -l)
	{
		echo "  $NAME: $gap_count vocab AF(s) have no sockaddr_storage_variants[] variant:"
		printf '    %s\n' $gaps
		echo "  fix: add a union_variant to sockaddr_storage_variants[] in"
		echo "       struct_catalog/sockaddr-af.c (see AF_UNIX / AF_INET for"
		echo "       reference shape), or remove the AF from"
		echo "       sockaddr_storage_af_vocab[] if it should not be drawn."
	} >&2
	echo "FAIL: $NAME: $gap_count new gap(s) of $vocab_count AF(s)"
	exit 1
fi

covered=$vocab_count
echo "PASS: $NAME (vocab=$vocab_count, variants=$variants_count, covered=$covered)"
exit 0
