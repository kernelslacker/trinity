#!/bin/bash
#
# variant-address-walk: verify both the static reachability walker
# (struct_desc_has_address_field() in struct_catalog/address.c) and the
# runtime nested-address scrub (scrub_struct_addresses() in
# args/generate-args.c) traverse desc->variants[] / variant->base /
# variant->nested_variants[] -- not just desc->fields[].
#
# Background: scrub_struct_addresses() relocates any FT_ADDRESS field
# that ended up aliasing a shared sibling buffer.  Until the variant
# walk landed, both helpers walked only desc->fields[], so an
# FT_ADDRESS that lives only inside a tagged-union variant (e.g.
# perf_event_attr.bp_addr on the BREAKPOINT arm) was invisible: the
# reachability gate said "no FT_ADDRESS here", the nested-scrub mask
# stayed zero, and the runtime scrub never ran.  An in-struct
# kernel-deref pointer could then alias the shared csfu buffer -- the
# exact heap-corruption class the scrub exists to close.
#
# A runtime selftest in struct_field_mutate_self_check()
# (selftest_variant_address_walk) BUG()s at init if the reachability
# walker regresses.  This static check is the second layer: it makes
# the regression visible at source-grep time, before the build, and
# also asserts the runtime selftest is wired into the self-check entry
# point (a silently-detached selftest would silently stop guarding).

set -u

NAME="variant-address-walk"
ROOT="${REPO_ROOT:-$(pwd)}"
SCRUB="$ROOT/args/scrub.c"
MUT="$ROOT/args/struct_mutate.c"
CAT="$ROOT/struct_catalog/address.c"

fail() {
	echo "FAIL: $NAME: $1" >&2
	exit 1
}

[ -r "$SCRUB" ] || fail "cannot read $SCRUB"
[ -r "$MUT" ] || fail "cannot read $MUT"
[ -r "$CAT" ] || fail "cannot read $CAT"

# Extract the actual function body (not the forward decl) for the
# reachability helper.  The forward decl ends with ");" on a line, and
# the definition opens "{" on its own line that we anchor on.
cat_body=$(awk '
	/^static bool struct_desc_has_address_field_depth\(/ { seen++ }
	seen == 2 { print }
	seen == 2 && /^\}$/ { exit }
' "$CAT")

[ -n "$cat_body" ] \
	|| fail "struct_desc_has_address_field_depth() definition not found in $CAT"

problems=()
checked=0

# Helper: -F (fixed-string) + -- so leading "->" needles are not
# parsed as grep options.
grep_in() {
	local body="$1"
	local needle="$2"
	printf '%s\n' "$body" | grep -qF -- "$needle"
}

# Local-variable names in the helper body: desc->variants[v] iterates,
# var aliases each entry and we read var->base + var->nested_variants.
want_cat=(
	"desc->variants"
	"var->base"
	"var->nested_variants"
)
for needle in "${want_cat[@]}"; do
	checked=$((checked + 1))
	if ! grep_in "$cat_body" "$needle"; then
		problems+=("struct_catalog/address.c reachability helper missing '$needle' traversal")
	fi
done

# Extract scrub_struct_addresses() body (skip the forward decl, grab
# the second match through the next top-level closing brace).
# scrub_struct_addresses and scrub_variant_overlay_nested live in
# args/scrub.c after the generate-args carve.
scrub_body=$(awk '
	/^static void scrub_struct_addresses\(/ { seen++ }
	seen == 2 { print }
	seen == 2 && /^\}$/ { exit }
' "$SCRUB")

[ -n "$scrub_body" ] \
	|| fail "scrub_struct_addresses() definition not found in $SCRUB"

want_scrub=(
	"struct_desc_resolve_variant"
	"scrub_variant_overlay_nested"
)
for needle in "${want_scrub[@]}"; do
	checked=$((checked + 1))
	if ! grep_in "$scrub_body" "$needle"; then
		problems+=("scrub_struct_addresses() missing '$needle' call")
	fi
done

# scrub_variant_overlay_nested itself must walk base + matched nested.
overlay_body=$(awk '
	/^static void scrub_variant_overlay_nested\(/ { in_block = 1 }
	in_block { print }
	in_block && /^\}$/ { exit }
' "$SCRUB")

[ -n "$overlay_body" ] \
	|| fail "scrub_variant_overlay_nested() not found in $SCRUB"

want_overlay=(
	"variant->base"
	"struct_desc_resolve_nested_variant"
)
for needle in "${want_overlay[@]}"; do
	checked=$((checked + 1))
	if ! grep_in "$overlay_body" "$needle"; then
		problems+=("scrub_variant_overlay_nested() missing '$needle' traversal")
	fi
done

# Runtime selftest must exist AND be wired into the entry point.
# selftest_variant_address_walk() and struct_field_mutate_self_check()
# live in args/struct_mutate.c after the generate-args carve.
checked=$((checked + 1))
if ! grep -qE '^static void selftest_variant_address_walk\(void\)' "$MUT"; then
	problems+=("selftest_variant_address_walk() not defined in $MUT")
fi

selfcheck_body=$(awk '
	/^void struct_field_mutate_self_check\(void\)/ { in_block = 1 }
	in_block { print }
	in_block && /^\}$/ { exit }
' "$MUT")

checked=$((checked + 1))
if ! grep_in "$selfcheck_body" "selftest_variant_address_walk("; then
	problems+=("struct_field_mutate_self_check() does not call selftest_variant_address_walk()")
fi

if [ "${#problems[@]}" -gt 0 ]; then
	{
		echo "  $NAME: variant walk gaps detected:"
		for line in "${problems[@]}"; do
			echo "    $line"
		done
		echo "  fix: both the reachability walker and the runtime scrub"
		echo "       must mirror struct_field_fill_schema_aware()'s"
		echo "       traversal of desc->variants / variant->base /"
		echo "       variant->nested_variants; the selftest must stay"
		echo "       wired into struct_field_mutate_self_check()."
	} >&2
	fail "${#problems[@]} mismatch(es) of $checked"
fi

echo "PASS: $NAME: $checked structural item(s) validated"
exit 0
