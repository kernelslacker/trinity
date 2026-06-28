#!/bin/bash
#
# perf-event-attr-catalog: verify the perf_event_attr field table in
# struct_catalog.c carries the expected (field -> tag) annotations.
#
# Background: sanitise_perf_event_open() in syscalls/perf_event_open.c
# hand-rolls the live perf_event_attr payload via pick_perf_tuple() and
# discards the schema-aware fill produced upstream.  The catalog
# entries therefore exist only as forward infra for type-scoped CMP
# attribution (struct_field_for_cmp() prefers same-width FT_ENUM /
# FT_FLAGS / FT_VERSION_MAGIC slots over FT_RAW when associating a
# learned KCOV CMP constant with a field).  No runtime path consumes
# the tags today, so a wrong tag silently demotes the CMP attribution
# scope without breaking the build or any runtime test.  This check
# is the tripwire: it grep-asserts the 8 annotated scalar fields plus
# the off-40 hand-built bit-field group still carry the tags Phase 2
# step 6 commits A and B installed.

set -u

NAME="perf-event-attr-catalog"
ROOT="${REPO_ROOT:-$(pwd)}"
SRC="$ROOT/struct_catalog/perf.c"
SPINE="$ROOT/struct_catalog.c"

fail() {
	echo "FAIL: $NAME: $1" >&2
	exit 1
}

[ -r "$SRC" ] || fail "cannot read $SRC"
[ -r "$SPINE" ] || fail "cannot read $SPINE"

# Slurp the perf_event_attr_fields[] initializer body.  The carve
# flipped the symbol from `static const` to `const` so the spine in
# struct_catalog.c can reach it via the extern; match either form.
block=$(awk '
	/^(static[[:space:]]+)?const struct struct_field perf_event_attr_fields\[.*\] = \{/ {
		in_block = 1
		next
	}
	in_block && /^\};/ { in_block = 0; exit }
	in_block { print }
' "$SRC")

[ -n "$block" ] || fail "perf_event_attr_fields[] not found in $SRC"

# tag_of NAME: print the field's tag (FT_ENUM / FT_FLAGS / FT_RAW / ...)
# or MISSING if no entry names it.  FIELDX carries the tag as its 3rd
# argument; a bare FIELD() expands to FT_RAW.
tag_of() {
	local field="$1"
	local hit
	hit=$(printf '%s\n' "$block" | awk -v f="$field" '
		match($0, "FIELDX\\(struct perf_event_attr, *" f ", *([A-Z_]+)", m) {
			print m[1]; exit
		}
		match($0, "FIELD\\(struct perf_event_attr, *" f "\\)") {
			print "FT_RAW"; exit
		}
	')
	[ -n "$hit" ] && { echo "$hit"; return; }
	echo "MISSING"
}

# Expected tags per Phase 2 step 6 commits A+B.  Fields not listed
# here are intentionally left FT_RAW (per-type variants in commits
# C/D/E/F or opaque PMU extensions); a future commit may upgrade
# them but this check stays minimal.
checks=(
	"type FT_ENUM"
	"size FT_VERSION_MAGIC"
	"sample_type FT_FLAGS"
	"read_format FT_FLAGS"
	"branch_sample_type FT_FLAGS"
	"sample_stack_user FT_RANGE"
	"clockid FT_ENUM"
	"sample_max_stack FT_RANGE"
	"aux_action FT_FLAGS"
)

problems=()
checked=0
for entry in "${checks[@]}"; do
	field="${entry%% *}"
	want="${entry##* }"
	got=$(tag_of "$field")
	checked=$((checked + 1))
	if [ "$got" != "$want" ]; then
		problems+=("$field: want $want, got $got")
	fi
done

# Off-40 bit-field group is a literal struct entry (no FIELDX --
# offsetof on a bit-field member is invalid).  Verify the named slot
# is present with .offset = 40 and .tag = FT_FLAGS.
if ! printf '%s\n' "$block" | grep -qE '\.name[[:space:]]*=[[:space:]]*"flags_bitfield"'; then
	problems+=("flags_bitfield: off-40 bit-field group entry missing")
elif ! printf '%s\n' "$block" | grep -qE '\.offset[[:space:]]*=[[:space:]]*40\b'; then
	problems+=("flags_bitfield: entry present but no .offset = 40 nearby")
elif ! printf '%s\n' "$block" | grep -qE '\.tag[[:space:]]*=[[:space:]]*FT_FLAGS\b'; then
	problems+=("flags_bitfield: entry present but no .tag = FT_FLAGS nearby")
fi
checked=$((checked + 1))

# Per-type variants installed by commits C/D/E/F.  All six PERF_TYPE_*
# values should appear as named union_variant entries in
# perf_event_attr_variants[]; TRACEPOINT and RAW are intentionally
# empty (config stays FT_RAW) but still present so the resolver
# returns a named variant for CMP-attribution scoping.
variants_block=$(awk '
	/^(static[[:space:]]+)?const struct union_variant perf_event_attr_variants\[.*\] = \{/ {
		in_block = 1
		next
	}
	in_block && /^\};/ { in_block = 0; exit }
	in_block { print }
' "$SRC")

if [ -z "$variants_block" ]; then
	problems+=("perf_event_attr_variants[]: array not found")
else
	for v in HARDWARE SOFTWARE HW_CACHE BREAKPOINT TRACEPOINT RAW; do
		if ! printf '%s\n' "$variants_block" \
		     | grep -qE "\.name[[:space:]]*=[[:space:]]*\"$v\""; then
			problems+=("perf_event_attr_variants[]: missing PERF_TYPE_$v entry")
		fi
		checked=$((checked + 1))
	done
fi

# The desc-level buffer-relative discriminator wires `type` (offset 0,
# size 4) so the resolver can reach the variant set installed above.
desc_block=$(awk '
	/\.name[[:space:]]*=[[:space:]]*"perf_event_attr"/ { in_block = 1 }
	in_block { print }
	in_block && /^[[:space:]]*\},$/ { in_block = 0; exit }
' "$SPINE")
if ! printf '%s\n' "$desc_block" \
     | grep -qE '\.buffer_discrim_offset[[:space:]]*='; then
	problems+=("perf_event_attr desc: missing .buffer_discrim_offset")
fi
if ! printf '%s\n' "$desc_block" \
     | grep -qE '\.buffer_discrim_size[[:space:]]*='; then
	problems+=("perf_event_attr desc: missing .buffer_discrim_size")
fi
checked=$((checked + 2))

if [ "${#problems[@]}" -gt 0 ]; then
	{
		echo "  $NAME: catalog mismatch(es) for perf_event_attr:"
		for line in "${problems[@]}"; do
			echo "    $line"
		done
		echo "  fix: re-read schema-aware-phase2-step6-perf-event-attr-spec"
		echo "       for the expected tags + variants; commits A/B/C/D/E/F"
		echo "       installed them."
	} >&2
	fail "${#problems[@]} mismatch(es) of $checked"
fi

echo "PASS: $NAME: $checked catalog item(s) validated"
exit 0
