/*
 * Struct-catalog CMP-attribution steering.
 *
 * Carved out of struct_catalog/catalog.c: this TU owns the heuristic
 * that maps a KCOV-CMP-learned constant back to the most likely
 * struct field it came from.
 *
 *   - natural_width picks the smallest byte width needed to represent
 *     the constant (1/2/4/8).
 *   - field_tag_is_gate marks the tags that carry kernel-ABI vocab
 *     (FT_ENUM / FT_FLAGS / FT_VERSION_MAGIC); these are preferred
 *     over same-width FT_RAW opaque-id fields because a mutation
 *     hint on a gate field steers toward a meaningful sibling value,
 *     while a hint on an opaque field would waste future mutations.
 *   - struct_field_for_cmp is the entry point: variant-scopes the
 *     field pool through struct_desc_resolve_variant (defined in
 *     struct_catalog/variant.c) and returns a reservoir-sampled
 *     field index that prefers gate-tagged matches over same-width
 *     matches over any wider fit.
 *
 * Kept independent from the (nr, arg) registry lookup because the
 * CMP-steering interface has a different contract (variant-scoped,
 * pre-fill) and is a good unit-test surface on its own.
 */

#include <stdbool.h>
#include <stddef.h>

#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "rnd.h"
#include "trinity.h"

/*
 * Return the natural byte width needed to represent val:
 *   val < 2^8  -> 1, < 2^16 -> 2, < 2^32 -> 4, else 8.
 */
static unsigned int natural_width(unsigned long val)
{
	if (val < (1UL << 8))
		return 1;
	if (val < (1UL << 16))
		return 2;
	if (val < (1UL << 32))
		return 4;
	return 8;
}

/*
 * True for the tag set that carries kernel-ABI vocabulary the CMP
 * attribution prefers when it has a same-width match: FT_ENUM /
 * FT_FLAGS / FT_VERSION_MAGIC are the gates the kernel actively
 * compares against the constants KCOV-CMP traps, so attributing a
 * learned constant to one of those slots produces a steerable
 * mutation hint instead of landing on a coincidentally-same-width
 * FT_RAW opaque-id field where future mutations would be wasted.
 */
static bool field_tag_is_gate(enum field_tag tag)
{
	switch (tag) {
	case FT_ENUM:
	case FT_FLAGS:
	case FT_VERSION_MAGIC:
		return true;
	default:
		return false;
	}
}

int struct_field_for_cmp(const struct struct_desc *desc,
			 struct syscallrecord *rec, unsigned long val)
{
	const struct union_variant *variant;
	const struct struct_field *fields;
	unsigned int num_fields;
	unsigned int want = natural_width(val);
	unsigned int i;
	unsigned int gate_seen = 0, exact_seen = 0, fit_seen = 0;
	int gate_pick = -1, exact_pick = -1, fit_pick = -1;

	/*
	 * Variant-scoped candidate pool when the discriminator resolves.
	 * No-match on a tagged-union desc falls through to the shared
	 * desc->fields[] (today an empty prefix for bpf_attr; future
	 * structs with common-prefix fields land there too).
	 */
	/*
	 * CMP runs before the next fill so there's no buffer to consult
	 * for buffer-discriminator structs; passing buf == NULL makes the
	 * resolver short-circuit and attribution lands on the flat field
	 * list (typically the shared head field carrying the discriminator
	 * itself, which is the high-value CMP target anyway).
	 */
	variant = struct_desc_resolve_variant(desc, rec, NULL);
	if (variant != NULL) {
		fields = variant->fields;
		num_fields = variant->num_fields;
	} else {
		fields = desc->fields;
		num_fields = desc->num_fields;
	}

	/*
	 * Single-pass reservoir sample with three reservoirs:
	 *   gate_pick  — uniform random among same-width gate-tagged
	 *                fields (FT_ENUM / FT_FLAGS / FT_VERSION_MAGIC).
	 *                Preferred over the size-only matches when any
	 *                gate field is a candidate, on the principle
	 *                that the kernel CMP'd a constant against a
	 *                gate field's vocab more often than against a
	 *                same-width opaque field.
	 *   exact_pick — uniform random among same-width fields of any
	 *                tag (the pre-tag fallback).
	 *   fit_pick   — uniform random among fields whose size >= want
	 *                (covers narrow CMP values landing in wider
	 *                slots).
	 */
	for (i = 0; i < num_fields; i++) {
		unsigned int fsize = fields[i].size;
		enum field_tag tag = fields[i].tag;

		if (fsize == want) {
			exact_seen++;
			if (rnd_modulo_u32(exact_seen) == 0)
				exact_pick = (int)i;
			if (field_tag_is_gate(tag)) {
				gate_seen++;
				if (rnd_modulo_u32(gate_seen) == 0)
					gate_pick = (int)i;
			}
		}
		if (fsize >= want) {
			fit_seen++;
			if (rnd_modulo_u32(fit_seen) == 0)
				fit_pick = (int)i;
		}
	}

	if (gate_pick >= 0)
		return gate_pick;
	if (exact_pick >= 0)
		return exact_pick;
	if (fit_pick >= 0)
		return fit_pick;
	return -1;
}
