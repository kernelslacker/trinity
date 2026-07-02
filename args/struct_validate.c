#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "args-internal.h"
#include "debug.h"		// BUG
#include "struct_catalog.h"
#include "syscall.h"

/*
 * Per-array consistency check for FT_LEN_* fields carrying a
 * buf_fields[] sibling list.  The pre-pin pass in struct_fill_passes
 * pre-pins one shared count across every listed sibling and writes
 * the LEN slot from that same count, which is sound only when:
 *
 *  1. every resolvable sibling has the same pointer tag -- all
 *     FT_PTR_BYTES, xor all FT_PTR_ARRAY.  A mix would store one
 *     count into a byte buffer (interpreted as bytes) and the same
 *     count into an array slot (interpreted as elements), with no
 *     unit the kernel can read consistently.
 *  2. the LEN field's unit agrees with that tag: FT_LEN_BYTES pairs
 *     with FT_PTR_BYTES, FT_LEN_COUNT with FT_PTR_ARRAY.  A
 *     mismatch (e.g. FT_LEN_BYTES naming an FT_PTR_ARRAY sibling)
 *     would publish a byte count into a slot the kernel reads as
 *     an element count, silently mis-shaping the arg tuple.
 *
 * Resolution uses find_field_index_in() against the same fields[]
 * scope the runtime pre-pin pass uses, so an index that doesn't
 * resolve here is skipped, not flagged -- it cannot contribute to
 * either rule and only means "no claim either way".  A genuine
 * contradiction among the resolved siblings is BUG()'d.
 */
static void validate_len_buf_fields(const struct struct_field *fields,
				    unsigned int n)
{
	unsigned int i;

	for (i = 0; i < n; i++) {
		const struct struct_field *f = &fields[i];
		enum field_tag agreed = FT_RAW;
		bool agreed_set = false;
		unsigned int j;

		if (f->tag != FT_LEN_BYTES && f->tag != FT_LEN_COUNT)
			continue;
		if (f->u.len_of.buf_fields == NULL ||
		    f->u.len_of.n_buf_fields == 0)
			continue;

		for (j = 0; j < f->u.len_of.n_buf_fields; j++) {
			int p = find_field_index_in(fields, n,
						    f->u.len_of.buf_fields[j]);
			enum field_tag pt;

			if (p < 0 || (unsigned int) p >= n)
				continue;
			pt = fields[p].tag;
			if (pt != FT_PTR_BYTES && pt != FT_PTR_ARRAY)
				BUG("LEN buf_fields sibling is not FT_PTR_BYTES/ARRAY");
			if (!agreed_set) {
				agreed = pt;
				agreed_set = true;
				continue;
			}
			if (pt != agreed)
				BUG("LEN buf_fields siblings mix FT_PTR_BYTES and FT_PTR_ARRAY");
		}

		if (!agreed_set)
			continue;

		if (f->tag == FT_LEN_BYTES && agreed != FT_PTR_BYTES)
			BUG("FT_LEN_BYTES paired with non-FT_PTR_BYTES sibling");
		if (f->tag == FT_LEN_COUNT && agreed != FT_PTR_ARRAY)
			BUG("FT_LEN_COUNT paired with non-FT_PTR_ARRAY sibling");
	}
}

/*
 * Walk every fields[] array reachable in struct_catalog[]:
 * top-level desc->fields, each variant->fields, each variant->base
 * (when present), and each nested_variant->fields.  Each array is
 * an independent name-resolution scope at runtime, so each is
 * validated against itself the same way the fill paths read it.
 *
 * Catalog data is built from C99 literal initialisers at compile
 * time, so a flagged inconsistency is a structural authoring bug,
 * not runtime drift.  Loud BUG() at first fill turns what would
 * otherwise be a silent mis-generation into a startup failure.
 */
static void validate_struct_catalog(void)
{
	unsigned int i;

	for (i = 0; i < SC_NR_ENTRIES; i++) {
		const struct struct_desc *d = &struct_catalog[i];
		unsigned int v;

		validate_len_buf_fields(d->fields, d->num_fields);

		for (v = 0; v < d->num_variants; v++) {
			const struct union_variant *var = &d->variants[v];
			unsigned int k;

			validate_len_buf_fields(var->fields, var->num_fields);
			if (var->base != NULL)
				validate_len_buf_fields(var->base->fields,
							var->base->num_fields);
			for (k = 0; k < var->num_nested_variants; k++) {
				const struct union_variant *nv =
					&var->nested_variants[k];

				validate_len_buf_fields(nv->fields,
							nv->num_fields);
			}
		}
	}
}

void struct_field_fill_schema_aware(unsigned char *buf, unsigned int size,
				    const struct struct_desc *desc,
				    struct syscallrecord *rec)
{
	static bool catalog_validated;
	const struct union_variant *variant;

	/*
	 * First-call gate: validate every fields[] array in struct_catalog
	 * once per process.  Steady-state cost is one bool test; a
	 * descriptor inconsistency BUG()s here at first generate instead
	 * of silently mis-shaping args at runtime.
	 */
	if (!catalog_validated) {
		validate_struct_catalog();
		catalog_validated = true;
	}

	/*
	 * Arg-derived discriminator resolves up-front from rec; nested
	 * FT_PTR_STRUCT calls thread rec through so a child struct under
	 * a tagged-union parent reads the same syscall args.  Buffer-
	 * derived discriminators can't resolve here -- the buffer is empty
	 * -- so the shared desc->fields[] head pass runs first and writes
	 * the discriminator (e.g. sockaddr_storage's ss_family).  The
	 * per-AF variant fill then runs on the now-populated buffer.
	 */
	variant = struct_desc_resolve_variant(desc, rec, NULL);
	if (variant != NULL) {
		struct_fill_passes(buf, size, variant->fields,
				   variant->num_fields, rec);
		struct_variant_overlay_nested(buf, size, variant, rec);
		return;
	}

	struct_fill_passes(buf, size, desc->fields, desc->num_fields, rec);

	if (desc->buffer_discrim_size == 0)
		return;

	variant = struct_desc_resolve_variant(desc, rec, buf);
	if (variant != NULL) {
		struct_fill_passes(buf, size, variant->fields,
				   variant->num_fields, rec);
		struct_variant_overlay_nested(buf, size, variant, rec);
	}
}
