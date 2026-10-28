/*
 * syscalls/bpf-fallback.c -- schema-aware bpf_attr floor for the cmd arms
 * without a hand-rolled sanitiser.  Fed by the default arm of sanitise_bpf()'s
 * switch in syscalls/bpf.c, and by sanitise_bpf_link_create(), which draws
 * the head itself and takes only the arm its attach type names: consults
 * struct_catalog's bpf_attr variant table for the per-cmd effective_size and
 * delegates the field fill to struct_field_fill_schema_aware().
 */

#ifdef USE_BPF

#include <linux/bpf.h>

#include "bpf-internal.h"
#include "sanitise.h"
#include "struct_catalog.h"

/*
 * Size the call to the nested arm the sub-discriminator in @attr names when
 * it has an effective_size, else to @variant's, else to the whole union.
 */
static void size_bpf_call(union bpf_attr *attr, struct syscallrecord *rec,
			  const struct union_variant *variant)
{
	const struct union_variant *nested = NULL;

	if (variant != NULL && variant->nested_variants != NULL)
		nested = struct_desc_resolve_nested_variant(variant,
							    (const unsigned char *) attr,
							    sizeof(union bpf_attr));
	if (nested != NULL && nested->effective_size != 0)
		rec->a3 = nested->effective_size;
	else if (variant != NULL && variant->effective_size != 0)
		rec->a3 = variant->effective_size;
	else
		rec->a3 = sizeof(union bpf_attr);
}

void sanitise_bpf_default(union bpf_attr *attr, struct syscallrecord *rec)
{
	/*
	 * Schema-aware floor for the ~15 cmds without a hand-rolled
	 * arm above (BPF_PROG_QUERY, BPF_TASK_FD_QUERY, the MAP_*
	 * batch ops, etc.).  struct_field_fill_schema_aware reads
	 * the cmd discriminator off rec->a1 via bpf_attr's variant
	 * table; annotated variants get FT_ENUM / FT_FLAGS / FT_FD
	 * / FT_PTR_BYTES coherent fill instead of zero, and
	 * unannotated cmds fall through to the zmalloc-zero shape
	 * the old default produced.  rec->a3 prefers the variant's
	 * effective_size when set so the kernel sees a per-cmd size
	 * rather than the full union; unset effective_size keeps
	 * the historical sizeof(union bpf_attr) default.
	 */
	const struct struct_desc *desc = struct_catalog_lookup("bpf_attr");
	const struct union_variant *variant = NULL;

	if (desc != NULL) {
		variant = struct_desc_resolve_variant(desc, rec, NULL);
		struct_field_fill_schema_aware((unsigned char *) attr,
					       sizeof(union bpf_attr),
					       desc, rec);
	}
	/*
	 * Nested tagged-union: when the outer variant gates a sub-union
	 * (e.g. link_create's attach_type), the sub-variant's
	 * effective_size is the more specific bound -- a TRACING arm's 28
	 * bytes vs. the full 88 link_create struct.
	 */
	size_bpf_call(attr, rec, variant);
}

/*
 * Only the nested arm of the command's variant: the base pass and the arm
 * the sub-discriminator a sanitiser already wrote into @attr names, then the
 * size of the call, for a sanitiser that draws the head itself.
 */
void sanitise_bpf_nested(union bpf_attr *attr, struct syscallrecord *rec)
{
	const struct struct_desc *desc = struct_catalog_lookup("bpf_attr");
	const struct union_variant *variant = NULL;

	if (desc != NULL) {
		variant = struct_desc_resolve_variant(desc, rec, NULL);
		if (variant != NULL)
			struct_variant_overlay_nested((unsigned char *) attr,
						      sizeof(union bpf_attr),
						      variant, rec);
	}
	size_bpf_call(attr, rec, variant);
}

#endif	/* USE_BPF */
