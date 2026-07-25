/*
 * syscalls/bpf-fallback.c -- schema-aware bpf_attr floor for the
 * cmd arms without a hand-rolled sanitiser, carved out of
 * syscalls/bpf.c.
 *
 * Fed by the default arm of sanitise_bpf()'s switch dispatch in the
 * aggregator syscalls/bpf.c.  Consults struct_catalog's bpf_attr
 * variant table for the per-cmd effective_size and delegates the
 * field fill to struct_field_fill_schema_aware.  See the extern in
 * bpf-internal.h.
 */

#ifdef USE_BPF

#include <linux/bpf.h>

#include "bpf-internal.h"
#include "sanitise.h"
#include "struct_catalog.h"

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
	const struct union_variant *nested = NULL;

	if (desc != NULL) {
		variant = struct_desc_resolve_variant(desc, rec, NULL);
		struct_field_fill_schema_aware((unsigned char *) attr,
					       sizeof(union bpf_attr),
					       desc, rec);
		/*
		 * Nested tagged-union: when the outer variant gates
		 * a sub-union (e.g. link_create's attach_type), the
		 * sub-variant's effective_size is the more specific
		 * bound -- a TRACING arm's 28 bytes vs. the full 88
		 * link_create struct.  Pick the nested size when it
		 * resolves and is non-zero; otherwise the outer
		 * variant's size still wins.
		 */
		if (variant != NULL && variant->nested_variants != NULL)
			nested = struct_desc_resolve_nested_variant(
				variant,
				(const unsigned char *) attr,
				sizeof(union bpf_attr));
	}
	if (nested != NULL && nested->effective_size != 0)
		rec->a3 = nested->effective_size;
	else if (variant != NULL && variant->effective_size != 0)
		rec->a3 = variant->effective_size;
	else
		rec->a3 = sizeof(union bpf_attr);
}

#endif	/* USE_BPF */
