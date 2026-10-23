/*
 * Struct-catalog FT_ADDRESS reachability walk: can a struct_desc, or any
 * registration under a syscall name + arg, reach an FT_ADDRESS field directly,
 * through FT_PTR_STRUCT / FT_PTR_ARRAY targets or via any variant?  The answer
 * feeds the nested-address scrub mask that gates args/scrub.c.  Pinned by
 * selftest_variant_address_walk and check-static/variant-address-walk.sh.
 */

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "struct_catalog.h"
#include "struct_catalog-internal.h"

bool struct_arg_any_has_address_field(const char *name, unsigned int arg_idx)
{
	const struct syscall_struct_arg_group *g;
	const struct syscall_struct_arg *sa;

	if (name == NULL || arg_idx < 1 || arg_idx > 6)
		return false;
	FOR_EACH_SYSCALL_STRUCT_ARG(g, sa) {
		if (sa->arg_idx != arg_idx)
			continue;
		if (strcmp(sa->syscall_name, name) != 0)
			continue;
		if (struct_desc_has_address_field(sa->desc))
			return true;
	}
	return false;
}

/*
 * Bounded recursion depth for the FT_ADDRESS reachability check.  Real
 * cataloged structs are flat or one level deep (msghdr -> iovec); the
 * cap is a safety net against future cyclic catalog entries.
 */
#define STRUCT_ADDRESS_SCAN_MAX_DEPTH	4

static bool struct_desc_has_address_field_depth(const struct struct_desc *desc,
						unsigned int depth);

/*
 * Per-array reachability scan: returns true iff @fields[0..n) contains
 * an FT_ADDRESS or reaches one via an FT_PTR_STRUCT / FT_PTR_ARRAY
 * target's own catalog descriptor.  Shared by the desc->fields[] walk
 * and the per-variant walks so a variant-only FT_ADDRESS contributes
 * to the reachability gate the nested-address scrub mask is built
 * from.
 */
static bool fields_have_address_field(const struct struct_field *fields,
				      unsigned int num_fields,
				      unsigned int depth)
{
	unsigned int i;

	if (fields == NULL)
		return false;

	for (i = 0; i < num_fields; i++) {
		const struct struct_field *f = &fields[i];
		const struct struct_desc *target;

		switch (f->tag) {
		case FT_ADDRESS:
			return true;
		case FT_PTR_STRUCT:
			target = struct_catalog_lookup(f->u.ptr_struct.struct_name);
			if (struct_desc_has_address_field_depth(target, depth + 1))
				return true;
			break;
		case FT_PTR_ARRAY:
			target = struct_catalog_lookup(f->u.ptr_array.elem_struct);
			if (struct_desc_has_address_field_depth(target, depth + 1))
				return true;
			break;
		case FT_EMBEDDED_STRUCT:
			target = struct_catalog_lookup(f->u.embedded_struct.elem_struct_name);
			if (struct_desc_has_address_field_depth(target, depth + 1))
				return true;
			break;
		default:
			break;
		}
	}
	return false;
}

/*
 * Variant-aware: walks desc->fields[] and -- since the live discriminator
 * is not known at mask-build time -- every variant's fields[],
 * variant->base->fields, and variant->nested_variants[k]->fields too.
 * A conservative OR across all variants is correct here because the
 * mask gates whether the per-dispatch scrub runs at all; the runtime
 * scrub then resolves the active variant and walks only those fields
 * (see scrub_struct_addresses() in args/scrub.c).  Without the
 * variant walk a variant-only FT_ADDRESS (e.g. perf_event_attr's
 * bp_addr on the BREAKPOINT arm) would silently disable the scrub for
 * any syscall slot that reaches one only through a variant.
 */
static bool struct_desc_has_address_field_depth(const struct struct_desc *desc,
						unsigned int depth)
{
	unsigned int v;

	if (desc == NULL || depth >= STRUCT_ADDRESS_SCAN_MAX_DEPTH)
		return false;

	if (fields_have_address_field(desc->fields, desc->num_fields, depth))
		return true;

	for (v = 0; v < desc->num_variants; v++) {
		const struct union_variant *var = &desc->variants[v];
		unsigned int k;

		if (fields_have_address_field(var->fields, var->num_fields,
					      depth))
			return true;
		if (var->base != NULL &&
		    fields_have_address_field(var->base->fields,
					      var->base->num_fields, depth))
			return true;
		for (k = 0; k < var->num_nested_variants; k++) {
			const struct union_variant *nv =
				&var->nested_variants[k];

			if (fields_have_address_field(nv->fields,
						      nv->num_fields, depth))
				return true;
		}
	}
	return false;
}

bool struct_desc_has_address_field(const struct struct_desc *desc)
{
	return struct_desc_has_address_field_depth(desc, 0);
}
