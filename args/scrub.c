#include <stdbool.h>
#include <stdint.h>

#include "args-internal.h"
#include "sanitise.h"		// avoid_shared_buffer_out
#include "shm.h"
#include "struct_catalog.h"
#include "syscall.h"
#include "utils.h"		// is_corrupt_ptr_shape, is_in_glibc_heap, range_readable_user

/* Default-on scrub: any argtype with default_address_scrub set in the
 * descriptor table (today ARG_ADDRESS / ARG_NON_NULL_ADDRESS / ARG_RANGE)
 * that ended up aliasing shared_regions or the libc heap arena gets
 * redirected to a writable address before the syscall is issued. Catches
 * the coverage-gap class where per-syscall sanitisers either don't call
 * avoid_shared_buffer_out() or miss specific slots. Length default is
 * page_size (conservative; bare ARG_ADDRESS carries no length info
 * and walking adjacent slots per dispatch is too expensive). */

/*
 * Bounded recursion depth for the nested-address walker.  Real
 * cataloged structs are flat or one level deep (msghdr -> iovec); the
 * cap mirrors STRUCT_ADDRESS_SCAN_MAX_DEPTH in struct_catalog.c so a
 * future cyclic catalog entry cannot drive infinite recursion at
 * dispatch time.
 */
#define NESTED_ADDRESS_SCRUB_MAX_DEPTH	4

/*
 * Stateless pre-deref guard for every struct base
 * scrub_struct_addresses() is about to walk -- the top-level
 * rec->aN slot fed in by nested_address_scrub(), and the
 * FT_PTR_STRUCT / FT_PTR_ARRAY base pointers read out of a parent
 * struct during the walk.  All three are the exact class of value a
 * sibling scribble can replace with garbage between sanitise and
 * dispatch.  Reject when the candidate base either fails the shape
 * predicate (NULL-ish, non-canonical, or misaligned) or falls
 * outside the cached glibc brk arena: a legitimate zmalloc_tracked()
 * struct slot satisfies both, and a scribbled value that aliases
 * neither does not.  Bump nested_scrub_reject_untracked on the reject
 * so a clean run (near-zero rate-of-change) double-checks the guard
 * is not false-rejecting valid bases.  The predicates are
 * lifecycle-independent on purpose: by scrub time the deferred-free
 * ring has already consumed the tracker entries for these pointers,
 * so an alloc_track_lookup()-based gate would false-reject ~100% of
 * legitimately-generated bases.
 */
static bool nested_scrub_base_unsafe(unsigned long base)
{
	const void *p = (const void *) base;

	if (is_corrupt_ptr_shape(p) || !is_in_glibc_heap(p)) {
		__atomic_add_fetch(&shm->stats.deferred_free.nested_scrub_reject_untracked,
				   1, __ATOMIC_RELAXED);
		return true;
	}
	return false;
}

static void scrub_struct_addresses(unsigned char *buf, unsigned int size,
				   const struct struct_desc *desc,
				   struct syscallrecord *rec,
				   unsigned int depth);

/*
 * Per-field-array scrub sweep: visit every FT_ADDRESS in @fields[0..n)
 * and recurse through FT_PTR_STRUCT / FT_PTR_ARRAY edges.  Shared by
 * the flat desc->fields[] walk and the variant overlay walks
 * (variant->fields, variant->base->fields, matched nested variant's
 * fields), mirroring how struct_field_fill_schema_aware() splits
 * between a flat pass and overlay passes.  @rec is threaded through so
 * a recursed-into child struct can resolve its own variants the same
 * way the FILL path does in struct_field_fill_schema_aware().
 *
 * Sibling LEN lookup uses find_field_index_in() against the same
 * fields[] array currently being walked, matching the runtime
 * pre-pin pass and validate_struct_catalog()'s comment that each
 * fields[] array is an independent name-resolution scope.
 */
static void scrub_field_array(unsigned char *buf, unsigned int size,
			      const struct struct_field *fields,
			      unsigned int num_fields,
			      struct syscallrecord *rec,
			      unsigned int depth)
{
	unsigned int i;

	for (i = 0; i < num_fields; i++) {
		const struct struct_field *f = &fields[i];
		const struct struct_desc *target;
		unsigned long ptr;

		if (f->offset + f->size > size)
			continue;

		switch (f->tag) {
		case FT_ADDRESS: {
			/*
			 * Scrub at the field's natural pointer width.
			 * Sub-pointer-sized FT_ADDRESS fields cannot hold a
			 * useful address; skip them rather than scribble
			 * adjacent bytes.
			 */
			if (f->size != sizeof(unsigned long))
				break;
			avoid_shared_buffer_out(
				(unsigned long *)(buf + f->offset), page_size);
			break;
		}
		case FT_PTR_STRUCT:
			ptr = (unsigned long) read_field_uint(buf, f);
			if (ptr == 0)
				break;
			target = struct_catalog_lookup(f->u.ptr_struct.struct_name);
			if (target == NULL || target->struct_size == 0)
				break;
			if (nested_scrub_base_unsafe(ptr))
				break;
			scrub_struct_addresses((unsigned char *) ptr,
					       target->struct_size,
					       target, rec, depth + 1);
			break;
		case FT_EMBEDDED_STRUCT:
			/*
			 * No pointer indirection: the target lives in-place at
			 * buf + offset within the already-validated parent
			 * buffer, so the nested_scrub_base_unsafe() guard the
			 * FT_PTR_STRUCT arm applies to a freshly-read pointer
			 * is not appropriate here.  Recurse at the child's
			 * struct_size so per-field bounds still gate reads.
			 */
			target = struct_catalog_lookup(f->u.embedded_struct.elem_struct_name);
			if (target == NULL || target->struct_size == 0)
				break;
			if ((unsigned long) f->offset + target->struct_size > size)
				break;
			scrub_struct_addresses(buf + f->offset,
					       target->struct_size,
					       target, rec, depth + 1);
			break;
		case FT_PTR_ARRAY: {
			unsigned long count = 0;
			unsigned long cap;
			int paired;
			unsigned long j;

			ptr = (unsigned long) read_field_uint(buf, f);
			if (ptr == 0)
				break;
			target = struct_catalog_lookup(f->u.ptr_array.elem_struct);
			if (target == NULL || target->struct_size == 0)
				break;
			if (nested_scrub_base_unsafe(ptr))
				break;

			paired = find_field_index_in(fields, num_fields,
						     f->u.ptr_array.len_field);
			if (paired >= 0)
				count = (unsigned long) read_field_uint(
					buf, &fields[paired]);

			/*
			 * Cap the iteration at the catalog's declared
			 * max_count (or PTR_ARRAY_DEFAULT_MAX) so a sibling-
			 * scribbled len field cannot drive a walk past the
			 * allocation's tail and SEGV the sanitiser.
			 */
			cap = f->u.ptr_array.max_count;
			if (cap == 0)
				cap = PTR_ARRAY_DEFAULT_MAX;
			if (count > cap)
				count = cap;

			for (j = 0; j < count; j++) {
				unsigned char *elem = (unsigned char *) ptr
					+ j * target->struct_size;

				scrub_struct_addresses(elem,
						       target->struct_size,
						       target, rec, depth + 1);
			}
			break;
		}
		default:
			break;
		}
	}
}

/*
 * Mirror struct_variant_overlay_nested() from the FILL path: when an
 * outer variant carries a nested_variants table, re-resolve the
 * sub-variant against the just-filled buffer and scrub variant->base
 * (if set) plus the matched nested->fields[] in the same order FILL
 * wrote them.  Depth-1 only -- struct_desc_resolve_nested_variant()
 * rejects nested-of-nested, matching the FILL contract.
 */
static void scrub_variant_overlay_nested(unsigned char *buf,
					 unsigned int size,
					 const struct union_variant *variant,
					 struct syscallrecord *rec,
					 unsigned int depth)
{
	const struct union_variant *nested;

	if (variant->nested_variants == NULL)
		return;

	nested = struct_desc_resolve_nested_variant(variant, buf, size);
	if (nested == NULL && variant->base == NULL)
		return;

	if (variant->base != NULL)
		scrub_field_array(buf, size,
				  variant->base->fields,
				  variant->base->num_fields, rec, depth);

	if (nested != NULL)
		scrub_field_array(buf, size,
				  nested->fields,
				  nested->num_fields, rec, depth);
}

/*
 * Walk one cataloged-struct buffer and scrub every FT_ADDRESS field,
 * recursing into FT_PTR_STRUCT targets and FT_PTR_ARRAY elements whose
 * element struct is itself cataloged.  FT_PTR_BYTES and the FT_PTR_*
 * pointers themselves are trinity-allocated via zmalloc_tracked() and
 * cannot alias shared_regions[] or the libc brk arena; they are not
 * scrub targets, only recursion edges.
 *
 * Variant-aware: when desc carries variants the active variant
 * resolves the field set the FILL path actually wrote, and a variant-
 * only FT_ADDRESS is reachable only through variant->fields,
 * variant->base->fields, or the matched nested_variant->fields.  The
 * traversal exactly mirrors struct_field_fill_schema_aware() so an
 * arg-derived variant replaces desc->fields, a buffer-derived variant
 * overlays it, and nested overlays apply on top -- the scrub visits
 * every byte the fill could have written an FT_ADDRESS into.  Without
 * this mirroring a variant-only FT_ADDRESS field is never scrubbed,
 * leaving it free to alias a shared sibling buffer and re-open the
 * cross-child corruption window the top-level scrub closes.
 */
static void scrub_struct_addresses(unsigned char *buf, unsigned int size,
				   const struct struct_desc *desc,
				   struct syscallrecord *rec,
				   unsigned int depth)
{
	const struct union_variant *variant;

	if (buf == NULL || desc == NULL ||
	    depth >= NESTED_ADDRESS_SCRUB_MAX_DEPTH)
		return;

	/*
	 * Range-gate the whole walk before touching @buf.  At depth 0
	 * @buf is the caller-supplied syscall slot (rec->aN); at depth
	 * >= 1 it is a pointer value read out of a parent struct.  Both
	 * are the exact class of value a sibling scribble can replace
	 * with garbage between sanitise and dispatch -- defending
	 * against which is the entire reason the scrub exists.  The
	 * field walk below dereferences @buf in two ways that fault on
	 * a stale pointer with no recovery: read_field_uint() does a
	 * memcpy out of buf+offset, and avoid_shared_buffer_out() ->
	 * asb_relocate() reads *addr at the top of its body (the
	 * asb_copy_active sigsetjmp guard covers only the inner
	 * memcpy, not this outer deref).  The per-field bound check
	 * (f->offset + f->size > size) only constrains the walk within
	 * an assumed-valid @size-byte allocation; it does nothing when
	 * @buf itself is unmapped.
	 *
	 * range_readable_user() proves @buf is mapped from cached
	 * state (tracked shared regions + libc heap snapshot) -- a
	 * pure in-process lookup, no deref, cannot fault.  Legit
	 * zmalloc_tracked() targets live in the heap snapshot and
	 * pass; scribbled garbage that aliases neither snapshot fails.
	 * Skip-the-scrub on false is safe: the scrub is purely
	 * defensive, the fuzzed syscall has not yet fired, and falling
	 * through means the kernel sees the pre-scrub argument -- the
	 * exact gap the scrub narrows, not a regression.
	 */
	if (!range_readable_user(buf, size))
		return;

	/*
	 * Arg-derived variant: FILL writes variant->fields[] in place of
	 * desc->fields[].  Mirror exactly -- scrubbing desc->fields[] here
	 * would walk a field set that was never populated by FILL.
	 */
	variant = struct_desc_resolve_variant(desc, rec, NULL);
	if (variant != NULL) {
		scrub_field_array(buf, size, variant->fields,
				  variant->num_fields, rec, depth);
		scrub_variant_overlay_nested(buf, size, variant, rec, depth);
		return;
	}

	/*
	 * No arg-derived variant.  FILL runs desc->fields[] first; if the
	 * descriptor carries a buffer-derived discriminator the resolved
	 * variant is then overlaid on top.  Mirror exactly.
	 */
	scrub_field_array(buf, size, desc->fields, desc->num_fields,
			  rec, depth);

	if (desc->buffer_discrim_size == 0)
		return;

	variant = struct_desc_resolve_variant(desc, rec, buf);
	if (variant != NULL) {
		scrub_field_array(buf, size, variant->fields,
				  variant->num_fields, rec, depth);
		scrub_variant_overlay_nested(buf, size, variant, rec, depth);
	}
}

void nested_address_scrub(struct syscallentry *entry,
			  struct syscallrecord *rec)
{
	uint8_t mask = entry->nested_address_scrub_mask;

	while (mask != 0) {
		unsigned int i = (unsigned int)__builtin_ctz(mask) + 1;
		const struct struct_desc *desc;
		unsigned long slot;

		switch (i) {
		case 1: slot = rec->a1; break;
		case 2: slot = rec->a2; break;
		case 3: slot = rec->a3; break;
		case 4: slot = rec->a4; break;
		case 5: slot = rec->a5; break;
		case 6: slot = rec->a6; break;
		default: slot = 0; break;
		}

		desc = struct_arg_lookup(rec->nr, i, rec->do32bit, rec);
		if (slot != 0 && desc != NULL &&
		    !nested_scrub_base_unsafe(slot))
			scrub_struct_addresses((unsigned char *) slot,
					       desc->struct_size, desc,
					       rec, 0);
		mask &= (uint8_t)(mask - 1);
	}
}
