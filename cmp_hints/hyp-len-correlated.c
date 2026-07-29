/*
 * SHADOW length-correlation observe path (metacode-novel #7, Slice A).
 *
 * Fires from the per-record loop in cmp_hints_collect().  For every KCOV
 * CMP record that carries KCOV_CMP_CONST -- i.e. arg1 holds a compile-
 * time constant and arg2 holds the runtime operand the kernel compared
 * it against (per the KCOV convention documented at cmp_hints/collect.c
 * :477) -- walk the dispatching syscall's cataloged INPUT struct args
 * looking for an FT_LEN_BYTES / FT_LEN_COUNT field whose value in the
 * dispatched buffer equals arg2.  The value in an FT_LEN_* slot IS the
 * length struct_fill_passes chose during its length pass (chosen_len[]
 * gets written into the field via write_field_uint at struct_fill.c
 * pass 3), so this walk is exactly the "arg2 matches a chosen_len[]
 * value filled for the dispatched struct" gate the design specifies
 * without a second thread-through path.
 *
 * On a match, arg1 (the constant) becomes the expected length and gets
 * stored into a CMP_HYP_LEN_CORRELATED entry keyed by
 * cmp_field_pool_hash(desc, nr, do32, arg_idx, field_idx, size) folded
 * into the entry's cmp_ip slot -- reusing the existing hyp-pool alloc /
 * find machinery unmodified.  Slice A is SHADOW: the entry never feeds
 * the picker (its ladder skips LEN_CORRELATED, see hyp-pick.c
 * ladder_kinds[]) and never feeds struct_fill, so this path does not
 * consume RNG and does not perturb the fuzzing byte stream.
 *
 * Gate discipline mirrors cmp_hints_field_scan_record() (field.c:320):
 * NARROW MVP -- fixed-size cataloged INPUT structs only; tagged-union
 * and buffer-discriminated descs are skipped, corrupt/short-alloc/
 * unreadable pointers bail cleanly with cmp_hyp_len_correlated_bad_desc
 * bumped so the deflect rate is legible from the default run.
 */

#include <stdint.h>
#include <string.h>

#include "arch.h"
#include "cmp_hints.h"
#include "cmp_hints-internal.h"
#include "cmp_hints/hyp-internal.h"
#include "deferred-free.h"
#include "kcov.h"
#include "sanitise.h"
#include "shm.h"
#include "struct_catalog.h"
#include "syscall.h"
#include "tables.h"

/*
 * Record ONE (desc, field_idx) LEN_CORRELATED observation.  Reuses
 * cmp_hyp_find + cmp_hyp_alloc from hyp-pool.c so the per-kind cap +
 * per-syscall cap accounting is shared with every other lane.  Keyed
 * by the folded cmp_field_pool_hash so a repeat observation at the
 * same (nr, do32, arg_idx, desc, field_idx, size) refreshes the
 * existing entry instead of stacking a duplicate.
 *
 * Locking: cmp_hyp_observe (from cmp_hints_flush_pending) is the sole
 * writer to hyp_pools[] under the matching durable cmp_hint_pool
 * lock.  This scan fires BEFORE flush_pending on the collect path,
 * so we take the durable pool's lock explicitly here to preserve the
 * "hyp_pools writes serialised per-(nr, do32) via the durable pool
 * lock" invariant.  Two children fuzzing the same syscall in parallel
 * could otherwise race cmp_hyp_alloc's count-increment and stomp
 * each other's slot.
 *
 * Bumps cmp_hyp_len_correlated_recorded on a fresh insert / refresh;
 * when the alloc bails on cap saturation, the standard hyp_flat
 * cmp_hyp_pool_full / cmp_hyp_kind_full counters bump inside
 * cmp_hyp_alloc() so the drop is visible without a second dedicated
 * counter here.
 */
static void cmp_hyp_len_correlated_record_one(unsigned int nr, bool do32,
					      unsigned int arg_idx,
					      const struct struct_desc *desc,
					      unsigned int field_idx,
					      unsigned int size,
					      unsigned long expected)
{
	struct cmp_hyp_pool *pool;
	struct cmp_hint_pool *durable;
	struct cmp_hypothesis *h;
	unsigned long key;
	uint8_t width;

	if (cmp_hints_shm == NULL || nr >= MAX_NR_SYSCALL)
		return;
	if (size != 1 && size != 2 && size != 4 && size != 8)
		return;

	width = (uint8_t)size;
	pool = &cmp_hints_shm->hyp_pools[nr][do32 ? 1 : 0];
	durable = &cmp_hints_shm->pools[nr][do32 ? 1 : 0];

	/*
	 * cmp_field_pool_hash is a 32-bit splitmix over the identity
	 * tuple; widen to unsigned long for the cmp_ip slot the shared
	 * find/alloc machinery keys on.  Different (nr, arg_idx, desc,
	 * field_idx, size) tuples produce different keys with
	 * overwhelming probability; a hash collision between two distinct
	 * length fields would fold their observations into a single
	 * entry, which for SHADOW slice A only smears the would-fire
	 * value counter -- no injection consumes it.
	 */
	key = (unsigned long)cmp_field_pool_hash(desc, nr, do32 ? 1U : 0U,
						 arg_idx, field_idx, size);

	pool_lock(durable);
	/*
	 * Wild-write defence identical to cmp_hyp_observe(): a stomp past
	 * the per-syscall cap would let the find/alloc scans walk off
	 * entries[].  Silently bail under the lock -- cmp_hyp_observe
	 * already surfaces the stomp on cmp_hyp_pool_overflow from its
	 * own record path, so a second counter here would double-count.
	 */
	if (pool->count > CMP_HYP_PER_SYSCALL) {
		pool_unlock(durable);
		return;
	}

	h = cmp_hyp_find(pool, CMP_HYP_LEN_CORRELATED, key, width);
	if (h != NULL) {
		h->exemplar = (uint64_t)expected;
		h->seen_count++;
	} else {
		h = cmp_hyp_alloc(pool, CMP_HYP_LEN_CORRELATED, nr, do32,
				  key, width);
		if (h != NULL) {
			h->exemplar = (uint64_t)expected;
			h->lo = (uint64_t)expected;
			h->hi = (uint64_t)expected;
			h->seen_count = 1;
		}
	}
	pool_unlock(durable);

	if (h != NULL && kcov_shm != NULL)
		__atomic_fetch_add(
			&kcov_shm->cmp_hyp_shadow.cmp_hyp_len_correlated_recorded,
			1UL, __ATOMIC_RELAXED);
}

/*
 * Per-record LEN_CORRELATED shadow scan.  Called from
 * cmp_hints_collect() with (arg1 = KCOV constant, arg2 = runtime
 * operand) already extracted from the trace-buffer record, and the
 * same (srec, entry) dispatch-time snapshot the field-scan path uses.
 *
 * NOTE ON arg1/arg2 CONVENTION: the design doc (design-len-correlated-
 * cmp-lane-2026-07-29.md) wrote "arg1 == a length-field value we just
 * filled AND arg2 == constant C, ... expected=arg2".  KCOV's actual
 * convention (documented in cmp_hints/collect.c around line 477) is
 * the opposite: __sanitizer_cov_trace_const_cmpN puts the constant in
 * arg1 and the runtime operand in arg2.  This implementation follows
 * the codebase reality (arg1 = constant, arg2 = runtime) which the
 * cmp_hints_field_scan_record path already relies on -- the design's
 * semantic intent ("detect when a length we chose is compared to a
 * constant, record the constant as the expected length") is preserved.
 *
 * The gate is STRICTLY conservative: an FT_LEN_* slot value must equal
 * arg2 AND that slot's field->tag must be FT_LEN_BYTES or FT_LEN_COUNT
 * AND field->size must equal the record's operand width.  A plain
 * scalar cmp against a random field value with no length semantics is
 * not recorded (prefer false-negatives per design §Risks).
 *
 * Only fires on KCOV_CMP_CONST records -- the caller in
 * cmp_hints_collect() already gates on !(type & KCOV_CMP_CONST) → drop,
 * so by the time this function runs arg1 is guaranteed to be a
 * compile-time constant.  No CONST bit check needed here.
 */
void cmp_hyp_len_correlated_scan_record(struct syscallrecord *srec,
					struct syscallentry *entry,
					unsigned int nr, bool do32,
					unsigned long arg1, unsigned long arg2,
					unsigned int size, unsigned long cmp_ip)
{
	unsigned int slot;
	unsigned int slot_max;

	(void)cmp_ip;	/* keyed by field identity, not cmp_ip; sink here */

	if (cmp_hints_shm == NULL || srec == NULL || entry == NULL)
		return;
	if (size != 1 && size != 2 && size != 4 && size != 8)
		return;

	slot_max = entry->num_args;
	if (slot_max > 6)
		slot_max = 6;

	for (slot = 0; slot < slot_max; slot++) {
		enum argtype t = entry->argtype[slot];
		const struct struct_desc *desc;
		const unsigned char *buf;
		unsigned long limit;
		size_t actual_len;
		unsigned int i;

		if (t != ARG_STRUCT_PTR_IN && t != ARG_STRUCT_PTR_INOUT)
			continue;

		desc = struct_arg_lookup(nr, slot + 1, do32, srec);
		if (desc == NULL || desc->struct_size == 0 ||
		    desc->fields == NULL || desc->num_fields == 0)
			continue;

		/* NARROW MVP: skip tagged-union / buffer-discriminated descs
		 * for the same reason cmp_hints_field_scan_record does --
		 * variant-scoped attribution needs the live variant choice
		 * which is post-fill state the CMP-time scan can't resolve
		 * safely from the snapshot alone. */
		if (desc->variants != NULL || desc->num_variants != 0 ||
		    desc->buffer_discrim_size != 0)
			continue;

		buf = (const unsigned char *)(uintptr_t)
			srec->dispatch_args[slot];
		if (is_corrupt_ptr_shape(buf)) {
			if (kcov_shm != NULL)
				__atomic_fetch_add(
					&kcov_shm->cmp_hyp_shadow.cmp_hyp_len_correlated_bad_desc,
					1UL, __ATOMIC_RELAXED);
			continue;
		}

		actual_len = alloc_track_lookup_size((void *)(uintptr_t)buf);
		if (actual_len == 0) {
			if (kcov_shm != NULL)
				__atomic_fetch_add(
					&kcov_shm->cmp_hyp_shadow.cmp_hyp_len_correlated_bad_desc,
					1UL, __ATOMIC_RELAXED);
			continue;
		}
		limit = desc->struct_size;
		if ((unsigned long)actual_len < limit)
			limit = (unsigned long)actual_len;

		if (!range_readable_user(buf, limit)) {
			if (kcov_shm != NULL)
				__atomic_fetch_add(
					&kcov_shm->cmp_hyp_shadow.cmp_hyp_len_correlated_bad_desc,
					1UL, __ATOMIC_RELAXED);
			continue;
		}

		for (i = 0; i < desc->num_fields; i++) {
			const struct struct_field *f = &desc->fields[i];
			unsigned long fv;

			/* STRICT: only FT_LEN_BYTES / FT_LEN_COUNT -- a random
			 * scalar cmp against an unrelated field must NOT be
			 * recorded as a length hint (design §Risks: prefer
			 * false-negatives, do not record random scalars). */
			if (f->tag != FT_LEN_BYTES && f->tag != FT_LEN_COUNT)
				continue;

			/* Width must match the record's operand width -- a
			 * u16 length field vs a 4-byte cmp record is a
			 * different comparison, drop. */
			if (f->size != size)
				continue;

			if ((unsigned long)f->offset + size > limit)
				continue;

			fv = 0;
			switch (size) {
			case 1:
				fv = *(const uint8_t *)(buf + f->offset);
				break;
			case 2: {
				uint16_t v;

				memcpy(&v, buf + f->offset, sizeof(v));
				fv = v;
				break;
			}
			case 4: {
				uint32_t v;

				memcpy(&v, buf + f->offset, sizeof(v));
				fv = v;
				break;
			}
			case 8: {
				uint64_t v;

				memcpy(&v, buf + f->offset, sizeof(v));
				fv = v;
				break;
			}
			}

			/* Gate: the length we chose (fv, read back from the
			 * dispatched buffer's FT_LEN_* slot) matches the
			 * runtime operand the kernel compared its constant
			 * against (arg2).  arg1 is that constant -- the
			 * expected length. */
			if (fv != arg2)
				continue;

			if (kcov_shm != NULL) {
				__atomic_fetch_add(
					&kcov_shm->cmp_hyp_shadow.cmp_hyp_len_correlated_would_fire,
					1UL, __ATOMIC_RELAXED);
				if (arg1 != 0)
					__atomic_fetch_add(
						&kcov_shm->cmp_hyp_shadow.cmp_hyp_len_correlated_value_nonzero,
						1UL, __ATOMIC_RELAXED);
			}

			cmp_hyp_len_correlated_record_one(nr, do32, slot + 1,
							  desc, i, size, arg1);
		}
	}
}
