/*
 * Per-syscallrecord release of tracked allocations: the gates that
 * cleanup_release_post_state() puts ahead of freeing a post_state buffer,
 * and the rec->owned[] carrier that rec_own() fills and rec_owned_drain()
 * empties once the call has been dispatched.  It reaches the queue only
 * through the calls declared in deferred-free.h.
 */

#include <stdint.h>

#include "child.h"
#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

void cleanup_release_post_state(struct syscallrecord *rec)
{
	void *ptr = (void *) rec->post_state;

	rec->post_state = 0;

	if (ptr == NULL)
		return;

	/*
	 * Shape gate first: cheap reject for NULL-ish / non-canonical /
	 * misaligned scribbles.  Forward our caller's PC so per-handler
	 * shape-reject attribution stays sharp.
	 */
	if (looks_like_corrupted_ptr_pc(rec, ptr, __builtin_return_address(0)))
		return;

	/*
	 * Heap-bounds gate: matches the deferred_free_enqueue_internal
	 * reject_outside_heap rail.  Catches scribbles whose value passes
	 * the shape heuristic but lands in the stack / a library mapping /
	 * an executable mapping / one of trinity's own MAP_PRIVATE
	 * regions.  alloc_track_lookup below provides a stronger ground-
	 * truth check, but this rail short-circuits before paying the hash
	 * probe and matches the page-aligned arena-band stomp class the
	 * arena_ptr_stale_caught_post_state telemetry surfaces.  Bumps the
	 * deferred_free_reject_non_heap counter so the rate stays
	 * comparable with the matching enqueue-side reject.
	 */
	if (!is_in_glibc_heap(ptr)) {
		__atomic_add_fetch(&shm->stats.deferred_free.reject_non_heap,
				   1, __ATOMIC_RELAXED);
		return;
	}

	/*
	 * Shared-region overlap gate: matches the
	 * deferred_free_enqueue_internal reject_shared_region rail.  A
	 * scribbled snapshot whose value falls inside one of trinity's own
	 * mmap'd regions (object pool, kcov ring, etc.) is not a free()
	 * target -- libc rejects it as not-malloc()d.  Bumps the matching
	 * counter so the rate is observable alongside the enqueue-side
	 * reject.
	 */
	if (range_overlaps_shared((unsigned long) ptr, 1)) {
		__atomic_add_fetch(&shm->stats.deferred_free.reject_shared_region,
				   1, __ATOMIC_RELAXED);
		return;
	}

	/*
	 * Ownership gate: the shape guard waves through heap-shaped
	 * foreign pointers, so verify @ptr was actually produced by a
	 * zmalloc_tracked() in this child before handing it to free().
	 * A miss is silently leaked -- bounded by child lifetime, vastly
	 * preferable to a glibc/ASAN abort on a foreign address that
	 * would masquerade as a real kernel finding.
	 */
	if (!alloc_track_lookup(ptr))
		return;

	tracked_free_now(ptr);
}

void rec_own(struct syscallrecord *rec, void *ptr)
{
	if (ptr == NULL)
		return;

	/*
	 * Bound: REC_OWNED_MAX is sized so this branch never fires in
	 * practice for in-tree callers (heaviest are ~3 buffers, bound
	 * is 8).  A non-zero overflow rate is a bug to surface, not a
	 * workload to tolerate: log + counter bump so it cannot fail
	 * silently, then fall back to the deferred-free ring so the
	 * caller's "no longer your problem" contract still holds.  The
	 * fallback re-introduces the pre-dispatch ring-enqueue shape the
	 * owned list was built to eliminate -- spec acknowledges and
	 * accepts this trade-off, bounded by the assumption the fallback
	 * is unreachable.
	 */
	if (rec->owned_count >= REC_OWNED_MAX) {
		__atomic_add_fetch(&shm->stats.deferred_free.rec_owned_overflow_to_ring, 1,
				   __ATOMIC_RELAXED);
		outputerr("rec_own: rec->owned[] saturated at %u entries for %s; falling back to deferred_free_enqueue_or_leak\n",
			  REC_OWNED_MAX,
			  rec->entry != NULL ? rec->entry->name : "(unknown)");
		/*
		 * Leak-on-pressure variant: rec_own holds buffers the kernel or
		 * post handler may still consume, so a synchronous free under
		 * ring pressure would be a pre-dispatch UAF.  The overflow is
		 * unreachable in tree today (REC_OWNED_MAX=8, heaviest caller
		 * uses 3) so leak rate is theoretical.
		 */
		deferred_free_enqueue_or_leak(ptr);
		return;
	}

	rec->owned[rec->owned_count++] = ptr;
}

void rec_owned_drain(struct syscallrecord *rec)
{
	unsigned int i;

	if (rec->owned_count == 0)
		return;

	/*
	 * Walk the carrier high-to-low so a longjmp-interrupted drain
	 * leaves a contiguous prefix of still-owned slots and a tail of
	 * cleared (NULL'd, count-decremented) slots.  Critical:
	 * null the slot AND decrement owned_count BEFORE handing the
	 * pointer to tracked_free_now() -- if tracked_free_now() (or a
	 * signal taken during it) longjmps out, a second drain pass on
	 * this rec (or deferred_free_flush() on child exit) sees no
	 * residue and cannot double-free.  Mirrors the "clear the slot
	 * before free" discipline already used by free_ring_entry /
	 * deferred_free_tick on the deferred-free ring itself.
	 */
	for (i = rec->owned_count; i > 0; i--) {
		void *p = rec->owned[i - 1];
		uintptr_t v = (uintptr_t)p;

		/*
		 * Attribution overlay for the SELF-corruption cluster.  If a
		 * sibling scribbled one of the rec->owned[] slots between
		 * enqueue and drain, tracked_free_now(p) below either aborts
		 * inside glibc (heap-check trip) or SIGSEGVs deep in libc, in
		 * either case with the current SREC being this rec (the innocent
		 * drain runs after the culprit's own return) or already-replaced
		 * by whatever cleanup boundary reached the drain.  Log the
		 * pre-free SREC so the child bug-log carries the culprit BEFORE
		 * the glibc abort/SEGV vaporises the state.
		 *
		 * NULL is a legitimate slot value in principle (a caller could
		 * push NULL and rely on tracked_free_now's own NULL handling);
		 * gate the check on p != NULL so a legitimate NULL slot does
		 * not manufacture a false positive.  Same [0x10000, 2^47)
		 * bracket the always-on shape heuristic uses.  Log-only:
		 * tracked_free_now(p) still runs unchanged.
		 */
		if (unlikely(p != NULL &&
			     !(v >= 0x10000UL && v < 0x800000000000UL))) {
			struct childdata *cc = this_child();

			log_self_corrupt_culprit(
				"deferred:rec_owned_drain", v,
				cc != NULL ? &cc->syscall : NULL);
		}

		rec->owned[i - 1] = NULL;
		rec->owned_count = i - 1;
		tracked_free_now(p);
	}
}
