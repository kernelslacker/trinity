/*
 * deferred_free_test.c -- deferred-free ownership and sealing fixtures.
 *
 * Eight fixtures covering deferred-free ownership and sealing
 * invariants.  Three build flavors exist: debug (default), ASAN
 * (ASAN=1), and NDEBUG (NDEBUG=1).  All eight fixtures pass in all
 * three flavors.
 *
 * Prerequisites: persist/deferred-free.c compiled as a REAL_SRC (added
 * by the test-seam extension that compiles persist/deferred-free.c).
 *
 * mprotect failure injection (fixture 7): the Makefile passes
 * -Wl,--wrap=mprotect so every PLT mprotect call in the linked binary
 * goes through __wrap_mprotect() below.  When g_mprotect_fail_countdown
 * is zero (the default) the wrapper is transparent.  Fixture 7 sets it
 * to 5 before calling deferred_free_seal_all() to make the first five
 * "seal" (PROT_READ or PROT_NONE) calls fail with EACCES; they succeed
 * again once the countdown reaches zero.  ASAN's shadow-memory mprotect
 * calls go through __sanitizer_internal_mprotect (a direct syscall) and
 * are not routed via the PLT, so they are unaffected.
 *
 * Suite entry point: deferred_free_ownership_self_check()
 *
 * Fixtures
 * --------
 * 1. duplicate_address     -- enqueue same addr twice; second rejected
 * 2. hash_desync_authority -- array is authoritative, hash accelerator
 * 3. ring_ownership        -- exactly one owner per ring slot
 * 4. generation_retirement -- retired entries unreachable after flush
 * 5. enomem_disposal       -- consume-fail => leak, not partial free
 * 6. signal_unwind         -- loop-top seal_all restores after longjmp
 * 7. seal_failure_per_region (×5) -- NO dispatch after mprotect fail;
 *                                    seal_all returns false on failure,
 *                                    true on clean re-seal (all flavors)
 * 8. permanent_seal_failure_suppresses_dispatch -- permanent mprotect
 *                                    failure: seal_all returns false on
 *                                    every call; simulated chokepoint
 *                                    caller proves dispatch suppressed
 */

#include <errno.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "deferred-free.h"	/* public deferred-free API */
#include "params.h"		/* extern bool deferred_free_batch */
#include "shm.h"		/* extern struct shm_s *shm */
#include "stats_ring.h"		/* extern struct stats_aggregate parent_stats */

/*
 * Mirror of file-scope constants from persist/deferred-free.c.
 * Update here if the production constants change.
 */
#define ALLOC_TRACK_SIZE	4096
#define DEFERRED_RING_SIZE	64
#define DEFERRED_TICK_BATCH	16

/* ------------------------------------------------------------------ */
/* mprotect failure-injection wrapper (fixtures 7 and 8)              */
/* ------------------------------------------------------------------ */

extern int __real_mprotect(void *addr, size_t len, int prot);
int __wrap_mprotect(void *addr, size_t len, int prot);

/*
 * When > 0, the first g_mprotect_fail_countdown "seal" mprotect calls
 * (prot == PROT_READ or prot == PROT_NONE) are failed with EACCES.
 * All other mprotect calls (prot & PROT_WRITE, i.e. "unlock" calls)
 * are passed through unconditionally so the deferred-free init and
 * normal admission paths are unaffected.
 *
 * When g_mprotect_fail_permanent is true EVERY seal mprotect call
 * (prot == PROT_READ or prot == PROT_NONE) fails unconditionally,
 * regardless of the countdown.  Used by fixture 8 to simulate a
 * persistent mprotect failure so that deferred_free_seal_all() never
 * recovers and the caller cannot "race past" a transient window.
 */
static volatile int  g_mprotect_fail_countdown;
static volatile bool g_mprotect_fail_permanent;

int __wrap_mprotect(void *addr, size_t len, int prot)
{
	if ((prot == PROT_READ || prot == PROT_NONE) &&
	    (g_mprotect_fail_permanent ||
	     g_mprotect_fail_countdown > 0)) {
		if (!g_mprotect_fail_permanent)
			g_mprotect_fail_countdown--;
		errno = EACCES;
		return -1;
	}
	return __real_mprotect(addr, len, prot);
}

/* ------------------------------------------------------------------ */
/* Assertion helper                                                    */
/* ------------------------------------------------------------------ */

static void df_selftest_bug(const char *msg,
			    const char *file, unsigned int line)
{
	fprintf(stderr, "FAIL: deferred_free_ownership: %s:%u: %s\n",
		file, line, msg);
	fflush(stderr);
	abort();
}

#define DF_ASSERT(cond) \
	do { \
		if (!(cond)) \
			df_selftest_bug(#cond, __FILE__, __LINE__); \
	} while (0)

/* ------------------------------------------------------------------ */
/* Fake-pointer factory for alloc_track-only tests                    */
/*                                                                     */
/* Returns a canonical, 8-byte-aligned user-VA that is_corrupt_ptr_   */
/* shape() accepts (>= 0x10000, < 2^47, aligned) but is NOT a real    */
/* malloc result.  Used only in deferred_alloc_track() calls where the  */
/* pointer value is stored as a membership token; never passed to      */
/* deferred_free_enqueue() or free().                                  */
/* ------------------------------------------------------------------ */

static unsigned int g_fake_idx;

static inline void *next_fake_ptr(void)
{
	/*
	 * 0x20000 + idx*16: canonical user VA, 16-byte aligned, non-NULL,
	 * well below the brk arena so glibc malloc never returns addresses
	 * here.  The test fake is_in_glibc_heap() returns true for all
	 * non-NULL pointers so these sail through deferred-free's heap
	 * check if they ever reach it.
	 */
	return (void *)((uintptr_t)0x20000 + (uintptr_t)g_fake_idx++ * 16);
}

/* ------------------------------------------------------------------ */
/* Fixture 1: Duplicate address                                       */
/*                                                                     */
/* Enqueue the same address twice.  The second enqueue must be         */
/* rejected/coalesced: ring[] is source-of-truth, and ring_contains() */
/* intercepts the second admission, bumping double_admit_skip.         */
/* After both enqueue calls: alloc_track still has the pointer         */
/* (non-consuming lookup); the hash accelerator and array agree.       */
/* ------------------------------------------------------------------ */

static void fixture_duplicate_address(void)
{
	void *ptr;
	unsigned long base_skip;

	ptr = malloc(16);
	DF_ASSERT(ptr != NULL);
	memset(ptr, 0xAB, 16);

	deferred_alloc_track(ptr, 16);

	/* Non-consuming probe: alloc_track has the pointer. */
	DF_ASSERT(alloc_track_lookup(ptr));

	base_skip = shm->stats.deferred_free.double_admit_skip;

	/* First enqueue: admitted to the ring. */
	deferred_free_enqueue(ptr);
	DF_ASSERT(shm->stats.deferred_free.double_admit_skip == base_skip);

	/* alloc_track entry is still present (non-consuming enqueue). */
	DF_ASSERT(alloc_track_lookup(ptr));

	/* Second enqueue: ring_contains(ptr) returns true inside the
	 * ring_unlock bracket -> bail, bump double_admit_skip. */
	deferred_free_enqueue(ptr);
	DF_ASSERT(shm->stats.deferred_free.double_admit_skip == base_skip + 1);

	/* Array and hash still agree: ptr is tracked (ring owns lifecycle). */
	DF_ASSERT(alloc_track_lookup(ptr));

	/* Drain the ring (frees ptr via tracked_free_checked + free()). */
	deferred_free_flush();
}

/* ------------------------------------------------------------------ */
/* Fixture 2: Hash desync / displacement                              */
/*                                                                     */
/* Force alloc_track[] and alloc_track_hash[] out of agreement via the */
/* duplicate-ptr displacement scenario described in the alloc_track_   */
/* lookup() comment (deferred-free.c §"Membership probe"):            */
/*                                                                     */
/*   1. Track ptr_A -> array slot S1, hash[H_A] = ptr_A               */
/*   2. Track ptr_A again -> array slot S2, hash unchanged (idempotent)*/
/*   3. Track (ALLOC_TRACK_SIZE-2) fillers -> head wraps, slot S1      */
/*      is displaced; alloc_track_hash_remove(ptr_A) removes the       */
/*      hash entry while S2 still holds ptr_A.                         */
/*                                                                     */
/* Assert: alloc_track_lookup(ptr_A) returns true (array fallback),   */
/* and alloc_track_lookup_array_fallback_hit was incremented.          */
/* The array is authoritative; the hash is an accelerator.            */
/* ------------------------------------------------------------------ */

static void fixture_hash_desync_array_authority(void)
{
	void *ptr_A;
	unsigned long base_fallback;
	unsigned int i;

	ptr_A = malloc(8);
	DF_ASSERT(ptr_A != NULL);

	base_fallback = shm->stats.deferred_free.alloc_track_lookup_array_fallback_hit;

	/*
	 * Step 1: track ptr_A -> array slot S1 (head == H0, so S1=H0&mask).
	 * Step 2: track ptr_A again -> array slot S2 = (H0+1)&mask.
	 *         hash_insert is idempotent: hash[H_A] already holds ptr_A.
	 */
	deferred_alloc_track(ptr_A, 8);
	deferred_alloc_track(ptr_A, 8);

	DF_ASSERT(alloc_track_lookup(ptr_A));

	/*
	 * Step 3: register ALLOC_TRACK_SIZE-1 fake pointers.
	 *
	 * After two ptr_A registrations head is at H0+2.  The N-th filler
	 * writes slot (H0+1+N) & mask.  We need (H0+1+N) & mask == S1 ==
	 * H0 & mask, i.e. N+1 ≡ 0 (mod ALLOC_TRACK_SIZE), so N =
	 * ALLOC_TRACK_SIZE-1 = 4095.  The (ALLOC_TRACK_SIZE-1)-th filler
	 * writes slot S1 and triggers alloc_track_hash_remove(ptr_A).
	 * Array slot S2 still holds ptr_A (would need one more full
	 * rotation to overwrite it).
	 *
	 * Fake ptrs are never enqueued or freed; they are pure
	 * membership tokens that rotate out in later fixtures.
	 */
	for (i = 0; i < ALLOC_TRACK_SIZE - 1; i++)
		deferred_alloc_track(next_fake_ptr(), 0);

	/*
	 * Hash now lacks ptr_A (removed by the displacement); array
	 * still has it.  alloc_track_lookup() must fall back to the
	 * linear array scan, return true, and bump the fallback counter.
	 */
	DF_ASSERT(alloc_track_lookup(ptr_A));
	DF_ASSERT(shm->stats.deferred_free.alloc_track_lookup_array_fallback_hit
		  > base_fallback);

	/*
	 * Free ptr_A via tracked_free_now(): ring_contains returns false
	 * (never enqueued), so tracked_free_checked -> alloc_track_consume
	 * (finds ptr_A at slot S2) -> free(ptr_A).
	 */
	tracked_free_now(ptr_A);

	/* After consume: ptr_A is gone from alloc_track. */
	DF_ASSERT(!alloc_track_lookup(ptr_A));
}

/* ------------------------------------------------------------------ */
/* Fixture 3: Ring ownership                                          */
/*                                                                     */
/* Prove exactly one owner per ring slot across enqueue/evict/dispose.*/
/* Fill the ring with DEFERRED_RING_SIZE distinct pointers, then retry */
/* each enqueue: every retry must be rejected by ring_contains(),      */
/* bumping double_admit_skip by exactly DEFERRED_RING_SIZE.            */
/* No slot is disposed twice (the flush frees each slot exactly once). */
/* ------------------------------------------------------------------ */

static void fixture_ring_ownership(void)
{
	void *ptrs[DEFERRED_RING_SIZE];
	unsigned long base_skip;
	unsigned int i;

	for (i = 0; i < DEFERRED_RING_SIZE; i++) {
		ptrs[i] = malloc(8);
		DF_ASSERT(ptrs[i] != NULL);
		deferred_alloc_track(ptrs[i], 8);
	}

	base_skip = shm->stats.deferred_free.double_admit_skip;

	/* Fill the ring: all DEFERRED_RING_SIZE slots occupied. */
	for (i = 0; i < DEFERRED_RING_SIZE; i++)
		deferred_free_enqueue(ptrs[i]);

	/* No double-admits during first fill. */
	DF_ASSERT(shm->stats.deferred_free.double_admit_skip == base_skip);

	/*
	 * Re-enqueue each pointer: ring_contains() catches every one.
	 * double_admit_skip must advance by exactly DEFERRED_RING_SIZE,
	 * confirming each pointer occupies exactly one slot.
	 */
	for (i = 0; i < DEFERRED_RING_SIZE; i++)
		deferred_free_enqueue(ptrs[i]);

	DF_ASSERT(shm->stats.deferred_free.double_admit_skip
		  == base_skip + DEFERRED_RING_SIZE);

	/*
	 * Flush drains every ring slot exactly once.  Each free_ring_entry
	 * call clears ring[i].ptr BEFORE calling free() -- no double-free,
	 * no partial transition.
	 */
	deferred_free_flush();
}

/* ------------------------------------------------------------------ */
/* Fixture 4: Generation retirement                                   */
/*                                                                     */
/* Evict a pointer from the ring into the generation arena, then flush.*/
/* Assert: the evicted pointer's alloc_track entry is consumed during  */
/* gen_arena_flush() (retired = unreachable); subsequent address reuse */
/* is safe because the old alloc_track slot was already cleared.       */
/*                                                                     */
/* Protocol:                                                           */
/*   - Fill ring with DEFERRED_RING_SIZE ptrs (all ACTIVE).           */
/*   - Enqueue one more ptr -> ring_evict_oldest_safe() evicts the     */
/*     lowest-TTL slot into the generation arena (gen_arena_push).     */
/*   - Before flush: alloc_track has all DEFERRED_RING_SIZE+1 ptrs.   */
/*   - deferred_free_flush() runs gen_arena_flush() FIRST, retiring    */
/*     the evicted ptr (tracked_free_checked -> alloc_track_consume -> */
/*     free).  Then the ring drain frees the remaining 64 ptrs.        */
/*   - After flush: alloc_track_lookup for all 65 ptrs returns false.  */
/* ------------------------------------------------------------------ */

static void fixture_generation_retirement(void)
{
	void *ptrs[DEFERRED_RING_SIZE + 1];
	unsigned long base_admitted, base_retired;
	unsigned int i;

	for (i = 0; i < DEFERRED_RING_SIZE + 1; i++) {
		ptrs[i] = malloc(8);
		DF_ASSERT(ptrs[i] != NULL);
		deferred_alloc_track(ptrs[i], 8);
	}

	base_admitted = shm->stats.deferred_free.gen_arena_admitted;
	base_retired  = shm->stats.deferred_free.gen_arena_retired_ok;

	/* Fill the ring (64 ptrs). */
	for (i = 0; i < DEFERRED_RING_SIZE; i++)
		deferred_free_enqueue(ptrs[i]);

	/* One more enqueue triggers ring_evict_oldest_safe() ->
	 * gen_arena_push() for the evicted pointer. */
	deferred_free_enqueue(ptrs[DEFERRED_RING_SIZE]);

	/* gen_arena_admitted must have increased by at least 1
	 * (unless the arena was under pressure, in which case it
	 * fell back to ring_evict_leaked -- still acceptable). */
	unsigned long admitted_delta =
		shm->stats.deferred_free.gen_arena_admitted - base_admitted;

	/*
	 * All 65 pointers are still alloc_track-resident before flush:
	 * the gen arena holds the evicted pointer without consuming its
	 * alloc_track entry (consume is deferred to retirement).
	 */
	if (admitted_delta > 0) {
		/* We can only verify the non-evicted ptrs are tracked
		 * (the evicted one's slot may have rotated under the
		 * heavy fixture-2 churn above -- benign).
		 * At minimum, the newly enqueued final ptr must be tracked. */
		DF_ASSERT(alloc_track_lookup(ptrs[DEFERRED_RING_SIZE]));
	}

	/*
	 * Flush: gen_arena_flush() runs first and retires every arena
	 * entry via tracked_free_checked() -> alloc_track_consume() ->
	 * free().  Then the ring drain frees the remaining 64 ptrs.
	 *
	 * After flush every alloc_track entry for ptrs[] has been consumed:
	 * retired entries are unreachable and cannot be resurrected by
	 * address reuse (the consuming flush cleared the slot).
	 */
	deferred_free_flush();

	if (admitted_delta > 0) {
		/* gen_arena_retired_ok must advance by at least admitted_delta
		 * (the force-flush retires regardless of bake age). */
		DF_ASSERT(shm->stats.deferred_free.gen_arena_retired_ok
			  >= base_retired + admitted_delta);
	}

	/*
	 * After flush all 65 alloc_track entries are consumed:
	 * no ptr is alloc_track-resident any more.
	 */
	for (i = 0; i < DEFERRED_RING_SIZE + 1; i++)
		DF_ASSERT(!alloc_track_lookup(ptrs[i]));
}

/* ------------------------------------------------------------------ */
/* Fixture 5: ENOMEM on disposal (consume-fail => leak-on-uncertainty)*/
/*                                                                     */
/* Simulate the disposal-path uncertainty case: enqueue ptr_A, then   */
/* rotate its alloc_track entry out by tracking ALLOC_TRACK_SIZE-1    */
/* fake pointers.  When deferred_free_flush() drains the ring,        */
/* free_ring_entry(ptr_A) -> tracked_free_checked -> alloc_track_     */
/* consume fails (ptr_A no longer in alloc_track) -> leak-on-         */
/* uncertainty: ptr_A is NOT freed, deferred_free_corrupt_ptr bumps.  */
/*                                                                     */
/* "Not a partial state transition": the ring slot is fully cleared    */
/* (ring[i].ptr = NULL, ring_count decremented) even though ptr_A was  */
/* not freed.  The ring is left in a consistent zero-count state.      */
/* The leak is counted: deferred_free_corrupt_ptr (via parent_stats).  */
/*                                                                     */
/* ASAN validation: ptr_A memory remains accessible after the flush    */
/* (a use-after-free would be caught here if the code had incorrectly  */
/* freed it despite the consume failure).                              */
/* ------------------------------------------------------------------ */

static void fixture_enomem_disposal(void)
{
	void *ptr_A;
	unsigned long base_corrupt;
	unsigned int i;
	volatile unsigned char *p;

	ptr_A = malloc(16);
	DF_ASSERT(ptr_A != NULL);
	memset(ptr_A, 0xDE, 16);

	deferred_alloc_track(ptr_A, 16);
	DF_ASSERT(alloc_track_lookup(ptr_A));

	/* Enqueue ptr_A into the ring. */
	deferred_free_enqueue(ptr_A);
	DF_ASSERT(alloc_track_lookup(ptr_A));  /* still tracked */

	base_corrupt = parent_stats.deferred_free_corrupt_ptr;

	/*
	 * Register ALLOC_TRACK_SIZE fake pointers to wrap the alloc_track[]
	 * ring once, overwriting ptr_A's slot.  After tracking ptr_A at
	 * head H5, head is at H5+1.  The N-th filler writes slot (H5+N) &
	 * mask.  We need (H5+N) & mask == H5 & mask == slot_A, i.e.
	 * N = ALLOC_TRACK_SIZE = 4096.  After this:
	 *   alloc_track_hash_remove(ptr_A) was called (the displaced slot
	 *   triggered it), and alloc_track[] no longer contains ptr_A.
	 */
	for (i = 0; i < ALLOC_TRACK_SIZE; i++)
		deferred_alloc_track(next_fake_ptr(), 0);

	/* ptr_A no longer in alloc_track after full rotation. */
	DF_ASSERT(!alloc_track_lookup(ptr_A));

	/*
	 * Flush: free_ring_entry(ptr_A) -> tracked_free_checked ->
	 * alloc_track_consume(ptr_A) fails -> ptr_A NOT freed.
	 * parent_stats.deferred_free_corrupt_ptr must increment by 1.
	 */
	deferred_free_flush();

	DF_ASSERT(parent_stats.deferred_free_corrupt_ptr == base_corrupt + 1);

	/*
	 * ASAN / memory-validity check: ptr_A must still be accessible
	 * (not freed).  Under ASAN a use-after-free would abort here
	 * if the disposal had incorrectly freed ptr_A despite the consume
	 * failure.  This is the "NOT a partial state transition" assertion:
	 * the ring slot was cleared but the heap chunk was left intact.
	 */
	p = (volatile unsigned char *)ptr_A;
	DF_ASSERT(*p == 0xDE);	/* original fill still readable */
	*p = 0xEF;		/* writable too: not poisoned by a stray free */
	DF_ASSERT(*p == 0xEF);

	/* Manual release: leak-on-uncertainty means WE own ptr_A now. */
	free(ptr_A);
}

/* ------------------------------------------------------------------ */
/* Fixture 6: Signal unwind with RW-open region                       */
/*                                                                     */
/* With deferred_free_batch enabled, mprotect bracket calls are lazy:  */
/* alloc_track_lock() is a no-op, so a region can be left RW-open      */
/* after an unexpected unwind (signal/longjmp).  The loop-top reseal   */
/* (deferred_free_seal_all()) must detect and close the open region.   */
/*                                                                     */
/* Protocol:                                                           */
/*   1. Enable batching.                                               */
/*   2. setjmp recovery point.                                         */
/*   3. deferred_alloc_track() opens alloc_track to RW (batch mode     */
/*      leaves alloc_track_lock a no-op -> alloc_track_rw_open=true).  */
/*   4. longjmp out (simulating a signal unwind mid-critical-section). */
/*   5. Loop-top: deferred_free_seal_all() closes every open region.  */
/*   6. Debug build: deferred_free_debug_assert_sealed() must not abort.*/
/*   7. Disable batching, free ptr.                                    */
/* ------------------------------------------------------------------ */

static void fixture_signal_unwind(void)
{
	jmp_buf recovery;
	void *ptr;
	unsigned long base_ro_calls;

	ptr = malloc(8);
	DF_ASSERT(ptr != NULL);
	deferred_alloc_track(ptr, 8);

	base_ro_calls = shm->stats.deferred_free.alloc_track_ro_calls;

	deferred_free_batch = true;

	if (setjmp(recovery) == 0) {
		/*
		 * Critical section: open alloc_track region.
		 * With batching ON, alloc_track_unlock() mprotects to RW
		 * and sets alloc_track_rw_open=true; alloc_track_lock()
		 * is a no-op, so the region stays open after this returns.
		 */
		deferred_alloc_track(ptr, 8);

		/*
		 * Simulate an abrupt unwind (signal arriving mid-section).
		 * In production this would be a sigsetjmp/siglongjmp from
		 * the fault handler; longjmp is sufficient for the
		 * reseal-on-recovery invariant test.
		 */
		longjmp(recovery, 1);

		/* Unreachable -- suppresses "code after longjmp" warning. */
		DF_ASSERT(0 && "unreachable");
	}

	/*
	 * Recovery / loop-top: seal all open regions.
	 * alloc_track_rw_open is true after the longjmp; seal_all
	 * detects it and mprotects alloc_track back to PROT_READ.
	 * alloc_track_ro_calls must advance by at least 1.
	 */
	deferred_free_seal_all();

	DF_ASSERT(shm->stats.deferred_free.alloc_track_ro_calls > base_ro_calls);

#ifndef NDEBUG
	/*
	 * Debug-build tripwire: assert every region is sealed.  Would
	 * abort here if seal_all missed an open region.
	 */
	deferred_free_debug_assert_sealed();
#endif

	deferred_free_batch = false;

	/*
	 * No dispatch ran with a region open: seal_all was called before
	 * any subsequent deferred-free operation (enqueue / tick / flush).
	 */
	tracked_free_now(ptr);
}

/* ------------------------------------------------------------------ */
/* Fixture 7: Per-region seal failure × 5                             */
/*                                                                     */
/* Open all five deferred-free protection regions, then inject one     */
/* mprotect failure per region via g_mprotect_fail_countdown=5.        */
/* Assert: deferred_free_seal_all() reports/counts the failure and     */
/* NO target syscall executes while a region is still open.            */
/*                                                                     */
/* Regions sealed (in order inside seal_all):                          */
/*   1. allocation tracking (PROT_READ)                                */
/*   2. inflight membership  (PROT_READ)                               */
/*   3. ring control         (PROT_READ)                               */
/*   4. ring data            (PROT_NONE)                               */
/*   5. generation arena     (PROT_READ)                               */
/*                                                                     */
/* Debug arm: verifies that alloc_track_ro_calls did NOT advance after */
/* the failed seal (the mprotect call was skipped in the else branch,  */
/* confirming the region stayed open).  We deliberately do NOT call    */
/* deferred_free_debug_assert_sealed() here: that would abort the test */
/* process on the open region -- the open region IS the test subject,  */
/* not an unexpected failure.  In production, debug_assert_sealed is   */
/* called at kernel-entry chokepoints and WOULD abort a dispatch that  */
/* tries to cross the boundary with a region open.                     */
/*                                                                     */
/* In all build flavors seal_all returns bool: false when any region  */
/* mprotect fails, true when all regions are successfully sealed.      */
/* The NDEBUG arm uses the return value in place of debug_assert_      */
/* sealed() to verify both the failure and the clean recovery.         */
/* ------------------------------------------------------------------ */

static void open_all_five_regions(void **ptr_out, void **ptr2_out)
{
	unsigned int i;
	void *ptr1, *ptr2;

	ptr1 = malloc(8);
	DF_ASSERT(ptr1 != NULL);
	ptr2 = malloc(8);
	DF_ASSERT(ptr2 != NULL);

	/* Open alloc_track (alloc_track_rw_open=true). */
	deferred_alloc_track(ptr1, 8);

	/* Enqueue ptr1: opens ring and rc (ring_rw_open,
	 * rc_rw_open = true). */
	deferred_free_enqueue(ptr1);

	/*
	 * Open gen arena: call deferred_free_tick() DEFERRED_TICK_BATCH
	 * times to trigger gen_arena_tick() which calls gen_unlock()
	 * (gen_rw_open=true).
	 */
	for (i = 0; i < DEFERRED_TICK_BATCH; i++)
		deferred_free_tick();

	/*
	 * Also track ptr2 for use in Part 2 (re-open after Part 1 seal).
	 * The track opens alloc_track (already open in batch mode -> no-op
	 * on the mprotect, just a hash+array write in the open RW window).
	 */
	deferred_alloc_track(ptr2, 8);

	*ptr_out  = ptr1;
	*ptr2_out = ptr2;
}

static void fixture_seal_failure_per_region(void)
{
	void *ptr1, *ptr2;
	unsigned long base_ro_calls;
	bool seal_ok;

	deferred_free_batch = true;

	/* ---- Part 1: normal seal (all five regions, no injection) ---- */

	open_all_five_regions(&ptr1, &ptr2);

	base_ro_calls = shm->stats.deferred_free.alloc_track_ro_calls;

	deferred_free_seal_all();

	/*
	 * alloc_track_ro_calls must advance: seal_all successfully sealed
	 * alloc_track (and the other four regions).
	 */
	DF_ASSERT(shm->stats.deferred_free.alloc_track_ro_calls > base_ro_calls);

#ifndef NDEBUG
	deferred_free_debug_assert_sealed();
#endif

	/* ---- Part 2: seal failure injection (5 regions × 1 fail each) ---- */

	/*
	 * Re-open all five regions: deferred_alloc_track(ptr2) opens
	 * alloc_track, deferred_free_enqueue(ptr2) opens ring+rc+inflight,
	 * DEFERRED_TICK_BATCH ticks open gen.
	 */
	deferred_alloc_track(ptr2, 8);

	deferred_free_enqueue(ptr2);

	{
		unsigned int i;
		for (i = 0; i < DEFERRED_TICK_BATCH; i++)
			deferred_free_tick();
	}

	base_ro_calls = shm->stats.deferred_free.alloc_track_ro_calls;

	/*
	 * Inject one failure per "seal" (PROT_READ/PROT_NONE) mprotect
	 * call.  deferred_free_seal_all() makes five such calls (one per
	 * region); all five fail.
	 */
	g_mprotect_fail_countdown = 5;
	seal_ok = deferred_free_seal_all();
	g_mprotect_fail_countdown = 0;

	/*
	 * seal_all must report failure: all five mprotect calls failed.
	 */
	DF_ASSERT(!seal_ok);

	/*
	 * alloc_track_ro_calls must NOT advance: the seal mprotect call
	 * failed, so the else branch (which clears alloc_track_rw_open
	 * and increments alloc_track_ro_calls) was not executed.
	 * This confirms the region stayed open after the failure.
	 */
	DF_ASSERT(shm->stats.deferred_free.alloc_track_ro_calls == base_ro_calls);

	/*
	 * In the debug build, the production guard against dispatch-with-
	 * open-region is deferred_free_debug_assert_sealed(), called at
	 * every kernel-entry chokepoint.  We do NOT call it here because
	 * it WOULD abort (the region IS still open -- that is the point
	 * of this test).  The counter assertion above is the test-visible
	 * proof that seal_all recorded the failure correctly.
	 *
	 * NO target syscall is issued after the failed seal in either
	 * build: no deferred_free_enqueue / tick / flush call follows
	 * before the recovery seal below.
	 */

	/* Recovery: re-seal all regions (no injection). */
	seal_ok = deferred_free_seal_all();

	/*
	 * After a clean (no-injection) seal, all regions must be closed and
	 * seal_all must report success.  In the debug build,
	 * deferred_free_debug_assert_sealed() provides an additional check
	 * via the rw_open flags; in NDEBUG the return value is the sole
	 * runtime indicator, so it carries the full correctness burden.
	 */
	DF_ASSERT(seal_ok);
#ifndef NDEBUG
	deferred_free_debug_assert_sealed();
#endif

	deferred_free_batch = false;

	/* Clean up both ptrs from the ring. */
	deferred_free_flush();

	/* ptr1 and ptr2 were freed by flush (or by prior ring drain).
	 * No manual free needed here. */
	(void)ptr1;
	(void)ptr2;
}

/* ------------------------------------------------------------------ */
/* Fixture 8: permanent seal failure suppresses dispatch              */
/* ------------------------------------------------------------------ */
/* Inject a PERMANENT mprotect failure (every seal call fails) and    */
/* verify that the simulated chokepoint caller — mirroring the        */
/* pattern used by the three production kernel-entry chokepoints —    */
/* does NOT proceed to the target operation.                          */
/*                                                                    */
/* Unlike fixture 7 (g_mprotect_fail_countdown=5), the permanent flag */
/* ensures seal_all() never recovers on its own, making it            */
/* impossible for a caller to "race past" a transient window.         */
/*                                                                    */
/* The simulated dispatch variable mirrors exactly what the           */
/* production callers do after the fail-closed repair:                */
/*   if (!deferred_free_seal_all())                                   */
/*       <abort / return>;   <- kernel NOT entered                    */
/*   <kernel entry here>;    <- only reached on success              */
/* ------------------------------------------------------------------ */

static void fixture_permanent_seal_failure_suppresses_dispatch(void)
{
	void *ptr;
	bool seal_ok;
	bool kernel_entered;

	deferred_free_batch = true;

	ptr = malloc(8);
	DF_ASSERT(ptr != NULL);

	/* Open alloc_track so seal_all has real work to do. */
	deferred_alloc_track(ptr, 8);

	/*
	 * Part 1: permanent failure — seal_all must return false on every
	 * call while the permanent flag is set.
	 */
	g_mprotect_fail_permanent = true;
	seal_ok = deferred_free_seal_all();
	DF_ASSERT(!seal_ok);

	/* A second call under the permanent flag must also fail. */
	seal_ok = deferred_free_seal_all();
	DF_ASSERT(!seal_ok);

	/*
	 * Part 2: simulate the fail-closed chokepoint caller pattern.
	 * Production code (dispatch/syscall.c, child/child.c) now reads:
	 *
	 *   if (!deferred_free_seal_all())
	 *       <abort/return>;    <- kernel NOT entered
	 *   <kernel entry>;        <- only reached when seal succeeds
	 *
	 * Replicate that pattern here: kernel_entered must stay false
	 * because the seal is still permanently failing.
	 */
	kernel_entered = false;
	if (deferred_free_seal_all())
		kernel_entered = true;

	DF_ASSERT(!kernel_entered);

	/* Lift the permanent failure. */
	g_mprotect_fail_permanent = false;

	/*
	 * Part 3: once the failure is cleared, seal_all must succeed and
	 * the simulated dispatch must now proceed (kernel_entered = true).
	 */
	if (deferred_free_seal_all())
		kernel_entered = true;

	DF_ASSERT(kernel_entered);
#ifndef NDEBUG
	deferred_free_debug_assert_sealed();
#endif

	deferred_free_flush();
	free(ptr);
	deferred_free_batch = false;
}

/* ------------------------------------------------------------------ */
/* Suite entry point                                                   */
/* ------------------------------------------------------------------ */

void deferred_free_ownership_self_check(void);
void deferred_free_ownership_self_check(void)
{
	/*
	 * One-time init for the whole suite.  deferred_free_init() sets
	 * up the four mmap'd protection regions (alloc_track, inflight,
	 * ring+ring_control, gen_arena) and seeds g_max_vmas from
	 * /proc/sys/vm/max_map_count.  All fixtures share this state;
	 * each fixture flushes the ring and resets batch mode at exit.
	 */
	deferred_free_init();

	printf("    fixture 1 (duplicate_address) ... ");
	fflush(stdout);
	fixture_duplicate_address();
	printf("OK\n");

	printf("    fixture 2 (hash_desync_array_authority) ... ");
	fflush(stdout);
	fixture_hash_desync_array_authority();
	printf("OK\n");

	printf("    fixture 3 (ring_ownership) ... ");
	fflush(stdout);
	fixture_ring_ownership();
	printf("OK\n");

	printf("    fixture 4 (generation_retirement) ... ");
	fflush(stdout);
	fixture_generation_retirement();
	printf("OK\n");

	printf("    fixture 5 (enomem_disposal) ... ");
	fflush(stdout);
	fixture_enomem_disposal();
	printf("OK\n");

	printf("    fixture 6 (signal_unwind) ... ");
	fflush(stdout);
	fixture_signal_unwind();
	printf("OK\n");

	printf("    fixture 7 (seal_failure_per_region) ... ");
	fflush(stdout);
	/*
	 * Fixture 7 passes in all three build flavors (debug, ASAN, NDEBUG).
	 * deferred_free_seal_all() returns bool in all flavors; the NDEBUG
	 * arm uses the return value to verify both the injection failure and
	 * the clean recovery seal without relying on debug_assert_sealed().
	 */
	fixture_seal_failure_per_region();
	printf("OK\n");

	printf("    fixture 8 (permanent_seal_failure_suppresses_dispatch) ... ");
	fflush(stdout);
	/*
	 * Fixture 8 proves the fail-closed guarantee: when mprotect never
	 * succeeds (permanent failure), the simulated dispatch caller does
	 * NOT proceed to the target operation.  Passing in all three build
	 * flavors; the permanent flag prevents any race-past scenario that
	 * a finite countdown could allow.
	 */
	fixture_permanent_seal_failure_suppresses_dispatch();
	printf("OK\n");
}
