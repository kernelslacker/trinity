/*
 * Generation arena: the bounded holding pen for pointers evicted from the
 * full ring.  An evicted chunk cannot be free()d on the spot, so it is filed
 * into a generation that seals when full or aged and retires, through the
 * alloc_track consume gate, once it has matured.
 */

#include <stdbool.h>

#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#include "deferred-free-internal.h"

/*
 * Generation arena: bounded holding pen for pointers evicted out of the
 * full ring by ring_evict_oldest_safe().  Eviction cannot free() on the
 * spot: the evicted entry may be a pre-dispatch buffer the syscall being
 * built still reads, or a chunk a stale caller ref still names (the
 * address-reuse bad-free class, see Documentation/deferred-free.md
 * "Leak-on-eviction defense").
 *
 * Every evicted chunk is filed into an ACTIVE generation, an ACTIVE
 * generation SEALs when it fills or ages past GEN_ARENA_SEAL_TICKS, and a
 * SEALED generation retires (drains its entire chunk list via
 * df_tracked_free_checked, which alloc_track-consume-gates each free) once
 * it has aged GEN_ARENA_RETIRE_TICKS batched-ticks beyond seal time.
 *
 * The retire horizon is bounded on both sides.  It matches the longest
 * ring TTL, so an evicted chunk is held about as long as one that expires
 * in the ring.  And the retire has to land before ALLOC_TRACK_SIZE more
 * tracked allocations rotate the chunk's alloc_track slot out: the slot
 * was written when the buffer was allocated, before its time in the
 * ring, and every evicted pointer had its own tracking call, so a horizon
 * of thousands of syscalls makes the retire consume-miss and leak the
 * chunk instead of freeing it.
 *
 * Under arena pressure (every slot ACTIVE or SEALED-not-yet-retirable),
 * eviction falls back to the historical leak-on-eviction behaviour and
 * bumps the dedicated _pressure_leak counter in addition to
 * ring_evict_leaked, so an operator can tell "arena defense engaged" from
 * "arena undersized for this workload."  An evicted chunk is held RETIRE
 * to SEAL + RETIRE ticks; the arena sustains up to (SLOTS - 1) * ENTRIES
 * / RETIRE_TICKS evictions per batched tick (~2.2 per syscall), and never
 * runs dry at low rates, where generations seal on age rather than fill,
 * while SLOTS - 1 seal windows cover RETIRE_TICKS (asserted below).
 *
 * Storage is one small mmap'd armor region shared across all generations;
 * df_gen_unlock()/df_gen_lock() open the RW window for the duration of a
 * mutation, matching the discipline of the other three protection
 * regions.  Steady state PROT_READ so a fuzzed value-result stomp on a
 * generation's ptrs[] page fails the write, preserving the
 * "corruption-shaped stomp cannot silently reach free()" invariant.
 */
#define GEN_ARENA_SEAL_TICKS		16	/* ~256 syscalls: force-seal an under-filled active */
#define GEN_ARENA_RETIRE_TICKS		DEFERRED_TTL_MAX	/* post-seal hold: the longest ring TTL */

_Static_assert((GEN_ARENA_SLOTS - 1) * GEN_ARENA_SEAL_TICKS >=
	       GEN_ARENA_RETIRE_TICKS,
	       "a trickle of evictions would seal every generation before "
	       "the oldest retires and fall back to the pressure leak");

/*
 * Oldest an evicted chunk's alloc_track slot can be at retire: a full
 * ring TTL before eviction, SEAL + RETIRE in the arena, a tick of slack.
 * Keeping that under half the alloc_track window lets retire still find
 * the slot at up to two tracked allocations per iteration.
 */
_Static_assert((DEFERRED_TTL_MAX + 1 + GEN_ARENA_SEAL_TICKS +
		GEN_ARENA_RETIRE_TICKS) * DEFERRED_TICK_BATCH * 2 <=
	       ALLOC_TRACK_SIZE,
	       "an evicted chunk can outlive its alloc_track slot, so its "
	       "retire would consume-miss and leak it");

/*
 * Retirement gate for a SEALED generation.  Runs the same stateless
 * prefilters free_ring_entry uses (shape / heap-bounds / shared-region)
 * against every entry before handing it to df_tracked_free_checked with the
 * arena-retire site tag; a stomp that scribbled the arena's ptrs[] slot
 * during the hold is caught here rather than fed to free().  Caller must
 * hold df_gen_unlock() -- we mutate arena->count and arena->state and clear
 * arena->ptrs[].  Ordered "clear the slot BEFORE free()" for the same
 * signal/longjmp reason free_ring_entry has.
 */
static void gen_arena_retire_one(struct gen_arena *arena)
{
	unsigned int i;

	for (i = 0; i < arena->count; i++) {
		void *ptr = arena->ptrs[i];
		const char *reason = NULL;

		arena->ptrs[i] = NULL;
		if (ptr == NULL)
			continue;

		if (is_corrupt_ptr_shape(ptr))
			reason = "shape";
		else if (!is_in_glibc_heap(ptr))
			reason = "non-heap";
		else if (range_overlaps_shared((unsigned long)ptr, 1))
			reason = "shared-region";

		if (reason != NULL) {
			outputerr("deferred_free: gen_arena retire rejected "
				  "ptr=%p (%s)\n", ptr, reason);
			__atomic_add_fetch(&shm->stats.deferred_free.gen_arena_retire_reject,
					   1, __ATOMIC_RELAXED);
			continue;
		}

		if (df_tracked_free_checked(ptr, TRACKED_FREE_SITE_GEN_RETIRE))
			__atomic_add_fetch(&shm->stats.deferred_free.gen_arena_retired_ok,
					   1, __ATOMIC_RELAXED);
	}

	arena->count = 0;
	arena->armed_tick = 0;
	arena->sealed_tick = 0;
	arena->state = GEN_EMPTY;
}

/*
 * Retire every SEALED generation whose sealed_tick has aged past
 * GEN_ARENA_RETIRE_TICKS.  Also force-seals the ACTIVE generation if it
 * has aged past GEN_ARENA_SEAL_TICKS since arming, so a slow-eviction
 * workload does not indefinitely delay the retirement clock.  Called
 * from deferred_free_tick() under the same batched cadence as the ring
 * drain, so the arena's bookkeeping runs at 1/DEFERRED_TICK_BATCH the
 * syscall rate and does not add per-syscall syscalls.  Caller must NOT
 * hold df_gen_unlock() -- we open it ourselves.
 */
void df_gen_arena_tick(void)
{
	unsigned int i;
	unsigned long now;
	bool did_work = false;

	if (df_gen == NULL)
		return;

	if (df_gen_unlock() != 0)
		return;

	df_gen->tick_counter++;
	now = df_gen->tick_counter;

	for (i = 0; i < GEN_ARENA_SLOTS; i++) {
		struct gen_arena *a = &df_gen->arenas[i];

		if (a->state == GEN_ACTIVE && a->count > 0 &&
		    (now - a->armed_tick) >= GEN_ARENA_SEAL_TICKS) {
			a->state = GEN_SEALED;
			a->sealed_tick = now;
			did_work = true;
		}
	}

	for (i = 0; i < GEN_ARENA_SLOTS; i++) {
		struct gen_arena *a = &df_gen->arenas[i];

		if (a->state == GEN_SEALED &&
		    (now - a->sealed_tick) >= GEN_ARENA_RETIRE_TICKS) {
			gen_arena_retire_one(a);
			did_work = true;
		}
	}

	(void)did_work;
	df_gen_lock();
}

/*
 * File @ptr into the current active generation.  Returns true on admit,
 * false under arena pressure (every slot ACTIVE-and-full or SEALED-not-
 * yet-retirable): the eviction caller falls back to the historical
 * leak-on-eviction path so its "no longer your problem" contract still
 * holds without arming a bad-free.  A push that fills the active
 * generation seals it in place and rotates active_idx to a free slot;
 * if no free slot exists at that point we intentionally do NOT retire
 * a not-yet-mature SEALED generation (that would defeat the retirement
 * bake) -- the next push returns false and the caller leaks.  Caller
 * must NOT hold df_gen_unlock() -- we open it ourselves.
 */
bool df_gen_arena_push(void *ptr)
{
	struct gen_arena *a;
	unsigned int i;

	if (df_gen == NULL || ptr == NULL)
		return false;

	if (df_gen_unlock() != 0)
		return false;

	a = &df_gen->arenas[df_gen->active_idx];

	if (a->state == GEN_EMPTY) {
		a->state = GEN_ACTIVE;
		a->armed_tick = df_gen->tick_counter;
	}

	if (a->state != GEN_ACTIVE || a->count >= GEN_ARENA_ENTRIES) {
		if (a->state == GEN_ACTIVE) {
			a->state = GEN_SEALED;
			a->sealed_tick = df_gen->tick_counter;
		}
		for (i = 0; i < GEN_ARENA_SLOTS; i++) {
			struct gen_arena *cand = &df_gen->arenas[i];

			if (cand->state == GEN_EMPTY) {
				df_gen->active_idx = i;
				cand->state = GEN_ACTIVE;
				cand->armed_tick = df_gen->tick_counter;
				a = cand;
				break;
			}
		}
		if (a->state != GEN_ACTIVE || a->count >= GEN_ARENA_ENTRIES) {
			/* Arena pressure: every generation is either
			 * ACTIVE-full or SEALED-not-yet-retirable.  The
			 * caller leaks in this window. */
			df_gen_lock();
			return false;
		}
	}

	a->ptrs[a->count++] = ptr;
	__atomic_add_fetch(&shm->stats.deferred_free.gen_arena_admitted,
			   1, __ATOMIC_RELAXED);
	df_gen_lock();
	return true;
}

/*
 * Drain every generation immediately, regardless of maturity.  Called on
 * child exit from deferred_free_flush(): the child is going away, so
 * holding chunks for the retirement bake is pointless -- the kernel
 * reclaims the whole address space right after anyway.  Retire discipline
 * still applies (prefilter + df_alloc_track_consume gate); a scribbled arena
 * slot does not silently reach free().  Caller must NOT hold df_gen_unlock()
 * -- we open it ourselves.
 */
void df_gen_arena_flush(void)
{
	unsigned int i;

	if (df_gen == NULL)
		return;

	if (df_gen_unlock() != 0)
		return;

	for (i = 0; i < GEN_ARENA_SLOTS; i++) {
		struct gen_arena *a = &df_gen->arenas[i];

		if (a->state != GEN_EMPTY)
			gen_arena_retire_one(a);
	}
	df_gen->active_idx = 0;
	df_gen_lock();
}

/*
 * Is @ptr held by a generation?  An evicted pointer keeps its alloc_track
 * entry until its generation retires, so every check that treats a
 * ring-resident pointer as deferred-owned (enqueue dedup,
 * tracked_free_now, alloc_track_refresh) must treat an arena-resident
 * one the same way: a re-enqueue or tracked_free_now would otherwise give
 * the pointer a second owner whose free lands on whatever reuses the
 * address.  Reads the PROT_READ steady state directly, no bracket; the
 * clamp keeps a scribbled count from walking past ptrs[].  Each of those
 * calls scans every occupied entry, several hundred while the ring is
 * saturated.
 */
bool df_gen_arena_contains(void *ptr)
{
	unsigned int i;
	unsigned int j;

	if (df_gen == NULL)
		return false;

	for (i = 0; i < GEN_ARENA_SLOTS; i++) {
		const struct gen_arena *a = &df_gen->arenas[i];

		for (j = 0; j < a->count && j < GEN_ARENA_ENTRIES; j++) {
			if (a->ptrs[j] == ptr)
				return true;
		}
	}
	return false;
}
