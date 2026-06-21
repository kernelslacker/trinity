/*
 * Per-child memlock accounting and recently-locked ring shared by the
 * mlock and munlock sanitisers.
 *
 * The mlock/munlock sanitisers used to call common_set_mmap_ptr_len()
 * and stop, leaving rec->a1 pinned to map->ptr and rec->a2 at
 * rnd_modulo_u32(map->size) & PAGE_MASK.  Single-page, full-map, and
 * over-end probes never got drawn; munlock had no way to bias its
 * (start, len) toward an actually-locked window so the unlock path
 * almost always picked an unlocked range and returned EINVAL; and on
 * multi-MB INITIAL_ANON mappings the random pick frequently exceeded
 * RLIMIT_MEMLOCK, surrendering the rest of the fuzz wave to EAGAIN.
 *
 * State here partitions the (start, len) input space into named
 * buckets and tracks how much of the memlock cap has been consumed so
 * the in-bounds buckets stay under the limit.  static __thread keeps
 * the running total per-child even when a childop spawns a helper
 * thread inside the child (plain static would be per-process and the
 * worker thread would race the spawning child's accounting).
 */
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/resource.h>
#include "arch.h"
#include "maps.h"
#include "mlock-state.h"
#include "rnd.h"

static __thread bool memlock_initialised;
static __thread unsigned long memlock_budget;
static __thread unsigned long memlock_used;

#define MLOCK_RING_SIZE	8
struct mlock_ring_entry {
	unsigned long start;
	unsigned long len;
};
static __thread struct mlock_ring_entry mlock_ring[MLOCK_RING_SIZE];
static __thread unsigned int mlock_ring_head;

/*
 * Lazy-load the memlock cap once per child.  Calling getrlimit on
 * every mlock would show up in syscall-generation hot-path profiles
 * the same way libc rand() did before the rnd.h split displaced it.
 * RLIM_INFINITY surfaces as ULONG_MAX so the clamp short-circuits.
 */
static void ensure_memlock_cache(void)
{
	struct rlimit r;

	if (memlock_initialised)
		return;
	memlock_initialised = true;

	if (getrlimit(RLIMIT_MEMLOCK, &r) != 0 ||
	    r.rlim_cur == RLIM_INFINITY) {
		memlock_budget = ULONG_MAX;
		return;
	}
	memlock_budget = (unsigned long) r.rlim_cur;
}

unsigned long mlock_state_pick_length(unsigned long map_size, bool *over_end)
{
	*over_end = false;
	switch (rnd_modulo_u32(4)) {
	case 0:
		return page_size;
	case 1:
		return (map_size / 2) & PAGE_MASK;
	case 2:
		return map_size & PAGE_MASK;
	default:
		*over_end = true;
		if (map_size > ULONG_MAX - page_size)
			return ULONG_MAX & PAGE_MASK;
		return (map_size + page_size) & PAGE_MASK;
	}
}

unsigned long mlock_state_pick_start(struct map *map)
{
	unsigned long pages;

	if (rnd_modulo_u32(4) != 0)
		return (unsigned long) map->ptr;
	pages = map->size / page_size;
	if (pages < 2)
		return (unsigned long) map->ptr;
	return (unsigned long) map->ptr +
	       (unsigned long) page_size *
	       rnd_modulo_u32((uint32_t) (pages - 1));
}

unsigned long mlock_state_clamp_len(unsigned long requested)
{
	unsigned long avail;

	ensure_memlock_cache();
	if (memlock_budget == ULONG_MAX)
		return requested;
	/*
	 * Budget already burned through.  Returning 0 here turned the
	 * subsequent mlock(addr, 0) into a no-op success the kernel
	 * short-circuits before reaching mlock_check_rlimit/account_locked_vm
	 * -- "high calls, low edges" cold-syscall shape.  Hand back
	 * page_size so the call lands inside the rlimit accounting path
	 * (EAGAIN at the cap) and the over-cap reject edges are retained
	 * instead of every subsequent draw collapsing to len=0.
	 */
	if (memlock_used >= memlock_budget)
		return page_size;
	avail = memlock_budget - memlock_used;
	return requested > avail ? avail : requested;
}

void mlock_state_record_locked(unsigned long start, unsigned long len)
{
	struct mlock_ring_entry *slot;

	if (len == 0)
		return;
	memlock_used += len;
	slot = &mlock_ring[mlock_ring_head];
	slot->start = start;
	slot->len = len;
	mlock_ring_head = (mlock_ring_head + 1) % MLOCK_RING_SIZE;
}

/*
 * Reader side of the 8-entry recently-locked ring.  Iterating the
 * whole ring to find a non-empty slot lets the ring stay sparsely
 * populated early in a child's life without biasing the subset draw
 * toward whichever slot the head happens to point at.  Returns false
 * (and leaves *startp / *lenp untouched) when no slot has ever been
 * written -- the caller then falls back to the random bucket path so
 * the unlocked-region EINVAL coverage is preserved.
 */
bool mlock_state_pick_recent(unsigned long *startp, unsigned long *lenp)
{
	struct mlock_ring_entry *slot;
	unsigned int i, populated = 0;
	unsigned int pick;

	for (i = 0; i < MLOCK_RING_SIZE; i++)
		if (mlock_ring[i].len != 0)
			populated++;
	if (populated == 0)
		return false;

	pick = rnd_modulo_u32(populated);
	for (i = 0; i < MLOCK_RING_SIZE; i++) {
		slot = &mlock_ring[i];
		if (slot->len == 0)
			continue;
		if (pick == 0) {
			*startp = slot->start;
			*lenp = slot->len;
			return true;
		}
		pick--;
	}
	return false;
}

/*
 * Counterpart to record_locked.  Subtract len from the running total,
 * saturating at zero -- the kernel does not refund the cap when an
 * unlock targets a range that mlock never actually locked, and the
 * ring may have aged out the matching record by the time munlock
 * draws it, so a naive subtract could underflow into a giant unsigned
 * value and starve the rest of the wave of any mlock budget.
 */
void mlock_state_record_unlocked(unsigned long len)
{
	if (len == 0)
		return;
	if (len >= memlock_used)
		memlock_used = 0;
	else
		memlock_used -= len;
}

/*
 * Bulk reset.  A successful munlockall cleared every VM_LOCKED vma
 * for this mm, so the per-child cumulative-locked total and the
 * recently-locked ring no longer reflect any real kernel state.
 * Leaving them populated would (a) keep clamp_len pinned at page_size
 * via the over-budget arm even though the budget is fully available
 * again, and (b) feed pick_recent stale (start, len) pairs that the
 * munlock sanitiser would then draw against ranges the kernel
 * already cleared.  Header / ensure_memlock_cache invariants are
 * untouched -- the cap value itself is process-stable.
 */
void mlock_state_reset(void)
{
	memlock_used = 0;
	memset(mlock_ring, 0, sizeof(mlock_ring));
	mlock_ring_head = 0;
}
