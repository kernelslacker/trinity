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
	if (memlock_used >= memlock_budget)
		return 0;
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
