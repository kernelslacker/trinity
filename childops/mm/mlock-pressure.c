/*
 * mlock_pressure - lock and unlock mappings to stress the unevictable LRU.
 *
 * Rapidly cycles through mlock/mlock2/munlock on random mappings and
 * sub-ranges.  Occasionally uses mlockall/munlockall for whole-process
 * pressure.  This exercises the unevictable page migration paths,
 * page reclaim under mlock pressure, and the MLOCK_ONFAULT lazy-fault
 * code path.
 */

#include <sys/mman.h>

#include "arch.h"
#include "child.h"
#include "maps.h"
#include "objects.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "vma-pressure.h"

#include "kernel/mman.h"
/*
 * Pick a page-aligned sub-range of a mapping for partial lock/unlock.
 */
static void pick_range(struct map *map, void **addrp, unsigned long *lenp)
{
	unsigned long nr_pages, start_page, count;

	nr_pages = map->size / page_size;
	if (nr_pages == 0) {
		/* Defence-in-depth: callers gate on map->size >= page_size,
		 * but a zero-page mapping leaking in would trip
		 * rnd_modulo_u32(0) below.  Hand back a zero-length range;
		 * mlock()/munlock() handle len==0 cleanly (no-op or EINVAL,
		 * not an abort). */
		*addrp = map->ptr;
		*lenp = 0;
		return;
	}
	if (nr_pages < 2) {
		*addrp = map->ptr;
		*lenp = map->size;
		return;
	}

	start_page = rnd_modulo_u32(nr_pages);
	count = 1 + rnd_modulo_u32(nr_pages - start_page);

	*addrp = (char *)map->ptr + start_page * page_size;
	*lenp = count * page_size;
}

static bool do_mlock(struct map *map)
{
	void *addr;
	unsigned long len;

	if (RAND_BOOL()) {
		/* Whole mapping. */
		addr = map->ptr;
		len = map->size;
	} else {
		pick_range(map, &addr, &len);
	}

	if (RAND_BOOL())
		mlock(addr, len);
	else
		mlock2(addr, len, (int)RAND_NEGATIVE_OR(RAND_BOOL() ? MLOCK_ONFAULT : 0));

	return true;
}

static bool do_munlock(struct map *map)
{
	void *addr;
	unsigned long len;

	if (RAND_BOOL()) {
		addr = map->ptr;
		len = map->size;
	} else {
		pick_range(map, &addr, &len);
	}

	munlock(addr, len);
	return true;
}

bool mlock_pressure(struct childdata *child)
{
	struct object *obj;
	struct map *map;

	/* Global VMA-pressure backoff.  mlock on a page-aligned sub-range
	 * splits the underlying VMA at the lock boundary; the mlockall
	 * branch below can also split via MCL_FUTURE intercepts on the
	 * probe mappings.  Skip the whole dispatch when latched. */
	if (vma_pressure_is_high())
		return true;

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	/*
	 * 5% of the time, do a whole-process mlockall/munlockall cycle.
	 * This is expensive but exercises a very different kernel path.
	 */
	if (ONE_IN(20)) {
		int flags = MCL_CURRENT;

#ifndef __SANITIZE_ADDRESS__
		/*
		 * MCL_FUTURE pins every later mmap with VM_LOCKED; under ASAN the
		 * allocator's shadow-extension mmap then -EAGAINs once RLIMIT_MEMLOCK
		 * is hit and libasan fatally aborts the child ("failed to allocate ...
		 * error code: 11").  The probe loop below holds MCL_FUTURE across
		 * several mmap/touch/munmap calls -- wide enough for ASAN to fall in.
		 * The raw mlockall syscall path source-gates MCL_FUTURE out of
		 * its arg list under ASAN (syscalls/mlockall.c); mirror that here.
		 */
		if (RAND_BOOL())
			flags |= MCL_FUTURE;
#endif
		if (RAND_BOOL())
			flags |= MCL_ONFAULT;

		if (valid_op)
			__atomic_add_fetch(&shm->stats.childop.data_path[op],
					   1, __ATOMIC_RELAXED);

		if (mlockall(flags) == 0 && (flags & MCL_FUTURE)) {
			/*
			 * MCL_FUTURE only matters if we make new mappings
			 * while mlockall is active. Allocate a handful of
			 * short-lived mappings so the MCL_FUTURE intercept
			 * path actually fires before we unlock.
			 */
			unsigned int i, n = 1 + rnd_modulo_u32(4);
			void *probes[4] = {NULL, NULL, NULL, NULL};
			size_t lens[4] = {0, 0, 0, 0};

			for (i = 0; i < n; i++) {
				size_t len = page_size * (1 + rnd_modulo_u32(8));
				void *p = mmap(NULL, len,
					       PROT_READ | PROT_WRITE,
					       MAP_PRIVATE | MAP_ANONYMOUS,
					       -1, 0);

				if (p == MAP_FAILED)
					continue;
				/* Touch a byte so non-ONFAULT locking actually
				 * binds a physical page. */
				*(volatile char *)p = 0;
				probes[i] = p;
				lens[i] = len;
			}
			for (i = 0; i < n; i++) {
				if (probes[i] != NULL)
					munmap(probes[i], lens[i]);
			}
		}

		/* Always unlock to avoid running out of lockable memory. */
		munlockall();
		return true;
	}

	obj = get_random_object(OBJ_MMAP_ANON, OBJ_LOCAL);
	if (obj == NULL)
		return true;

	map = &obj->map;

	if (map->size < page_size)
		return true;

	/* Safety: never mlock shared memory. */
	if (range_overlaps_shared((unsigned long)map->ptr, map->size))
		return true;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

	/*
	 * Bias toward lock (60%) to build pressure, but always
	 * unlock some to churn the unevictable list.
	 */
	if (rnd_modulo_u32(10) < 6)
		do_mlock(map);
	else
		do_munlock(map);

	return true;
}
