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
#include <stdlib.h>

#include "arch.h"
#include "child.h"
#include "maps.h"
#include "objects.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#ifndef MLOCK_ONFAULT
#define MLOCK_ONFAULT 1
#endif

/*
 * Pick a page-aligned sub-range of a mapping for partial lock/unlock.
 */
static void pick_range(struct map *map, void **addrp, unsigned long *lenp)
{
	unsigned long nr_pages, start_page, count;

	nr_pages = map->size / page_size;
	if (nr_pages < 2) {
		*addrp = map->ptr;
		*lenp = map->size;
		return;
	}

	start_page = rand() % nr_pages;
	count = 1 + (rand() % (nr_pages - start_page));

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
		mlock2(addr, len, RAND_BOOL() ? MLOCK_ONFAULT : 0);

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

	(void)child;

	/*
	 * 5% of the time, do a whole-process mlockall/munlockall cycle.
	 * This is expensive but exercises a very different kernel path.
	 */
	if (ONE_IN(20)) {
		int flags = MCL_CURRENT;

		if (RAND_BOOL())
			flags |= MCL_FUTURE;
		if (RAND_BOOL())
			flags |= MCL_ONFAULT;

		mlockall(flags);

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

	/*
	 * Bias toward lock (60%) to build pressure, but always
	 * unlock some to churn the unevictable list.
	 */
	if (rand() % 10 < 6)
		do_mlock(map);
	else
		do_munlock(map);

	return true;
}
