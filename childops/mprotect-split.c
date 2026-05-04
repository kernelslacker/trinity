/*
 * mprotect_split - force VMA splits by mprotect()ing sub-ranges.
 *
 * Picks an existing anonymous mapping and calls mprotect() on a
 * page-aligned sub-range with a different protection.  This forces
 * the kernel to split the VMA, exercising vma_merge/vma_split and
 * the maple tree rebalancing paths.  Occasionally re-merges by
 * restoring the original protection.
 */

#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>

#include "arch.h"
#include "child.h"
#include "maps.h"
#include "objects.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static const int prots[] = {
	PROT_NONE,
	PROT_READ,
	PROT_WRITE,
	PROT_READ | PROT_WRITE,
	PROT_READ | PROT_EXEC,
	PROT_READ | PROT_WRITE | PROT_EXEC,
};

/*
 * Pick a random page-aligned sub-range within a mapping.
 * Returns the offset from map->ptr; *lenp receives the length.
 */
static unsigned long pick_subrange(struct map *map, unsigned long *lenp)
{
	unsigned long nr_pages, start_page, end_page;

	nr_pages = map->size / page_size;
	if (nr_pages < 2) {
		/* Single page — mprotect the whole thing. */
		*lenp = page_size;
		return 0;
	}

	start_page = rand() % nr_pages;
	/*
	 * end_page is always <= nr_pages: rand() % (nr_pages - start_page)
	 * is in [0, nr_pages - start_page - 1], so end_page is in
	 * [start_page + 1, nr_pages].
	 */
	end_page = start_page + 1 + (rand() % (nr_pages - start_page));

	*lenp = (end_page - start_page) * page_size;
	return start_page * page_size;
}

bool mprotect_split(struct childdata *child)
{
	struct object *obj;
	struct map *map;
	unsigned long offset, len;
	int new_prot;
	void *addr;

	(void)child;

	obj = get_random_object(OBJ_MMAP_ANON, OBJ_LOCAL);
	if (obj == NULL)
		return true;

	map = &obj->map;

	/* Safety: never mprotect shared memory regions. */
	if (range_overlaps_shared((unsigned long)map->ptr, map->size))
		return true;

	/* Need at least one page to work with. */
	if (map->size < page_size)
		return true;

	offset = pick_subrange(map, &len);
	addr = (char *)map->ptr + offset;

	/*
	 * 20% of the time, restore the original prot to encourage
	 * VMA re-merging.  Otherwise pick a different prot to force
	 * a split.
	 */
	if (ONE_IN(5)) {
		new_prot = map->prot;
	} else {
		new_prot = RAND_ARRAY(prots);
		/* Try to pick something different from current. */
		if (new_prot == map->prot)
			new_prot = RAND_ARRAY(prots);
	}

	if (mprotect(addr, len, (int)RAND_NEGATIVE_OR(new_prot)) != 0)
		return true;

	/*
	 * Update the tracked prot.  For a whole-range change new_prot
	 * describes every page exactly.  For a sub-range, intersect:
	 * the result is the set of permission bits GUARANTEED present
	 * in every page of the mapping.
	 *
	 * get_map_with_prot() filters pool draws by m->prot, so a stale
	 * m->prot that still claims PROT_WRITE for a mapping whose
	 * sub-range we just downgraded to PROT_READ leaks into consumers
	 * (memory_pressure's per-page dirty loop, iouring_flood,
	 * iouring_recipes, madvise_pattern_cycler), which then SEGV_ACCERR
	 * on the first downgraded page.  Tracking the intersection is
	 * conservative — a sub-range upgrade (e.g. PROT_NONE map gaining
	 * PROT_RW pages) is not reflected, so the filter may skip a
	 * mapping that actually has writable pages somewhere.  That's an
	 * acceptable false-negative; a false-positive crashes the child.
	 */
	if (offset == 0 && len == map->size)
		map->prot = new_prot;
	else
		map->prot &= new_prot;

	return true;
}
