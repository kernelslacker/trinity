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
#include <sys/syscall.h>
#include <stdlib.h>
#include <string.h>

#include "arch.h"
#include "child.h"
#include "effector-map.h"
#include "maps.h"
#include "objects.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * Per-invocation prot-shift mode.  A single uniform-random prot pick
 * spreads the protection-bit transitions thinly across the prot
 * lattice; varying the mode concentrates a burst of related
 * transitions in one invocation, which reaches page-table paths a
 * uniform pick rarely lingers on long enough to race.
 *
 *   PROT_NONE_BURST    - hammer PROT_NONE across sub-ranges, exercises
 *                        the unmap-style page-table teardown path
 *                        repeatedly without releasing the VMA.
 *   PROT_RW_FLIP       - alternate PROT_READ <-> PROT_READ|PROT_WRITE,
 *                        isolates the writable-bit page-table flip
 *                        without touching the executable bit.
 *   PROT_X_TOGGLE      - alternate PROT_READ <-> PROT_READ|PROT_EXEC,
 *                        isolates the NX-bit flip and trips the W^X
 *                        edge when paired with the curated negative
 *                        flag escape.
 *   PROT_RANDOM_BITMASK - mask = rand() & 0x07; exhaustive over the
 *                        valid PROT_R/W/X combinations including
 *                        PROT_NONE, with no temporal correlation
 *                        between consecutive iterations.
 *
 * Mirrors the per-invocation variety pattern in 03d9df8c0f72
 * (vdso-mremap-race shape) and 4eb7e650afe5 (flock-thrash ordering).
 */
enum prot_mode {
	PROT_MODE_NONE_BURST = 0,
	PROT_MODE_RW_FLIP,
	PROT_MODE_X_TOGGLE,
	PROT_MODE_RANDOM_BITMASK,
	NR_PROT_MODES,
};

#define PROT_MODE_ITERS 4

/* Full PROT_R/W/X lattice (8 combinations, indexed by the same 3-bit
 * mask the kernel uses internally).  The PROT_RANDOM_BITMASK mode used
 * to draw rand() & 0x07 directly; routing through the effector-map lets
 * the per-bit significance scores for mprotect's prot arg bias the pick
 * toward combinations the kernel branches harder on. */
static const unsigned long prot_lattice[] = {
	0,
	PROT_READ,
	PROT_WRITE,
	PROT_READ | PROT_WRITE,
	PROT_EXEC,
	PROT_READ | PROT_EXEC,
	PROT_WRITE | PROT_EXEC,
	PROT_READ | PROT_WRITE | PROT_EXEC,
};

static int prot_for_mode(enum prot_mode mode, unsigned int iter)
{
	switch (mode) {
	case PROT_MODE_NONE_BURST:
		return PROT_NONE;
	case PROT_MODE_RW_FLIP:
		return (iter & 1) ? (PROT_READ | PROT_WRITE) : PROT_READ;
	case PROT_MODE_X_TOGGLE:
		return (iter & 1) ? (PROT_READ | PROT_EXEC) : PROT_READ;
	case PROT_MODE_RANDOM_BITMASK:
		return (int)prot_lattice[effector_pick_array_index(EFFECTOR_NR(__NR_mprotect), 2,
				prot_lattice, ARRAY_SIZE(prot_lattice))];
	default:
		return PROT_NONE;
	}
}

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
	enum prot_mode mode;
	unsigned int iter;

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

	mode = (enum prot_mode)((unsigned int)rand() % NR_PROT_MODES);

	for (iter = 0; iter < PROT_MODE_ITERS; iter++) {
		unsigned long offset, len;
		int new_prot;
		void *addr;

		offset = pick_subrange(map, &len);
		addr = (char *)map->ptr + offset;

		new_prot = prot_for_mode(mode, iter);

		if (mprotect(addr, len, (int)RAND_NEGATIVE_OR(new_prot)) != 0)
			continue;

		/*
		 * Update the tracked prot.  For a whole-range change
		 * new_prot describes every page exactly.  For a sub-range,
		 * intersect: the result is the set of permission bits
		 * GUARANTEED present in every page of the mapping.
		 *
		 * get_map_with_prot() filters pool draws by m->prot, so a
		 * stale m->prot that still claims PROT_WRITE for a mapping
		 * whose sub-range we just downgraded to PROT_READ leaks
		 * into consumers (memory_pressure's per-page dirty loop,
		 * iouring_flood, iouring_recipes, madvise_pattern_cycler),
		 * which then SEGV_ACCERR on the first downgraded page.
		 * Tracking the intersection is conservative — a sub-range
		 * upgrade (e.g. PROT_NONE map gaining PROT_RW pages) is
		 * not reflected, so the filter may skip a mapping that
		 * actually has writable pages somewhere.  That's an
		 * acceptable false-negative; a false-positive crashes the
		 * child.
		 */
		if (offset == 0 && len == map->size)
			map->prot = new_prot;
		else
			map->prot &= new_prot;
	}

	return true;
}
