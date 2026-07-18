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
 *   PROT_RANDOM_BITMASK - mask = random 3-bit pick; exhaustive over the
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
 * mask the kernel uses internally).  PROT_RANDOM_BITMASK draws one
 * entry uniformly so every combination (including PROT_NONE) gets the
 * same per-iteration weight. */
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
		return (int)prot_lattice[rnd_modulo_u32(ARRAY_SIZE(prot_lattice))];
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

	start_page = rnd_modulo_u32(nr_pages);
	/*
	 * end_page is always <= nr_pages: rnd_modulo_u32(nr_pages - start_page)
	 * is in [0, nr_pages - start_page - 1], so end_page is in
	 * [start_page + 1, nr_pages].
	 */
	end_page = start_page + 1 + rnd_modulo_u32(nr_pages - start_page);

	*lenp = (end_page - start_page) * page_size;
	return start_page * page_size;
}

bool mprotect_split(struct childdata *child)
{
	struct object *obj;
	struct map *map;
	enum prot_mode mode;
	unsigned int iter;

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

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

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	mode = (enum prot_mode)rnd_modulo_u32(NR_PROT_MODES);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

	for (iter = 0; iter < PROT_MODE_ITERS; iter++) {
		unsigned long offset, len;
		int new_prot, prot_used;
		void *addr;

		/* Global VMA-pressure backoff: every iteration here can
		 * cause a __split_vma; back off cleanly before pushing
		 * the count any further. */
		if (vma_pressure_is_high())
			break;

		offset = pick_subrange(map, &len);
		addr = (char *)map->ptr + offset;

		new_prot = prot_for_mode(mode, iter);

		/*
		 * RAND_NEGATIVE_OR can substitute a curated edge value
		 * (0, INT_MAX, page_size, ...) into the prot arg ~1/50 of
		 * the time.  If the kernel accepts that substituted value
		 * we must do the bookkeeping based on what was actually
		 * applied, not the original new_prot — otherwise map->prot
		 * drifts out of sync with reality and consumers SEGV.
		 */
		prot_used = (int)RAND_NEGATIVE_OR(new_prot);

		if (mprotect(addr, len, prot_used) != 0)
			continue;

		/*
		 * Only update the tracked prot when the value the kernel
		 * applied is a clean PROT_R/W/X combination (including
		 * PROT_NONE).  Edge sentinels like INT_MAX, page_size,
		 * etc. carry bits outside the lattice that our consumers
		 * have no way to model, so leave map->prot unchanged in
		 * that case rather than poisoning the bookkeeping.
		 */
		if ((prot_used & ~(PROT_READ | PROT_WRITE | PROT_EXEC)) != 0)
			continue;

		/*
		 * Update the tracked prot.  For a whole-range change
		 * prot_used describes every page exactly.  For a sub-range,
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
			map->prot = prot_used;
		else
			map->prot &= prot_used;

		/*
		 * This childop runs raw mprotect(2)s that bypass the
		 * sanitise/post pair, so post_mprotect's known_rw clear
		 * never fires for them.  Drop the cache here on every
		 * accepted iteration -- a downgrade voids the cache and
		 * even an upgrade to RW is safer cleared so the next
		 * get_writable_address() call re-vouches the slot.
		 */
		map->known_rw = false;
	}

	return true;
}
