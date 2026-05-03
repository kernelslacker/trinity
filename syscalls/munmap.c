/*
 * SYSCALL_DEFINE2(munmap, unsigned long, addr, size_t, len)
 */
#include <stdlib.h>
#include "arch.h"
#include "maps.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

#define WHOLE 1

static void sanitise_munmap(struct syscallrecord *rec)
{
	struct map *map = common_set_mmap_ptr_len();
	int action = 0;

	if (map == NULL) {
		/* No mapping to unmap. Stash NULL/0 so post_munmap sees
		 * action != WHOLE and skips the container_of deref. */
		rec->a3 = 0;
		rec->a4 = 0;
		return;
	}

	if (ONE_IN(20) == true) {
		/* delete the whole mapping. */
		action = WHOLE;
		/* For WHOLE, post_munmap will destroy the obj and call
		 * map_destructor → munmap(map->ptr, map->size).  Use the
		 * full extent here so the shared-region check below covers
		 * the same span the destructor will unmap. */
		rec->a1 = (unsigned long) map->ptr;
		rec->a2 = map->size;
	} else if (RAND_BOOL()) {
		/* unmap a range of the mapping. */
		unsigned long nr_pages;
		unsigned long offset, offsetpagenr;
		unsigned long len;

		nr_pages = map->size / page_size;
		if (nr_pages == 0)
			nr_pages = 1;
		offsetpagenr = rand() % nr_pages;
		offset = offsetpagenr * page_size;
		rec->a1 = (unsigned long) map->ptr + offset;

		len = (rand() % (nr_pages - offsetpagenr)) + 1;
		len *= page_size;
		rec->a2 = len;
	} else {
		/* just unmap 1 page of the mapping. */

		rec->a1 = (unsigned long) map->ptr;
		if (map->size > 0)
			rec->a1 += (rand() % map->size) & PAGE_MASK;
		rec->a2 = page_size;
	}

	/*
	 * Make sure we don't unmap the shm region — children fuzzing
	 * munmap can blow away trinity's shared state and crash everyone.
	 * For WHOLE, also drop the action so post_munmap doesn't run the
	 * destructor (which would munmap(map->ptr, map->size) regardless).
	 */
	if (range_overlaps_shared(rec->a1, rec->a2)) {
		rec->a1 = 0;
		rec->a2 = 0;
		action = 0;
	}

	/* Stash map pointer and action in unused arg slots for post callback. */
	rec->a3 = (unsigned long) map;
	rec->a4 = action;
}

static void post_munmap(struct syscallrecord *rec)
{
	struct map *map = (struct map *) rec->a3;
	int action = rec->a4;

	if (rec->retval != 0)
		return;

	if (action == WHOLE) {
		struct object *obj = container_of(map, struct object, map);
		destroy_object(obj, OBJ_LOCAL, OBJ_MMAP_ANON);
	} else if (map != NULL) {
		/*
		 * Sub-range munmap (19/20 invocations) punches a hole in the
		 * pool entry but leaves map->ptr / map->size unchanged.  A later
		 * get_map_with_prot() consumer (memory_pressure / iouring_flood
		 * / iouring_recipes / madvise_pattern_cycler) would then write
		 * into the punched-out range and SEGV_MAPERR on the first
		 * unmapped page.  Mirror the conservative invalidate from
		 * post_mprotect: blanket-disable the entry by clearing
		 * map->prot so get_map_with_prot(any) skips it.  Middle-of-
		 * mapping holes can't be expressed in a single (ptr, size)
		 * pair, so prot=0 is the only universally correct option.
		 * False-negatives (consumer skips a mapping that may still be
		 * partially writable) are acceptable; false-positives crash
		 * the child.
		 */
		map->prot = 0;
	}

	/*
	 * Oracle: 1-in-100 chance — verify the unmapped range is gone from
	 * /proc/self/maps.  Any overlapping entry means the kernel's VMA
	 * teardown silently failed despite returning success.
	 */
	if (rec->a1 != 0 && rec->a2 > 0 && ONE_IN(100)) {
		if (!proc_maps_check(rec->a1, rec->a2, 0, false)) {
			output(0, "mmap oracle: munmap(%lx, %lu) succeeded "
			       "but range still in /proc/self/maps\n",
			       rec->a1, rec->a2);
			__atomic_add_fetch(&shm->stats.mmap_oracle_anomalies, 1,
					   __ATOMIC_RELAXED);
		}
	}
}

struct syscallentry syscall_munmap = {
	.name = "munmap",
	.num_args = 2,
	.argtype = { [0] = ARG_MMAP, [1] = ARG_LEN },
	.argname = { [0] = "addr", [1] = "len" },
	.group = GROUP_VM,
	.sanitise = sanitise_munmap,
	.post = post_munmap,
};
