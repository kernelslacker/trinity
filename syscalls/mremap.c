/*
 * asmlinkage unsigned long sys_mremap(unsigned long addr,
 *   unsigned long old_len, unsigned long new_len,
 *   unsigned long flags, unsigned long new_addr)
 */

#include <stdlib.h>
#include <sys/mman.h>
#include "arch.h"
#include "maps.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "compat.h"
#include "utils.h"

#ifndef MREMAP_DONTUNMAP
#define MREMAP_DONTUNMAP	4
#endif

static const unsigned long alignments[] = {
	MB(1), MB(2), MB(4), MB(4),
	MB(10), MB(100),
	GB(1), GB(2), GB(4),
};

static void sanitise_mremap(struct syscallrecord *rec)
{
	struct map *map;
	unsigned long newaddr = 0;

	map = common_set_mmap_ptr_len();
	if (map == NULL) {
		/* No mapping available; stash NULL for post_mremap to skip. */
		rec->a6 = 0;
		return;
	}

	if (range_overlaps_shared(rec->a1, rec->a2)) {
		rec->a1 = 0;
		rec->a2 = 0;
	}

	rec->a3 = map->size;

	/* Sometimes request a different size */
	switch (rand() % 4) {
	case 0: break;	/* same size */
	case 1: rec->a3 /= 2; break;	/* shrink */
	case 2: rec->a3 *= 2; break;	/* grow */
	case 3: rec->a3 = page_size * (1 + rand() % 16); break;	/* random pages */
	}

	if (rec->a4 & MREMAP_FIXED) {
		unsigned long align = RAND_ARRAY(alignments);
		unsigned int shift = (WORD_BIT / 2) - 1;

		newaddr = RAND_BYTE();
		newaddr <<= shift;
		newaddr |= align;
		newaddr &= ~(align - 1);

		/* MREMAP_FIXED unmaps any prior mapping at [newaddr,
		 * newaddr + rec->a3) before placing the relocated
		 * mapping there.  Reject if that range overlaps a
		 * trinity-owned shared region — otherwise we silently
		 * unmap our own bookkeeping. */
		if (range_overlaps_shared(newaddr, rec->a3)) {
			rec->a4 &= ~MREMAP_FIXED;
			newaddr = 0;
		}
	}

	/* MREMAP_DONTUNMAP requires MREMAP_MAYMOVE; when combined with
	 * MREMAP_FIXED it remaps to new_addr without unmapping the source. */
	if (rec->a4 & MREMAP_DONTUNMAP)
		rec->a4 |= MREMAP_MAYMOVE;

	rec->a5 = newaddr;

	/* Stash map pointer in unused arg slot for post callback. */
	rec->a6 = (unsigned long) map;
}

/*
 * If we successfully remapped a range, we need to update our record of it
 * so we don't re-use the old address.
 */
static void post_mremap(struct syscallrecord *rec)
{
	struct map *map = (struct map *) rec->a6;
	void *ptr = (void *) rec->retval;

	if (ptr == MAP_FAILED || map == NULL)
		return;

	/* Cluster-1/2/3 guard: reject pid-scribbled rec->a6. */
	if (looks_like_corrupted_ptr(map)) {
		outputerr("post_mremap: rejected suspicious map=%p (pid-scribbled?)\n",
			  (void *) map);
		shm->stats.post_handler_corrupt_ptr++;
		return;
	}

	map->ptr = ptr;
	map->size = rec->a3;
}

static unsigned long mremap_flags[] = {
	MREMAP_MAYMOVE, MREMAP_FIXED, MREMAP_DONTUNMAP,
};

struct syscallentry syscall_mremap = {
	.name = "mremap",
	.num_args = 5,
	.sanitise = sanitise_mremap,
	.argtype = { [0] = ARG_MMAP, [1] = ARG_LEN, [2] = ARG_LEN, [3] = ARG_LIST },
	.argname = { [0] = "addr", [1] = "old_len", [2] = "new_len", [3] = "flags", [4] = "new_addr" },
	.arg_params[3].list = ARGLIST(mremap_flags),
	.group = GROUP_VM,
	.post = post_mremap,
};
