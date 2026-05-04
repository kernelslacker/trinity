/*
 * asmlinkage unsigned long sys_mremap(unsigned long addr,
 *   unsigned long old_len, unsigned long new_len,
 *   unsigned long flags, unsigned long new_addr)
 */

#include <stdlib.h>
#include <sys/mman.h>
#include "arch.h"
#include "deferred-free.h"
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

/*
 * Snapshot of the two mremap inputs read by the post handler, captured
 * at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot smear the new_len value that gets cached into
 * map->size, or retarget the trinity-tracked map pointer the post
 * handler updates.
 *
 * Unlike the readlink/statfs family, post_mremap does not memcpy out of
 * a kernel-written user buffer; it writes the kernel's returned address
 * and the requested new length back into trinity's map bookkeeping.
 * The snap exists to defend the bookkeeping write itself: a stomped
 * new_len would cache the wrong size into map->size and let later
 * memory_pressure / iouring_* / madvise_pattern_cycler consumers walk
 * off the actual mapping; a stomped map slot points the same write at
 * an unrelated heap allocation that the existing corruption guard
 * cannot tell apart from a real-but-wrong map pointer.
 */
struct mremap_post_state {
	unsigned long new_len;
	unsigned long map;
};

static void sanitise_mremap(struct syscallrecord *rec)
{
	struct mremap_post_state *snap;
	struct map *map;
	unsigned long newaddr = 0;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

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

	/*
	 * Snapshot the two inputs the post handler reads.  Without this
	 * the post handler reads rec->a3 and rec->a6 at post-time, when
	 * a sibling syscall may have scribbled the slots.  rec->a6 is
	 * already corruption-guarded against pid scribbles, but
	 * looks_like_corrupted_ptr() cannot tell a real-but-wrong heap
	 * address from a real map pointer, so a foreign-heap stomp slips
	 * the guard and the bookkeeping write lands in someone else's
	 * allocation.  rec->a3 is unguarded entirely; a stomped value
	 * caches the wrong size into map->size and a later consumer that
	 * trusts m->size walks off the actual mapping.  post_state is
	 * private to the post handler.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->new_len = rec->a3;
	snap->map     = rec->a6;
	rec->post_state = (unsigned long) snap;
}

/*
 * If we successfully remapped a range, we need to update our record of it
 * so we don't re-use the old address.
 */
static void post_mremap(struct syscallrecord *rec)
{
	struct mremap_post_state *snap =
		(struct mremap_post_state *) rec->post_state;
	struct map *map;
	void *ptr = (void *) rec->retval;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(snap)) {
		outputerr("post_mremap: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1,
				   __ATOMIC_RELAXED);
		rec->post_state = 0;
		return;
	}

	map = (struct map *) snap->map;

	if (ptr == MAP_FAILED || map == NULL)
		goto out_free;

	/*
	 * Defense in depth: even with the post_state snapshot, a wholesale
	 * stomp could rewrite the snapshot's inner map field.  Reject a
	 * pid-scribbled map before deref.
	 */
	if (looks_like_corrupted_ptr(map)) {
		outputerr("post_mremap: rejected suspicious map=%p (post_state-scribbled?)\n",
			  (void *) map);
		__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1,
				   __ATOMIC_RELAXED);
		goto out_free;
	}

	map->ptr = ptr;
	map->size = snap->new_len;

out_free:
	deferred_freeptr(&rec->post_state);
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
