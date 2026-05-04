/*
 * SYSCALL_DEFINE2(munmap, unsigned long, addr, size_t, len)
 */
#include <stdlib.h>
#include "arch.h"
#include "deferred-free.h"
#include "maps.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#define WHOLE 1

/*
 * Snapshot of the four munmap inputs read by the post handler, captured
 * at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot:
 *   - flip the action gate that decides destroy_object vs prot=0
 *     invalidate (a stomped 1 destroys an arbitrary trinity object via
 *     container_of(); a stomped 0 leaves a stale entry the consumer
 *     pool will hand out for write);
 *   - retarget the trinity-tracked map pointer the post handler
 *     destroys or invalidates (looks_like_corrupted_ptr cannot tell a
 *     real-but-wrong heap address from a real map pointer);
 *   - steer the proc-maps oracle's range arguments at a different
 *     address window than the syscall actually operated on (forging
 *     either a clean compare against an unrelated /proc/self/maps slice
 *     or an "unmap leaked" anomaly that never happened).
 */
struct munmap_post_state {
	unsigned long addr;
	unsigned long len;
	unsigned long map;
	unsigned long action;
};

static void sanitise_munmap(struct syscallrecord *rec)
{
	struct munmap_post_state *snap;
	struct map *map = common_set_mmap_ptr_len();
	int action = 0;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

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

	/*
	 * Snapshot the four inputs the post handler reads.  Without this
	 * the post handler reads rec->a1/a2/a3/a4 at post-time, when a
	 * sibling syscall may have scribbled the slots: a stomped action
	 * flips destroy_object vs prot=0 invalidate (destroying an
	 * arbitrary object via container_of, or leaving a stale entry the
	 * pool hands out for write), looks_like_corrupted_ptr() cannot
	 * tell a real-but-wrong heap address from a real map pointer so a
	 * foreign-heap stomp slips the rec->a3 guard, and a stomped
	 * rec->a1/a2 retargets the proc-maps oracle at a window the
	 * syscall never touched -- forging either a clean compare or a
	 * never-happened anomaly.  post_state is private to the post
	 * handler.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->addr   = rec->a1;
	snap->len    = rec->a2;
	snap->map    = rec->a3;
	snap->action = rec->a4;
	rec->post_state = (unsigned long) snap;
}

static void post_munmap(struct syscallrecord *rec)
{
	struct munmap_post_state *snap =
		(struct munmap_post_state *) rec->post_state;
	struct map *map;
	unsigned long action;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(snap)) {
		outputerr("post_munmap: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1,
				   __ATOMIC_RELAXED);
		rec->post_state = 0;
		return;
	}

	if (rec->retval != 0)
		goto out_free;

	map = (struct map *) snap->map;
	action = snap->action;

	/*
	 * Defense in depth: even with the post_state snapshot, a wholesale
	 * stomp could rewrite the snapshot's inner map field.  Reject a
	 * pid-scribbled map before deref.
	 */
	if (map != NULL && looks_like_corrupted_ptr(map)) {
		outputerr("post_munmap: rejected suspicious map=%p (post_state-scribbled?)\n",
			  (void *) map);
		__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1,
				   __ATOMIC_RELAXED);
		goto out_free;
	}

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
	if (snap->addr != 0 && snap->len > 0 && ONE_IN(100)) {
		if (!proc_maps_check(snap->addr, snap->len, 0, false)) {
			output(0, "mmap oracle: munmap(%lx, %lu) succeeded "
			       "but range still in /proc/self/maps\n",
			       snap->addr, snap->len);
			__atomic_add_fetch(&shm->stats.mmap_oracle_anomalies, 1,
					   __ATOMIC_RELAXED);
		}
	}

out_free:
	deferred_freeptr(&rec->post_state);
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
