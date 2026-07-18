/*
 * SYSCALL_DEFINE2(munmap, unsigned long, addr, size_t, len)
 */
#include "arch.h"
#include "maps.h"
#include "object-types.h"
#include "objects.h"
#include "random.h"
#include "rnd.h"
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
	unsigned long magic;
	unsigned long addr;
	unsigned long len;
	unsigned long map;
	unsigned long action;
	/*
	 * OBJ_MMAP_* pool the underlying obj lives in, as resolved by
	 * common_set_mmap_ptr_len() at sanitise time.  Captured here so
	 * the WHOLE branch in post_munmap routes destroy_object() to the
	 * head whose array actually contains the obj; a hard-coded
	 * OBJ_MMAP_ANON destroys nothing when the entry came from
	 * FILE/TESTFILE and the now-unmapped VMA stays cached in the
	 * pool for the next consumer to walk into.  OBJ_NONE means
	 * common_set_mmap_ptr_len() couldn't match the obj against any
	 * local mmap pool -- the WHOLE branch then declines to destroy
	 * rather than guess.
	 */
	unsigned long type;
};

#define MUNMAP_POST_STATE_MAGIC	0x4D554E4D41505F5FUL	/* "MUNMAP__" */

static void sanitise_munmap(struct syscallrecord *rec)
{
	struct munmap_post_state *snap;
	enum objecttype map_type = OBJ_NONE;
	struct map *map = common_set_mmap_ptr_len(&map_type);
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
		 * map_destructor → munmap(map->ptr, tracked_size ?: size).
		 * Match that extent here so the kernel-side munmap covers
		 * the full VMA -- map->size has been clamped down to the
		 * file-backed walkable region for clamped MMAPED_FILE
		 * entries, so passing it would unmap only the head and
		 * leak the past-EOF tail VMA when post_munmap declines to
		 * destroy (pool_type == OBJ_NONE arm, line ~217), and even
		 * when the destructor does fire the kernel sees two munmaps
		 * for the head plus one for the tail rather than a single
		 * clean teardown.  shared_region overlap check below also
		 * gets the real span so a tail that grazes trinity bookkeeping
		 * gets caught.  Falls back to map->size for legacy entries
		 * (alloc_zero_map ANON, post_mmap CHILD_ANON) where the two
		 * are equal anyway. */
		rec->a1 = (unsigned long) map->ptr;
		rec->a2 = map->tracked_size ? map->tracked_size : map->size;
	} else if (RAND_BOOL()) {
		/* unmap a range of the mapping. */
		unsigned long nr_pages;
		unsigned long offset, offsetpagenr;
		unsigned long len;

		nr_pages = map->size / page_size;
		if (nr_pages == 0)
			nr_pages = 1;
		offsetpagenr = rnd_modulo_u32(nr_pages);
		offset = offsetpagenr * page_size;
		rec->a1 = (unsigned long) map->ptr + offset;

		len = (rnd_modulo_u32((nr_pages - offsetpagenr))) + 1;
		len *= page_size;
		rec->a2 = len;
	} else {
		/* Unmap one page from the selected mapping. */

		rec->a1 = (unsigned long) map->ptr;
		if (map->size > 0)
			rec->a1 += (rnd_modulo_u32(map->size)) & PAGE_MASK;
		rec->a2 = page_size;
	}

	/*
	 * Make sure we don't unmap the shm region — children fuzzing
	 * munmap can blow away trinity's shared state and crash everyone.
	 * For WHOLE, also drop the action so post_munmap doesn't run the
	 * destructor (which would munmap(map->ptr, map->size) regardless).
	 */
	if (RANGE_OVERLAPS_SHARED_AUDITED("munmap", rec->a1, rec->a2)) {
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
	 * handler.  post_state_install pairs the rec->post_state assign
	 * with the ownership-table register so the observable window
	 * between the two is closed; post_munmap() will then gate the
	 * snap through post_state_claim_owned() and prove ownership
	 * before dereferencing any field.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic  = MUNMAP_POST_STATE_MAGIC;
	snap->addr   = rec->a1;
	snap->len    = rec->a2;
	snap->map    = rec->a3;
	snap->action = rec->a4;
	snap->type   = (unsigned long) map_type;
	post_state_install(rec, snap);
}

static void post_munmap(struct syscallrecord *rec)
{
	struct munmap_post_state *snap;
	struct map *map;
	unsigned long action;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, MUNMAP_POST_STATE_MAGIC, __func__);
	if (snap == NULL)
		return;

	if (rec->retval != 0)
		goto out_free;

	map = (struct map *) snap->map;
	action = snap->action;

	/*
	 * Defense in depth: even with the post_state snapshot, a wholesale
	 * stomp could rewrite the snapshot's inner map field.  Reject a
	 * pid-scribbled map before deref.
	 */
	if (map != NULL && looks_like_corrupted_ptr(rec, map)) {
		outputerr("post_munmap: rejected suspicious map=%p (post_state-scribbled?)\n",
			  (void *) map);
		goto out_free;
	}

	/*
	 * Either branch invalidates the get_writable_address() known_rw
	 * skip-cache.  For WHOLE the slot is about to be destroyed; for the
	 * sub-range branch we are about to clear map->prot to 0.  In both
	 * cases the cached "slot is RW and resident" claim is stale and
	 * letting it persist would let the hot path hand a caller a
	 * pointer into a torn-down or hole-punched VMA.
	 */
	if (map != NULL)
		map->known_rw = false;

	if (action == WHOLE && map != NULL) {
		enum objecttype pool_type = (enum objecttype) snap->type;

		/*
		 * Only destroy when common_set_mmap_ptr_len() positively
		 * identified the pool this obj lives in.  An OBJ_NONE
		 * here means the obj didn't match any local mmap pool at
		 * sanitise time -- the underlying VMA has now been
		 * unmapped, but routing destroy_object() at a guessed
		 * head would trip the head->array[idx] == obj invariant
		 * and leave the slot in place anyway.  The entry will be
		 * cleaned up later when its pool is torn down; better
		 * that than chasing the wrong head.
		 */
		if (pool_type == OBJ_MMAP_ANON ||
		    pool_type == OBJ_MMAP_FILE ||
		    pool_type == OBJ_MMAP_TESTFILE) {
			struct object *obj =
				container_of(map, struct object, map);
			destroy_object(obj, OBJ_LOCAL, pool_type);
		}
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
			__atomic_add_fetch(&shm->stats.oracle.mmap_oracle_anomalies, 1,
					   __ATOMIC_RELAXED);
		}
	}

out_free:
	post_state_release(rec, snap);
}

struct syscallentry syscall_munmap = {
	.name = "munmap",
	.num_args = 2,
	.argtype = { [0] = ARG_MMAP, [1] = ARG_LEN },
	.argname = { [0] = "addr", [1] = "len" },
	.group = GROUP_VM,
	.sanitise = sanitise_munmap,
	.post = post_munmap,
	.rettype = RET_ZERO_SUCCESS,
};
