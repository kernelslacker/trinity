/*
 * Per-child MAP_PRIVATE|MAP_ANON arena backing OBJ_LOCAL objpool storage
 * (struct object slots and head->array chunks), so one tracked-region
 * registration covers every slot.  The libc-heap check alone misses a glibc
 * mmap arena spawned after heap_bounds_init(), letting a fuzzed pointer
 * scribble a slot; range_overlaps_shared() relocates it out of the arena.
 */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/mman.h>

#include "child.h"
#include "objects.h"
#include "objects-internal.h"
#include "trinity.h"		/* outputerr */
#include "utils.h"		/* track_shared_region_tagged */

/*
 * 8 MiB of virtual space per child; physical use tracks the pages touched.
 * About 13x the observed steady-state OBJ_LOCAL footprint (~30 objheads *
 * ~100 objs * ~200 bytes ~= 600 KiB), so churn rarely reaches the
 * zmalloc_tracked() fallback.
 */
#define OBJPOOL_ARENA_BYTES	(8UL << 20)	/* 8 MiB */
#define OBJPOOL_ARENA_ALIGN	16UL		/* covers __alignof__(max_align_t) */

static unsigned char *objpool_arena_base;
static unsigned long objpool_arena_size;

void objpool_local_arena_init(void)
{
	void *p;

	p = mmap(NULL, OBJPOOL_ARENA_BYTES, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED) {
		outputerr("objpool_local_arena_init: mmap %lu failed: %s\n",
			  OBJPOOL_ARENA_BYTES, strerror(errno));
		return;
	}

	/*
	 * Register once, at the parent's pre-fork virtual address.  The
	 * shared_regions[] entry lives in alloc_shared()'d memory that every
	 * child inherits via fork, so every child's range_overlaps_shared()
	 * call sees the same tracked span at the same VA the child's COW
	 * view of the arena occupies.  Origin tag names the offender in the
	 * range_overlaps_shared_slow diagnostic under CONFIG_GUARD_SHARED;
	 * the untagged variant is functionally identical without the tag.
	 */
#ifdef CONFIG_GUARD_SHARED
	track_shared_region_tagged((unsigned long)p, OBJPOOL_ARENA_BYTES,
				   "objpool-local-arena");
#else
	track_shared_region((unsigned long)p, OBJPOOL_ARENA_BYTES);
#endif

	objpool_arena_base = p;
	objpool_arena_size = OBJPOOL_ARENA_BYTES;
}

/*
 * Return true if [p, p+size) falls entirely inside the arena.  Used by
 * release_obj() and add_object_grow_capacity() to choose the arena
 * memset/no-op path over the deferred_free_enqueue() path, and by
 * objpool_storage_plausible() to accept arena storage, which the libc
 * heap check refuses.  size==0 degenerates to a point-in-arena check.
 * A NULL base (init failed or ran before this call) returns false so
 * callers unconditionally take the libc-heap path.
 */
bool objpool_local_arena_owns(const void *p, unsigned long size)
{
	unsigned long v = (unsigned long)p;
	unsigned long base;

	if (objpool_arena_base == NULL)
		return false;
	if (p == NULL)
		return false;

	base = (unsigned long)objpool_arena_base;
	if (v < base)
		return false;
	if (size > objpool_arena_size)
		return false;
	if (v > base + objpool_arena_size - size)
		return false;
	return true;
}

/*
 * Bump allocator.  Returns a zero-initialised slot of at least @size
 * bytes on success, NULL on any failure (arena unavailable, size
 * larger than the arena, or bump cursor exhausted).  A NULL return is
 * the caller's cue to fall back to zmalloc_tracked() -- the fallback
 * pointer routes through the normal deferred-free path at release
 * time and pays the range_overlaps_libc_heap safety net.
 *
 * Bump-only, no free list, no wrap: recycling a slot would need a TTL
 * against stale readers (the deferred-free ring's job for libc-heap
 * allocations) and the arena has none.  Slots are not registered with
 * alloc_track either: they never reach free() (see release_obj()), and
 * obj_pool_slot_check() in mm/maps-pick.c validates a slot with
 * objpool_check(), not alloc_track_lookup().
 *
 * Owner-only writes to the cursor: the child's own bump cursor lives
 * in struct childdata (COW-inherited zero from the parent's zero-init
 * pre-fork), and parent-context callers get a static local so the
 * pre-fork parent path (rare -- OBJ_GLOBAL setup runs before the
 * per-child ring alloc) does not race the child cursors.
 */
void *objpool_local_arena_alloc(unsigned long size)
{
	struct childdata *child;
	static unsigned long parent_cursor;
	unsigned long *cursor_p;
	unsigned long cursor, aligned, end;

	if (objpool_arena_base == NULL)
		return NULL;
	if (size == 0)
		return NULL;

	aligned = (size + (OBJPOOL_ARENA_ALIGN - 1)) & ~(OBJPOOL_ARENA_ALIGN - 1);
	if (aligned > objpool_arena_size)
		return NULL;

	child = this_child();
	cursor_p = (child != NULL) ? &child->objpool_arena_cursor
				   : &parent_cursor;
	cursor = *cursor_p;
	end = cursor + aligned;
	if (end > objpool_arena_size)
		return NULL;

	*cursor_p = end;

	/*
	 * The MAP_PRIVATE|MAP_ANON region is zero-fill on first fault; a
	 * bump-forward cursor guarantees the slot is untouched, so a memset
	 * would just re-zero already-zero pages.  Skip it -- the caller
	 * (alloc_object / add_object_grow_capacity) also zeros before use,
	 * so a stray non-zero byte from a hypothetical future recycler
	 * would still be neutralised at the current call sites.
	 */
	return objpool_arena_base + cursor;
}
