#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "child.h"
#include "compiler.h"
#include "debug.h"
#include "deferred-free.h"
#include "maps.h"
#include "objects.h"
#include "objects-internal.h"
#include "params.h"
#include "pc_format.h"
#include "pids.h"
#include "random.h"
#include "rnd.h"
#include "registry-internal.h"
#include "shm.h"
#include "stats_ring.h"
#include "utils.h"

/*
 * Every obj struct comes from alloc_object().  Two backing stores:
 *
 *  1. this_child() != NULL and objpool_local_arena_alloc() succeeds:
 *     the slot lives inside the parent-registered MAP_PRIVATE|MAP_ANON
 *     objpool arena tracked with track_shared_region_tagged().  Fuzzed
 *     value-result pointers landing inside the arena get relocated by
 *     avoid_shared_buffer_out()'s range_overlaps_shared() gate before
 *     the syscall issues, closing the mm:runtime-map:objpool scribble
 *     window the range_overlaps_libc_heap gate misses when a post-fork
 *     glibc mmap arena falls outside the pre-fork snapshot's bbox.
 *
 *  2. Fallback -- parent context (pre-fork OBJ_GLOBAL setup), or arena
 *     exhausted / init failure: plain zmalloc_tracked() into the
 *     process's libc heap, protected by the range_overlaps_libc_heap
 *     safety net at the sanitiser layer.
 *
 * OBJ_GLOBAL pools are populated pre-fork in the parent, then fork-
 * COW'd into children's snapshots; OBJ_LOCAL pools are wholly per-child.
 * No path crosses the shared mapping for obj storage.
 */
struct object * alloc_object(void)
{
	struct object *p;

	heap_brk_maybe_refresh();

	if (this_child() != NULL) {
		p = objpool_local_arena_alloc(sizeof(struct object));
		if (p != NULL)
			return p;
	}
	return zmalloc_tracked(sizeof(struct object));
}

void release_obj(struct object *obj,
		 enum obj_scope scope __attribute__((unused)),
		 enum objecttype type __attribute__((unused)))
{
	memset(obj, 0, sizeof(*obj));
	/*
	 * Arena slots never route through free(): the arena is bump-only,
	 * has no recycler, and its pointers do not carry glibc chunk
	 * headers.  A zeroed slot leaves obj_type == OBJ_NONE so a stale
	 * reader fails objpool_check(), matching the deferred-free path's
	 * post-TTL semantics.  deferred_free_enqueue()'s alloc_track
	 * consume gate would also reject an arena pointer (it was never
	 * deferred_alloc_track()'d), leaking bookkeeping.
	 */
	if (objpool_local_arena_owns(obj, sizeof(*obj)))
		return;
	deferred_free_enqueue(obj);
}

/*
 * Can a pool reader load @size bytes at @p?  Pool storage comes only from
 * alloc_object()'s two stores and the array grow that mirrors them: a
 * child's OBJ_LOCAL storage from the objpool arena, which is not libc
 * heap, and the rest -- OBJ_GLOBAL, a child's snapshot of it, and the
 * zmalloc_tracked() fallback -- from the libc heap.  The arena is one
 * mapping with known bounds, so an address inside it is judged by the
 * arena alone, which has to hold every byte the reader loads, even when
 * is_in_glibc_heap() knows no allocator region and accepts anything.  A
 * libc chunk is placed by its start, which is all is_in_glibc_heap() can
 * judge.  The O(1) arena test runs first: arena addresses sit above the
 * break, where the heap lookup pays an sbrk().
 */
bool objpool_storage_plausible(const void *p, unsigned long size)
{
	uintptr_t v = (uintptr_t)p;

	if (v < 0x10000UL || v >= 0x800000000000UL)
		return false;
	if (objpool_local_arena_owns(p, 0))
		return objpool_local_arena_owns(p, size);
	return is_in_glibc_heap(p);
}

struct objhead * get_objhead(enum obj_scope scope, enum objecttype type)
{
	struct objhead *head;

	if (scope == OBJ_GLOBAL) {
		/*
		 * Children resolve against their fork-time snapshot of the
		 * parent's pre-fork pool (allocated by
		 * clone_global_objects_to_child).  The parent's writer view
		 * lives in parent_global_objects[] in this file.
		 *
		 * Children NEVER fall back to the parent view: a child reader
		 * indexing the parent's live head->array escapes the snapshot
		 * the OBJ_GLOBAL contract pins them to (post-fork parent grows
		 * are supposed to be invisible) AND the parent's array may sit
		 * on a heap chunk the parent has since freed and replaced via
		 * the deferred-free hand-off in add_object_grow_capacity().
		 * The child's COW page captured the pre-replacement pointer
		 * value; the indexed read off it lands inside a recycled chunk
		 * (the UAF this fix addresses).  Return NULL instead so any
		 * child whose snapshot did not complete (early init, snapshot
		 * alloc failure) gracefully takes the "empty pool" branch
		 * rather than dereferencing the wrong address space's
		 * bookkeeping.
		 */
		if (mypid() != mainpid) {
			struct childdata *child = this_child();

			if (child == NULL || child->global_objects == NULL)
				return NULL;
			return &child->global_objects[type];
		}
		head = &parent_global_objects[type];
	} else {
		struct childdata *child;

		child = this_child();
		if (child == NULL)
			return NULL;
		head = &child->objects[type];
	}
	return head;
}


/*
 * Snapshot helper for the for_each_obj iterator macro.  Captures
 * num_entries and array into the caller's state struct so the loop
 * body operates on a per-invocation hoist rather than re-loading
 * head fields on every iteration.  No cross-process coherence is
 * required post-Stage-5 — every pool lives in the iterating
 * process's private heap.
 *
 * The array_snap is additionally gated through
 * objpool_storage_plausible() over the n_snap slots the walk loads
 * before it publishes n_snap, the same check objhead_indexed_read()
 * makes.  A scribbled head->array that survives the NULL test still
 * lands the indexed load off for_each_obj's array_snap[idx] on an
 * unmapped page; forcing n_snap to 0 makes the iterator bail cleanly
 * instead.
 */
void __for_each_obj_init(struct objhead *head,
			 struct __for_each_obj_state *s)
{
	s->n_snap = head->num_entries;
	s->array_snap = head->array;

	if (s->array_snap == NULL) {
		s->n_snap = 0;
		return;
	}

	if (!objpool_storage_plausible(s->array_snap,
			(unsigned long)s->n_snap * sizeof(*s->array_snap))) {
		__atomic_add_fetch(&shm->stats.diag.objpool_array_stale_caught, 1,
				   __ATOMIC_RELAXED);
		s->n_snap = 0;
	}
}
