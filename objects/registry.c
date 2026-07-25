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
 * Every obj struct comes from alloc_object() (zmalloc) and lives in
 * the allocating process's private heap.  OBJ_GLOBAL pools are
 * populated pre-fork in the parent, then fork-COW'd into children's
 * snapshots; OBJ_LOCAL pools are wholly per-child.  No path crosses
 * the shared mapping for obj storage.
 */
struct object * alloc_object(void)
{
	heap_brk_maybe_refresh();
	return zmalloc_tracked(sizeof(struct object));
}

void release_obj(struct object *obj,
		 enum obj_scope scope __attribute__((unused)),
		 enum objecttype type __attribute__((unused)))
{
	memset(obj, 0, sizeof(*obj));
	deferred_free_enqueue(obj);
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
 * The array_snap is additionally range-checked and gated through
 * is_in_glibc_heap() before the walk publishes n_snap, mirroring
 * the guard in objhead_indexed_read().  A scribbled head->array
 * that survives the NULL test still lands the indexed load off
 * for_each_obj's array_snap[idx] on an unmapped page; forcing
 * n_snap to 0 makes the iterator bail cleanly instead.
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

	if ((uintptr_t)s->array_snap < 0x10000UL ||
	    (uintptr_t)s->array_snap >= 0x800000000000UL ||
	    !is_in_glibc_heap(s->array_snap)) {
		__atomic_add_fetch(&shm->stats.diag.objpool_array_stale_caught, 1,
				   __ATOMIC_RELAXED);
		s->n_snap = 0;
	}
}
