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
 * Grow head->array if the next slot is past current capacity.  head
 * is resolved once in add_object() and threaded through; same for
 * the hoisted is_fd / fd pair used by the leak-close error path.
 *
 * Both scopes grow the same way: allocate a fresh container, memcpy
 * the live slots over, publish head->array + array_capacity, then
 * deferred_free_enqueue(oldarray).  The deferred-free TTL (5-50
 * syscalls, effective 80-800 with DEFERRED_TICK_BATCH) keeps the old
 * chunk readable for a reader still holding the old head->array: a
 * for_each_obj walk keeps its own snapshot across its body, so a body
 * that grows the pool would otherwise go on indexing a freed
 * container.  Same hazard shape as the obj-struct deferred-free path:
 * a live container freed underneath a cached reader is a
 * use-after-free.
 *
 * OBJ_GLOBAL needs the same deferral as OBJ_LOCAL even though the
 * writer is single (parent pre-fork only): the parent itself reads
 * its own pre-fork OBJ_GLOBAL pool during arg-gen, so single-writer
 * does not imply single-reader.  This is single-process re-entrancy,
 * not cross-thread.
 *
 * The capacity is guarded at UINT_MAX / 2.  On overflow: close any
 * leaked fd, release_obj() the inbound obj, and tell the caller to
 * bail.
 *
 * Returns true if the grow failed (release_obj already called --
 * add_object() must return immediately); false if either no grow
 * was needed or the grow succeeded and the publish phase should run.
 */
bool add_object_grow_capacity(struct object *obj, enum obj_scope scope,
			      enum objecttype type, struct objhead *head,
			      bool is_fd, int fd)
{
	struct object **newarray, **oldarray;
	unsigned int n, cap, newcap;
	unsigned long oldbytes, newbytes;

	n = head->num_entries;
	cap = head->array_capacity;
	oldarray = head->array;
	oldbytes = (unsigned long)cap * sizeof(struct object *);

	/*
	 * Refresh head->array's alloc_track LRU slot before the grow
	 * check below.  Inter-grow windows on cap>=1024 pools span
	 * thousands of intervening zmalloc_tracked calls -- without this
	 * refresh the live container ages out of the 4096-slot ring and
	 * the next grow's deferred_free_enqueue(oldarray) rejects on
	 * alloc_track miss (leak, not UAF, but still silently bypasses
	 * the deferred-free path).  Same pattern as the clone_global_mmap_pool
	 * dedup-skip refresh: any long-lived container must be revived
	 * with alloc_track_refresh() before it can be deferred-freed.
	 * An arena container, the usual OBJ_LOCAL one, is neither tracked
	 * nor deferred-freed, so its refresh could only scan alloc_track
	 * and count a consume miss; it is skipped with the extent the
	 * release below judges it by.  The NULL guard skips the first
	 * grow (empty pool).
	 */
	if (oldarray != NULL && !objpool_local_arena_owns(oldarray, oldbytes))
		alloc_track_refresh(oldarray);

	if (n < cap)
		return false;

	if (cap > UINT_MAX / 2) {
		outputerr("add_object: cap overflow type=%u num_entries=%u capacity=%u\n",
			  type, n, cap);
		if (is_fd && fd >= 0)
			close(fd);
		release_obj(obj, scope, type);
		return true;
	}

	newcap = cap ? cap * 2 : 16;
	newbytes = (unsigned long)newcap * sizeof(struct object *);

	/*
	 * A child's pool prefers objpool_local_arena_alloc() so the
	 * container inherits the arena's track_shared_region_tagged()
	 * protection against fuzzed value-result writes.  Falls back to
	 * zmalloc_tracked on arena exhaustion (bump-only allocator;
	 * late-lifetime grows may miss the arena and rely on the
	 * range_overlaps_libc_heap safety net instead).
	 */
	newarray = NULL;
	if (scope == OBJ_LOCAL)
		newarray = objpool_local_arena_alloc(newbytes);
	if (newarray == NULL)
		newarray = zmalloc_tracked(newbytes);

	if (oldarray != NULL)
		memcpy(newarray, oldarray, oldbytes);
	head->array = newarray;
	head->array_capacity = newcap;

	/*
	 * An arena old container has no free()able chunk header and no
	 * tracker entry to consume, so it stays where the arena
	 * bump-cursor left it -- a bounded per-child leak of past-grown
	 * array footprint that the arena's ~13x headroom over
	 * steady-state OBJ_LOCAL storage accounts for.
	 */
	if (oldarray != NULL && !objpool_local_arena_owns(oldarray, oldbytes))
		deferred_free_enqueue(oldarray);

	return false;
}
