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
 * the hoisted is_fd / fd pair used by the leak-close error paths.
 *
 * The alloc-track LRU slot for the live head->array container is
 * refreshed before the grow check so the upcoming
 * deferred_free_enqueue(oldarray) doesn't reject on an alloc_track
 * miss after thousands of intervening zmalloc_tracked calls in
 * cap>=1024 pools.  An alloc_track miss would leak the old chunk
 * rather than UAF it, but still silently bypasses the deferred-free
 * path the indexed-read correctness model relies on.
 *
 * Both scopes use the same allocate-copy-defer-free shape: a fresh
 * zmalloc_tracked container, memcpy the live slots over, publish
 * head->array + array_capacity, bump array_generation, then
 * deferred_free_enqueue(oldarray).  The deferred-free TTL (5-50
 * syscalls, effective 80-800 with DEFERRED_TICK_BATCH) keeps the
 * old chunk readable across any in-flight reader's snapshot
 * through objhead_indexed_read() -- without it, the same process
 * can re-enter the picker during arg-gen, hold a cached
 * head->array snapshot across the grow, and UAF the freed
 * container.  Same hazard shape as the obj-struct deferred-free
 * path: a live container freed underneath a cached reader is a
 * use-after-free.
 *
 * OBJ_GLOBAL needs the same deferral as OBJ_LOCAL even though the
 * writer is single (parent pre-fork only): the parent itself reads
 * its own pre-fork OBJ_GLOBAL pool during arg-gen, so single-writer
 * does not imply single-reader.  This is single-process re-entrancy,
 * not cross-thread.
 *
 * Both branches cap-overflow-guard at UINT_MAX / 2.  On either the
 * overflow or the malloc-failure path: close any leaked fd,
 * release_obj() the inbound obj, and tell the caller to bail.
 *
 * Returns true if the grow failed (release_obj already called --
 * add_object() must return immediately); false if either no grow
 * was needed or the grow succeeded and the publish phase should run.
 */
bool add_object_grow_capacity(struct object *obj, enum obj_scope scope,
			      enum objecttype type, struct objhead *head,
			      bool is_fd, int fd)
{
	unsigned int n, cap;

	n = head->num_entries;
	cap = head->array_capacity;

	/*
	 * Refresh head->array's alloc_track LRU slot before the grow
	 * check below.  Inter-grow windows on cap>=1024 pools span
	 * thousands of intervening zmalloc_tracked calls -- without this
	 * refresh the live container ages out of the 4096-slot ring and
	 * the next grow's deferred_free_enqueue(oldarray) rejects on
	 * alloc_track miss (leak, not UAF, but still silently bypasses
	 * the deferred-free path the indexed-read correctness model
	 * relies on).  Same pattern as the clone_global_mmap_pool
	 * dedup-skip refresh: any long-lived container must be revived
	 * with alloc_track_refresh() before it can be deferred-freed.
	 * Both scopes alloc via zmalloc_tracked so the refresh applies
	 * uniformly; the NULL guard skips the first grow (empty pool).
	 */
	if (head->array != NULL)
		alloc_track_refresh(head->array);

	if (scope == OBJ_GLOBAL) {
		if (n >= cap) {
			/*
			 * Grow on the parent's private heap.  Single-writer
			 * (parent pre-fork only) but NOT single-reader: the
			 * parent re-enters get_random_object() during its own
			 * arg-gen and can hold a cached head->array snapshot
			 * across this grow.  An immediate free of the old
			 * container would UAF the in-flight indexed-read.
			 * Use the same allocate-copy-defer-free shape as the
			 * OBJ_LOCAL branch below; the deferred-free TTL keeps
			 * the old chunk readable across any reader's window.
			 */
			struct object **newarray;
			struct object **oldarray;
			unsigned int newcap = cap ? cap * 2 : 16;

			if (cap > UINT_MAX / 2) {
				outputerr("add_object: cap overflow type=%u num_entries=%u capacity=%u\n",
					  type, n, cap);
				if (is_fd && fd >= 0)
					close(fd);
				release_obj(obj, scope, type);
				return true;
			}
			newarray = zmalloc_tracked(newcap * sizeof(struct object *));
			if (newarray == NULL) {
				outputerr("add_object: malloc failed for type %u (cap %u)\n",
					  type, newcap);
				if (is_fd && fd >= 0)
					close(fd);
				release_obj(obj, scope, type);
				return true;
			}
			oldarray = head->array;
			if (oldarray != NULL && cap > 0)
				memcpy(newarray, oldarray,
				       cap * sizeof(struct object *));
			head->array = newarray;
			head->array_capacity = newcap;
			/*
			 * Bump before the deferred-free hand-off so any reader
			 * whose snapshot raced this grow re-reads the new
			 * generation and drops the pick rather than indexing
			 * the (now-ttl'd) old container.  Pool-private
			 * single-writer (parent pre-fork on OBJ_GLOBAL, owning
			 * child on OBJ_LOCAL), so an unlocked bump is
			 * sufficient.  See objhead_indexed_read().
			 */
			head->array_generation++;
			if (oldarray != NULL)
				deferred_free_enqueue(oldarray);
		}
	} else if (n >= cap) {
		/*
		 * OBJ_LOCAL grow on the owning child's private heap.  Use
		 * the same allocate-copy-defer-free shape that closed the
		 * UAF on the array container reachable through cached
		 * head->array reads in the arg-gen path: the deferred-free
		 * ring gives the old chunk a 5-50 syscall (effective
		 * 80-800 with DEFERRED_TICK_BATCH) TTL, far longer than
		 * any in-flight reader's window.  Same hazard shape as
		 * the obj-struct deferred-free path: freeing a live
		 * container underneath a cached reader is a use-after-free.
		 *
		 * First-slice payload-arena wiring: the new array prefers
		 * objpool_local_arena_alloc() so the container inherits the
		 * arena's track_shared_region_tagged() protection against
		 * fuzzed value-result writes.  Falls back to zmalloc_tracked
		 * on arena exhaustion (bump-only allocator; late-lifetime
		 * grows may miss the arena and rely on the range_overlaps_
		 * libc_heap safety net instead).  The old container's release
		 * routes back to deferred_free_enqueue only when it was libc-
		 * heap: an arena-allocated old container has no free()able
		 * chunk header and no tracker entry to consume, so it stays
		 * where the arena bump-cursor left it -- a bounded per-child
		 * leak of past-grown array footprint that the arena's ~13x
		 * headroom over steady-state OBJ_LOCAL storage accounts for.
		 */
		struct object **newarray;
		struct object **oldarray;
		unsigned int newcap = cap ? cap * 2 : 16;
		unsigned long newbytes;

		if (cap > UINT_MAX / 2) {
			outputerr("add_object: cap overflow type=%u num_entries=%u capacity=%u\n",
				  type, n, cap);
			if (is_fd && fd >= 0)
				close(fd);
			release_obj(obj, scope, type);
			return true;
		}
		newbytes = (unsigned long)newcap * sizeof(struct object *);
		newarray = objpool_local_arena_alloc(newbytes);
		if (newarray == NULL)
			newarray = zmalloc_tracked(newbytes);
		if (newarray == NULL) {
			outputerr("add_object: malloc failed for type %u (cap %u)\n",
				  type, newcap);
			if (is_fd && fd >= 0)
				close(fd);
			release_obj(obj, scope, type);
			return true;
		}
		oldarray = head->array;
		if (oldarray != NULL && cap > 0)
			memcpy(newarray, oldarray, cap * sizeof(struct object *));
		head->array = newarray;
		head->array_capacity = newcap;
		/*
		 * Bump before the deferred-free hand-off so any reader whose
		 * snapshot raced this grow re-reads the new generation and
		 * drops the pick rather than indexing the (now-ttl'd) old
		 * container.  See objhead_indexed_read().
		 */
		head->array_generation++;
		if (oldarray != NULL) {
			unsigned long oldbytes =
				(unsigned long)cap * sizeof(struct object *);

			if (!objpool_local_arena_owns(oldarray, oldbytes))
				deferred_free_enqueue(oldarray);
			/* else: arena slot -- bump-only, leaks by design. */
		}
	}

	return false;
}
