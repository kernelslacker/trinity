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
 * Indexed read off head->array guarded against a between-snapshot
 * grow / teardown.  The hazard the bare head->array[idx] read had was
 * that the array container is freed and replaced on grow and at pool
 * teardown -- a reader that captured the array pointer pre-grow then
 * indexed it post-grow would read off a chunk that may already have
 * been handed back to glibc (ASAN: heap-use-after-free at the
 * arr[idx] load).  All three array-replace sites
 * (OBJ_GLOBAL grow, OBJ_LOCAL grow, destroy_objects teardown) now
 * route the old container through deferred_free_enqueue, so the
 * captured arr stays readable across the TTL window the rechecks
 * below rely on.  The recipe here mirrors the obj-level
 * slot_version / object_slot_alive() pattern one level earlier and
 * is strictly check-then-load:
 *
 *   1. Snapshot array_generation, the array pointer and num_entries.
 *   2. Cheap stateless provenance check on the captured array pointer
 *      so an obviously-wild value (early-init noise, a scribbled
 *      head->array) is rejected before the indexed read fires --
 *      defense in depth on top of the gen re-check, not a substitute
 *      for it.
 *   3. Re-read array_generation BEFORE the load.  Mismatch ==> a
 *      grow/teardown ran between (1) and now, the captured arr is
 *      already the freed container, so bail without ever touching
 *      arr[idx].  This is the load-bearing fix -- a post-load
 *      re-check can only detect the UAF after the dangerous read has
 *      already executed.
 *   4. Load arr[idx].
 *   5. Re-read array_generation a second time.  Catches a grow that
 *      raced the load itself (between (3) and (4)); the deferred-free
 *      TTL keeps the captured arr safely readable across that tiny
 *      window, so the load completes, but a mismatch still poisons
 *      the result and we return NULL so the caller retries.
 *
 * The retry-on-NULL contract is what every get_random_object() consumer
 * already expects (empty pool returns NULL); the guarded path just
 * widens the set of conditions that lead to NULL.
 */
static struct object *objhead_indexed_read(struct objhead *head, unsigned int idx)
{
	unsigned int gen0;
	struct object **arr;
	unsigned int n;
	struct object *obj;

	gen0 = head->array_generation;
	arr = head->array;
	n = head->num_entries;

	if (arr == NULL || n == 0 || idx >= n)
		return NULL;

	if ((uintptr_t)arr < 0x10000UL ||
	    (uintptr_t)arr >= 0x800000000000UL ||
	    !is_in_glibc_heap(arr)) {
		__atomic_add_fetch(&shm->stats.diag.objpool_array_stale_caught, 1,
				   __ATOMIC_RELAXED);
		return NULL;
	}

	/*
	 * Pre-load gen re-check.  If a grow/teardown ran between snapshotting
	 * gen0 and here, the captured arr is the freed container and the
	 * indexed load below would touch a chunk the deferred-free TTL may
	 * already have handed back to glibc.  Bail before the read fires.
	 */
	if (head->array_generation != gen0) {
		__atomic_add_fetch(&shm->stats.diag.objpool_array_stale_caught, 1,
				   __ATOMIC_RELAXED);
		return NULL;
	}

	obj = arr[idx];

	if (head->array_generation != gen0) {
		__atomic_add_fetch(&shm->stats.diag.objpool_array_stale_caught, 1,
				   __ATOMIC_RELAXED);
		return NULL;
	}

	return obj;
}

/*
 * Pick a random object from a pool.  Single-writer per pool, single
 * reader per call (the owning process).  Children read their fork-time
 * snapshot of the parent's pre-fork OBJ_GLOBAL pool; OBJ_LOCAL pools
 * are wholly per-child.  An empty pool returns NULL, as does a pick
 * the indexed-read helper rejected (head->array was freed and replaced
 * between the picker's snapshot and the indexed load -- the chunk it
 * would have read was on the deferred-free path and may already have
 * been recycled by glibc).  Callers already retry on NULL.
 */
struct object * get_random_object(enum objecttype type, enum obj_scope scope)
{
	struct objhead *head;
	unsigned int n;

	head = get_objhead(scope, type);
	if (head == NULL)
		return NULL;

	n = head->num_entries;
	if (n == 0 || head->array == NULL)
		return NULL;

	return objhead_indexed_read(head, rnd_modulo_u32(n));
}

bool objpool_check(const struct object *obj, enum objecttype expected)
{
	if (obj == NULL)
		return false;

	if ((uintptr_t)obj < 0x10000UL ||
	    (uintptr_t)obj >= 0x800000000000UL ||
	    !is_in_glibc_heap(obj)) {
		__atomic_add_fetch(&shm->stats.diag.global_obj_uaf_caught, 1,
				   __ATOMIC_RELAXED);
		return false;
	}

	if (obj->obj_type != expected) {
		__atomic_add_fetch(&shm->stats.diag.global_obj_uaf_caught, 1,
				   __ATOMIC_RELAXED);
		return false;
	}

	return true;
}

bool objects_empty(enum objecttype type)
{
	struct objhead *head = get_objhead(OBJ_GLOBAL, type);

	if (head == NULL)
		return true;
	return head->num_entries == 0;
}

bool objects_pool_empty(enum obj_scope scope, enum objecttype type)
{
	struct objhead *head = get_objhead(scope, type);

	if (head == NULL)
		return true;
	return head->num_entries == 0;
}
