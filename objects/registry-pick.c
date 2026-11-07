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
 * Pick a random object from a pool.  Single-writer per pool, single
 * reader per call (the owning process).  Children read their fork-time
 * snapshot of the parent's pre-fork OBJ_GLOBAL pool; OBJ_LOCAL pools
 * are wholly per-child.  Nothing between the head->array snapshot and
 * the indexed load can grow the pool or tear it down, so the load reads
 * the live array.  What it does have to survive is a wild head->array
 * or num_entries (early-init noise or a scribble), which
 * objpool_storage_plausible() refuses over the whole array before the
 * load.  A refused pick returns NULL, as an empty pool does; callers
 * already retry on NULL.
 */
struct object * get_random_object(enum objecttype type, enum obj_scope scope)
{
	struct objhead *head;
	struct object **arr;
	unsigned int n;

	head = get_objhead(scope, type);
	if (head == NULL)
		return NULL;

	arr = head->array;
	n = head->num_entries;
	if (n == 0 || arr == NULL)
		return NULL;

	if (!objpool_storage_plausible(arr, (unsigned long)n * sizeof(*arr))) {
		__atomic_add_fetch(&shm->stats.diag.objpool_array_stale_caught, 1,
				   __ATOMIC_RELAXED);
		return NULL;
	}

	return arr[rnd_modulo_u32(n)];
}

bool objpool_check(const struct object *obj, enum objecttype expected)
{
	if (obj == NULL)
		return false;

	if (!objpool_storage_plausible(obj, sizeof(*obj))) {
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
