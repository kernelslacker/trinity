#include <stdbool.h>

#include "arch.h"
#include "child.h"
#include "maps.h"
#include "rnd.h"
#include "shm.h"
#include "utils.h"

/* used in several sanitise_* functions. */
struct map * common_set_mmap_ptr_len(enum objecttype *out_type)
{
	struct syscallrecord *rec;
	struct map *map;
	struct childdata *child = this_child();

	if (out_type != NULL)
		*out_type = OBJ_NONE;

	rec = &child->syscall;
	map = (struct map *) rec->a1;
	if (map == NULL) {
		rec->a1 = 0;
		rec->a2 = 0;
		return NULL;
	}

	/*
	 * ARG_MMAP plumbed a struct map * into rec->a1 at args-generation
	 * time, but a sibling kernel-write to childdata.syscall.a1 can
	 * replace it with a fuzzed value before we get here.  Validate the
	 * shape before the map->ptr / map->size derefs below; an unmapped
	 * or non-canonical pointer would SEGV the consumer (mincore,
	 * mremap, madvise, mlock, munlock, mbind, getrandom, ...).  Mirror
	 * the failure mode of the NULL path so existing callers' NULL
	 * short-circuits handle it cleanly.
	 */
	if (looks_like_corrupted_ptr(rec, map)) {
		outputerr("common_set_mmap_ptr_len: rejected suspicious map=%p (pid-scribbled?)\n",
			  map);
		rec->a1 = 0;
		rec->a2 = 0;
		return NULL;
	}

	rec->a1 = (unsigned long) map->ptr;
	if (map->size == 0) {
		rec->a2 = 0;
	} else {
		rec->a2 = rnd_modulo_u64(map->size);
		rec->a2 &= PAGE_MASK;
	}

	/*
	 * Resolve which OBJ_LOCAL OBJ_MMAP_* pool this obj actually lives
	 * in.  destroy_object() in post_munmap's WHOLE branch needs the
	 * matching head to satisfy its head->array[idx] == obj invariant
	 * -- a hard-coded OBJ_MMAP_ANON destroys nothing when the entry
	 * came from FILE/TESTFILE, leaving an obj that points at unmapped
	 * memory in the pool for the next consumer to walk into.
	 *
	 * obj->obj_type is stamped by add_object() and would be a faster
	 * read, but a wild rec->a1 that passes looks_like_corrupted_ptr
	 * could still point at the embedded map field of a non-mmap obj
	 * whose stamped tag would then mislead us.  Walking the three
	 * mmap pools and matching the obj pointer is the ground-truth
	 * check: a no-match leaves *out_type at OBJ_NONE so the caller
	 * declines to destroy.
	 */
	if (out_type != NULL) {
		struct object *want = container_of(map, struct object, map);
		static const enum objecttype map_pool_types[3] = {
			OBJ_MMAP_ANON, OBJ_MMAP_FILE, OBJ_MMAP_TESTFILE,
		};
		unsigned int i;
		/* Cumulative objects visited across the
		 * three-pool walk this call.  Bumped per-iteration
		 * inside for_each_obj, accumulated locally so the
		 * shared counter pays exactly one RELAXED add per
		 * call instead of one per object visited. */
		unsigned long scanned = 0;

		for (i = 0; i < 3; i++) {
			struct objhead *head;
			struct object *obj;
			unsigned int idx;

			head = get_objhead(OBJ_LOCAL, map_pool_types[i]);
			if (head == NULL || head->array == NULL)
				continue;

			for_each_obj(head, obj, idx) {
				scanned++;
				if (obj == want) {
					*out_type = map_pool_types[i];
					goto type_resolved;
				}
			}
		}
type_resolved:
		/* Bump even on a miss: the walk still cost the
		 * objects it visited, and the miss-rate (1 - hits /
		 * calls) is itself a signal that the slot was
		 * scribbled / pre-clamped / from a non-MMAP pool. */
		__atomic_add_fetch(&shm->stats.maps.type_resolution_calls,
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.maps.type_resolution_scan_length_sum,
				   scanned, __ATOMIC_RELAXED);
		if (*out_type != OBJ_NONE)
			__atomic_add_fetch(&shm->stats.maps.type_resolution_hits,
					   1, __ATOMIC_RELAXED);
	}

	return map;
}
