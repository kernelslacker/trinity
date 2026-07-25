#pragma once

/*
 * Cross-TU internal glue for the objects/registry-*.c source split.
 * Symbols here were file-local static in the pre-split registry.c and
 * are shared exclusively across the registry-*.c sibling TUs
 * (registry.c, registry-lifecycle.c, registry-pool.c, registry-pick.c,
 * registry-diag.c).  Not part of the objects/ cross-subsystem API --
 * that lives in include/objects-internal.h.
 */

#include "objects.h"

/*
 * Release an obj struct.  Routed through deferred_free_enqueue()
 * rather than free()'d immediately so a stale slot pointer that
 * survived past __destroy_object() lands on a chunk with a 5-50
 * syscall TTL (effective 80-800 with DEFERRED_TICK_BATCH) instead
 * of glibc-reclaimed memory: get_map() and friends read &obj->map
 * after taking the slot pointer out of head->array, and the arg-gen
 * path that invoked get_map() can hold the pointer across the
 * window in which the slot's owner destroys the obj.
 *
 * Zero the chunk before handing it to the deferred-free ring so a
 * post-destroy read (via a stale slot pointer) trips the size==0
 * band of consumer sanity checks instead of dereferencing an obj
 * whose name string or mmap pointer was already torn down by the
 * destructor.
 */
void release_obj(struct object *obj, enum obj_scope scope,
		 enum objecttype type);

/*
 * Grow head->array if the next slot is past current capacity.  Lives
 * in registry-pool.c; called from add_object() in registry-lifecycle.c.
 * See the definition site for the full contract on the allocate-copy-
 * defer-free shape and the OBJ_GLOBAL / OBJ_LOCAL rationale.
 *
 * Returns true if the grow failed (release_obj already called --
 * add_object() must return immediately); false if either no grow
 * was needed or the grow succeeded and the publish phase should run.
 */
bool add_object_grow_capacity(struct object *obj, enum obj_scope scope,
			      enum objecttype type, struct objhead *head,
			      bool is_fd, int fd);
