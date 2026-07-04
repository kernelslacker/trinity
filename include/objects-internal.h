#pragma once

/*
 * Cross-TU internal glue for the objects/ subsystem dir.  Symbols
 * declared here were file-local static in the pre-carve objects.c and
 * are shared exclusively across the objects/ subsystem dir TUs.  Not part of the
 * public objects.h API -- consumers outside objects/ must go through
 * include/objects.h.
 */

#include "objects.h"

/*
 * Parent-private OBJ_GLOBAL pool.  Populated pre-fork by every
 * REG_GLOBAL_OBJ provider via add_object(OBJ_GLOBAL); the per-child
 * snapshot in clone_global_objects_to_child() reads this array.
 * Storage lives in objects/global.c.
 */
extern struct objhead parent_global_objects[MAX_OBJECT_TYPES];

/*
 * Parent-private fd->object hash and parallel compact live-fd list.
 * Storage lives in objects/fdhash.c.  Read by clone_global_objects_to_child
 * (objects/global.c) when snapshotting into a child.
 */
extern struct fd_hash_entry parent_fd_hash[FD_HASH_SIZE];
extern int parent_fd_live[FD_LIVE_MAX];
extern unsigned int parent_fd_hash_count;
extern unsigned int parent_fd_live_count;

/*
 * Per-type dispatch helpers.  invalidate_object_fd is used by the
 * registry's __destroy_object() to clear an obj's fd union member
 * before the destructor runs when the fd has already been closed.
 */
void invalidate_object_fd(struct object *obj, enum objecttype type);

/*
 * Per-OBJ_LOCAL objhead fd->object hash maintenance called by the
 * registry's add_object_publish() and __destroy_object().  The
 * lookup helper stays private to objects/local.c.
 */
void local_fd_hash_insert(struct objhead *head, int fd, struct object *obj);
void local_fd_hash_remove(struct objhead *head, int fd);

/*
 * Registry-side destroy helpers used by objects/global.c
 * (remove_object_by_fd, destroy_global_objects).
 */
void __destroy_object(struct object *obj, enum obj_scope scope,
		      enum objecttype type, bool already_closed);
void destroy_objects(enum objecttype type, enum obj_scope scope);
