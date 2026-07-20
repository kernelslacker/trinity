#include <stdbool.h>
#include <stdlib.h>
#include "child.h"
#include "objects.h"
#include "objects-internal.h"
#include "shm.h"
#include "utils.h"

/*
 * Per-objhead fd→object hash for OBJ_LOCAL fd-typed pools.
 *
 * Open-addressing with linear probing into a fixed power-of-two slot array
 * (LOCAL_FD_HASH_SIZE).  fd == -1 marks empty.  The table lives in the
 * owning child's private heap — head->fd_hash itself sits in shm alongside
 * the rest of the objhead, but the buffer it points at is per-process and
 * unreachable from any other address space, the same shape head->array
 * uses for OBJ_LOCAL pools allocated via get_objhead(OBJ_LOCAL).
 *
 * Replaces the O(n) linear walk over head->array in
 * find_local_object_by_fd() with a single hash probe.  That function is
 * called from register_returned_fd() on every successful RET_FD syscall
 * whose entry->ret_objtype is not OBJ_NONE (open, openat, socket, accept,
 * eventfd, timerfd, perf_event_open, io_uring_setup, memfd_create,
 * pidfd, fanotify_init, etc.), so the saving applies on the syscall hot
 * path with head->num_entries typically in the tens-to-low-hundreds.
 */
static unsigned int local_fd_hash_slot_idx(int fd)
{
	return (unsigned int)fd & (LOCAL_FD_HASH_SIZE - 1);
}

static void local_fd_hash_alloc(struct objhead *head)
{
	unsigned int i;

	head->fd_hash = malloc(LOCAL_FD_HASH_SIZE *
			       sizeof(struct local_fd_hash_slot));
	if (head->fd_hash == NULL)
		return;
	for (i = 0; i < LOCAL_FD_HASH_SIZE; i++) {
		head->fd_hash[i].fd = -1;
		head->fd_hash[i].obj = NULL;
	}
}

/*
 * Internal insert that does not check for an existing entry — used by
 * local_fd_hash_remove() to re-seat displaced entries after a removal.
 * The displaced entry's identity is unchanged, so the original (fd, obj)
 * pair is reinserted unconditionally into the first empty slot.
 */
static void local_fd_hash_reinsert(struct objhead *head, int fd,
				   struct object *obj)
{
	unsigned int slot, probe;

	slot = local_fd_hash_slot_idx(fd);
	for (probe = 0; probe < LOCAL_FD_HASH_SIZE; probe++) {
		if (head->fd_hash[slot].fd == -1) {
			head->fd_hash[slot].fd = fd;
			head->fd_hash[slot].obj = obj;
			return;
		}
		slot = (slot + 1) & (LOCAL_FD_HASH_SIZE - 1);
	}
}

void local_fd_hash_insert(struct objhead *head, int fd,
			  struct object *obj)
{
	unsigned int slot, probe;

	if (fd < 0)
		return;
	if (head->fd_hash == NULL) {
		local_fd_hash_alloc(head);
		if (head->fd_hash == NULL)
			return;
	}

	slot = local_fd_hash_slot_idx(fd);
	for (probe = 0; probe < LOCAL_FD_HASH_SIZE; probe++) {
		if (head->fd_hash[slot].fd == -1 ||
		    head->fd_hash[slot].fd == fd) {
			head->fd_hash[slot].fd = fd;
			head->fd_hash[slot].obj = obj;
			return;
		}
		slot = (slot + 1) & (LOCAL_FD_HASH_SIZE - 1);
	}
	/*
	 * Table saturated.  Realistically unreachable — LOCAL_FD_HASH_SIZE
	 * sits well above any per-(child, type) pool we have observed —
	 * but if it ever happens the caller gracefully falls back to the
	 * uninserted state: find_local_object_by_fd() returns NULL and
	 * register_returned_fd() simply re-adds, which is the same outcome
	 * as the pre-hash linear walk missing the entry.  Bump a stat so
	 * the silent drop is observable in the end-of-run summary.
	 */
	__atomic_add_fetch(&shm->stats.fd.local_hash_insert_dropped, 1,
			   __ATOMIC_RELAXED);
}

void local_fd_hash_remove(struct objhead *head, int fd)
{
	unsigned int slot, next, i;

	if (fd < 0 || head->fd_hash == NULL)
		return;

	slot = local_fd_hash_slot_idx(fd);
	for (i = 0; i < LOCAL_FD_HASH_SIZE; i++) {
		if (head->fd_hash[slot].fd == -1)
			return;
		if (head->fd_hash[slot].fd == fd) {
			head->fd_hash[slot].fd = -1;
			head->fd_hash[slot].obj = NULL;
			/*
			 * Linear-probing removal: re-seat any entries in the
			 * chain following us so a later lookup that hashes
			 * past this newly-empty slot still finds them.
			 */
			next = (slot + 1) & (LOCAL_FD_HASH_SIZE - 1);
			while (head->fd_hash[next].fd != -1) {
				struct local_fd_hash_slot displaced =
					head->fd_hash[next];
				head->fd_hash[next].fd = -1;
				head->fd_hash[next].obj = NULL;
				local_fd_hash_reinsert(head, displaced.fd,
						       displaced.obj);
				next = (next + 1) & (LOCAL_FD_HASH_SIZE - 1);
			}
			return;
		}
		slot = (slot + 1) & (LOCAL_FD_HASH_SIZE - 1);
	}
}

static struct object *local_fd_hash_lookup(struct objhead *head, int fd)
{
	unsigned int slot, i;

	if (fd < 0 || head->fd_hash == NULL)
		return NULL;

	slot = local_fd_hash_slot_idx(fd);
	for (i = 0; i < LOCAL_FD_HASH_SIZE; i++) {
		if (head->fd_hash[slot].fd == -1)
			return NULL;
		if (head->fd_hash[slot].fd == fd)
			return head->fd_hash[slot].obj;
		slot = (slot + 1) & (LOCAL_FD_HASH_SIZE - 1);
	}
	return NULL;
}

/*
 * Lazy per-child alloc for the OBJ_LOCAL objhead array, in the owning
 * child's private heap.  Runs from init_child() after fork, so the
 * allocation lands in the child's own address space and is unreachable
 * from any other process.  Failure leaves child->objects == NULL and
 * the OBJ_LOCAL path inert for this child -- callers must NULL-check
 * before touching child->objects.
 */
static void local_objects_alloc(struct childdata *child)
{
	if (child == NULL || child->objects != NULL)
		return;

	child->objects = zmalloc(sizeof(struct objhead) * MAX_OBJECT_TYPES);
}

void init_object_lists(enum obj_scope scope, struct childdata *child)
{
	unsigned int i;

	if (scope == OBJ_LOCAL) {
		if (child == NULL)
			return;
		/*
		 * struct childdata lives in alloc_shared() memory, which
		 * __alloc_shared() poisons with random bytes to expose
		 * uninitialised reads.  The objects pointer therefore
		 * arrives at first init holding a wild value, not NULL --
		 * local_objects_alloc()'s "skip if non-NULL" guard would
		 * then leave child->objects pointing at the poison.  Zero
		 * the field before the alloc to neutralise the poison.
		 */
		child->objects = NULL;
		local_objects_alloc(child);
		if (child->objects == NULL)
			return;
	}

	for (i = 0; i < MAX_OBJECT_TYPES; i++) {
		struct objhead *head;

		if (scope == OBJ_GLOBAL)
			head = &parent_global_objects[i];
		else
			head = &child->objects[i];

		head->num_entries = 0;
		head->array = NULL;
		head->array_capacity = 0;
		head->fd_hash = NULL;
		head->next_slot_version = 0;
		head->array_generation = 0;

		/*
		 * child lists can inherit properties from global lists.
		 */
		if (scope == OBJ_LOCAL) {
			struct objhead *globalhead;
			globalhead = &parent_global_objects[i];
			head->max_entries = globalhead->max_entries;
			head->destroy = globalhead->destroy;
			head->dump = globalhead->dump;
		}
	}
}

/*
 * Look up the obj that owns a given fd in the per-child OBJ_LOCAL pool of
 * one type.  Used by the generic post-hook to detect fds that a syscall-
 * specific post handler already registered, so we don't double-track them.
 *
 * O(1) probe through the per-objhead hash maintained by add_object() and
 * __destroy_object().  The previous implementation walked head->array
 * linearly, which on the syscall hot path cost one cache line per slot;
 * the hash collapses that into a single keyed lookup.  The hash is lazily
 * allocated on the first fd-typed insert, so an empty pool's lookup short-
 * circuits via the head->fd_hash == NULL check inside local_fd_hash_lookup
 * with no allocation pressure.
 *
 * The hash is a cache, not the source of truth: local_fd_hash_insert()
 * silently drops entries when the hash allocation fails or the 1024-slot
 * table saturates, but in both cases the obj IS still present in
 * head->array.  Returning NULL from those paths would cause callers such
 * as register_returned_fd() to re-register the live fd as a fresh obj,
 * setting up a later double-close once the duplicate is destroyed.  Fall
 * back to a linear walk of head->array on hash miss so the answer matches
 * reality even when the fast path has lost an entry.
 */
struct object *find_local_object_by_fd(enum objecttype type, int fd)
{
	struct objhead *head;
	struct object *obj;
	unsigned int i;

	if (fd < 0)
		return NULL;

	head = get_objhead(OBJ_LOCAL, type);
	if (head == NULL || head->num_entries == 0)
		return NULL;

	obj = local_fd_hash_lookup(head, fd);
	if (obj != NULL)
		return obj;

	for (i = 0; i < head->num_entries; i++) {
		obj = head->array[i];
		if (obj != NULL && fd_from_object(obj, type) == fd)
			return obj;
	}
	return NULL;
}

struct object *local_fd_find_by_fd(int fd)
{
	unsigned int type;

	if (fd < 0)
		return NULL;

	for (type = OBJ_NONE + 1; type < MAX_OBJECT_TYPES; type++) {
		struct object *obj;

		obj = find_local_object_by_fd((enum objecttype)type, fd);
		if (obj != NULL)
			return obj;
	}
	return NULL;
}
