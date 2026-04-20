#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "child.h"
#include "fd.h"
#include "list.h"
#include "locks.h"
#include "objects.h"
#include "pids.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static struct list_head global_obj_list = { &global_obj_list, &global_obj_list };

void register_global_obj_init(struct global_obj_entry *entry)
{
	list_add_tail((struct list_head *) &entry->list, &global_obj_list);
}

void init_global_objects(void)
{
	struct list_head *pos;

	list_for_each(pos, &global_obj_list) {
		struct global_obj_entry *entry = (struct global_obj_entry *) pos;

		output(0, "Initializing %s objects.\n", entry->name);
		entry->init();
	}
}

/*
 * Hash table mapping fd → (object, type) for O(1) lookup in
 * remove_object_by_fd().  Open-addressing with linear probing.
 *
 * The table itself lives in shm (shm->fd_hash) so children can read
 * the per-slot generation counter the parent updates on every fd-table
 * mutation.  Mutations happen under shm->objlock; child reads of the
 * gen field are unlocked and use ACQUIRE semantics.
 */

void fd_hash_init(void)
{
	unsigned int i;

	for (i = 0; i < FD_HASH_SIZE; i++) {
		shm->fd_hash[i].fd = -1;
		shm->fd_hash[i].gen = 0;
	}
	shm->fd_hash_count = 0;
}

static unsigned int fd_hash_slot(int fd)
{
	return (unsigned int) fd & (FD_HASH_SIZE - 1);
}

/*
 * Internal insert that preserves the entry's existing generation and
 * doesn't update fd_hash_count.  Used by fd_hash_remove to re-hash
 * displaced entries: the entry's identity is unchanged, only its slot,
 * so any cached gen on a child must continue to match.
 */
static void fd_hash_reinsert(int fd, struct object *obj, enum objecttype type,
			     uint32_t gen)
{
	unsigned int slot;
	unsigned int probe;

	slot = fd_hash_slot(fd);
	for (probe = 0; probe < FD_HASH_SIZE; probe++) {
		if (shm->fd_hash[slot].fd == -1)
			break;
		slot = (slot + 1) & (FD_HASH_SIZE - 1);
	}
	if (probe == FD_HASH_SIZE)
		return;

	shm->fd_hash[slot].obj = obj;
	shm->fd_hash[slot].type = type;
	__atomic_store_n(&shm->fd_hash[slot].gen, gen, __ATOMIC_RELEASE);
	__atomic_store_n(&shm->fd_hash[slot].fd, fd, __ATOMIC_RELEASE);
}

bool fd_hash_insert(int fd, struct object *obj, enum objecttype type)
{
	unsigned int slot;
	uint32_t gen;

	if (fd < 0)
		return true;

	if (shm->fd_hash_count >= FD_HASH_SIZE)
		return false;

	slot = fd_hash_slot(fd);
	while (shm->fd_hash[slot].fd != -1 && shm->fd_hash[slot].fd != fd)
		slot = (slot + 1) & (FD_HASH_SIZE - 1);

	if (shm->fd_hash[slot].fd == -1)
		shm->fd_hash_count++;

	shm->fd_hash[slot].obj = obj;
	shm->fd_hash[slot].type = type;
	/*
	 * Bump the slot's generation so any child that cached the
	 * previous occupant's (or absence) gen sees a mismatch.  The
	 * RELEASE-store on fd publishes the entry — children using
	 * ACQUIRE-load on fd see the updated gen too.
	 */
	gen = shm->fd_hash[slot].gen + 1;
	__atomic_store_n(&shm->fd_hash[slot].gen, gen, __ATOMIC_RELEASE);
	__atomic_store_n(&shm->fd_hash[slot].fd, fd, __ATOMIC_RELEASE);
	return true;
}

void fd_hash_remove(int fd)
{
	unsigned int slot, next, i;

	if (fd < 0)
		return;

	slot = fd_hash_slot(fd);
	for (i = 0; i < FD_HASH_SIZE; i++) {
		if (shm->fd_hash[slot].fd == -1)
			return;
		if (shm->fd_hash[slot].fd == fd) {
			uint32_t gen;

			/*
			 * Mark the slot empty and bump its generation so a
			 * child that cached this fd's gen sees a mismatch
			 * even before any replacement is inserted here.
			 */
			gen = shm->fd_hash[slot].gen + 1;
			__atomic_store_n(&shm->fd_hash[slot].gen, gen,
					 __ATOMIC_RELEASE);
			__atomic_store_n(&shm->fd_hash[slot].fd, -1,
					 __ATOMIC_RELEASE);
			shm->fd_hash_count--;
			next = (slot + 1) & (FD_HASH_SIZE - 1);
			while (shm->fd_hash[next].fd != -1) {
				struct fd_hash_entry displaced = shm->fd_hash[next];
				__atomic_store_n(&shm->fd_hash[next].fd, -1,
						 __ATOMIC_RELEASE);
				fd_hash_reinsert(displaced.fd, displaced.obj,
						 displaced.type, displaced.gen);
				next = (next + 1) & (FD_HASH_SIZE - 1);
			}
			return;
		}
		slot = (slot + 1) & (FD_HASH_SIZE - 1);
	}
}

struct fd_hash_entry *fd_hash_lookup(int fd)
{
	unsigned int slot, i;

	if (fd < 0)
		return NULL;

	slot = fd_hash_slot(fd);
	for (i = 0; i < FD_HASH_SIZE; i++) {
		int slot_fd = __atomic_load_n(&shm->fd_hash[slot].fd, __ATOMIC_ACQUIRE);

		if (slot_fd == -1)
			return NULL;
		if (slot_fd == fd)
			return &shm->fd_hash[slot];
		slot = (slot + 1) & (FD_HASH_SIZE - 1);
	}
	return NULL;
}

static bool is_fd_type(enum objecttype type)
{
	return type >= OBJ_FD_PIPE && type <= OBJ_FD_FS_CTX;
}

struct object * alloc_object(void)
{
	struct object *obj;
	obj = zmalloc(sizeof(struct object));
	INIT_LIST_HEAD(&obj->list);
	return obj;
}

struct objhead * get_objhead(enum obj_scope scope, enum objecttype type)
{
	struct objhead *head;

	if (scope == OBJ_GLOBAL)
		head = &shm->global_objects[type];
	else {
		struct childdata *child;

		child = this_child();
		if (child == NULL)
			return NULL;
		head = &child->objects[type];
	}
	return head;
}


/*
 * Fixed capacity for global object arrays.  These are allocated in
 * MAP_SHARED memory so children can safely read them.  Using realloc()
 * on private heap would put the new array in the parent's address space
 * only, causing children to SIGSEGV when they follow the pointer.
 */
#define GLOBAL_OBJ_MAX_CAPACITY	1024

void add_object(struct object *obj, enum obj_scope scope, enum objecttype type)
{
	struct objhead *head;
	bool was_protected = false;

	/* Children must not mutate global objects — the objhead metadata
	 * is in shared memory but the objects/arrays are in per-process
	 * heap (COW after fork).  Mixing the two corrupts everything. */
	if (scope == OBJ_GLOBAL && getpid() != mainpid) {
		free(obj);
		return;
	}

	if (scope == OBJ_GLOBAL) {
		lock(&shm->objlock);
		/* Most parent-side OBJ_GLOBAL adds happen during init,
		 * before freeze.  The post-freeze case is fd regeneration
		 * via try_regenerate_fd() — temporarily lift the RO
		 * protection so the list/array writes can land. */
		if (globals_are_protected()) {
			thaw_global_objects();
			was_protected = true;
		}
	}

	head = get_objhead(scope, type);
	if (head->list == NULL) {
		if (scope == OBJ_GLOBAL) {
			head->list = alloc_shared_global(sizeof(struct list_head));
		} else {
			head->list = zmalloc(sizeof(struct list_head));
		}
		INIT_LIST_HEAD(head->list);
	}

	list_add_tail(&obj->list, head->list);

	/* For global objects, the array was pre-allocated in shared
	 * memory by init_object_lists().  Never realloc — just reject
	 * if we've hit the fixed capacity. */
	if (scope == OBJ_GLOBAL) {
		if (head->num_entries >= head->array_capacity) {
			outputerr("add_object: global array full for type %u "
				  "(cap %u)\n", type, head->array_capacity);
			list_del(&obj->list);
			if (is_fd_type(type)) {
				int fd = fd_from_object(obj, type);
				if (fd >= 0)
					close(fd);
			}
			free(obj);
			goto out_unlock;
		}
	} else if (head->num_entries >= head->array_capacity) {
		/* Local objects: grow via realloc on private heap. */
		struct object **newarray;
		unsigned int newcap;

		newcap = head->array_capacity ? head->array_capacity * 2 : 16;
		newarray = realloc(head->array, newcap * sizeof(struct object *));
		if (newarray == NULL) {
			outputerr("add_object: realloc failed for type %u (cap %u)\n",
				  type, newcap);
			list_del(&obj->list);
			if (is_fd_type(type)) {
				int fd = fd_from_object(obj, type);
				if (fd >= 0)
					close(fd);
			}
			free(obj);
			return;
		}
		head->array = newarray;
		head->array_capacity = newcap;
	}
	head->array[head->num_entries] = obj;
	obj->array_idx = head->num_entries;

	head->num_entries++;

	/* Track global fd-type objects in the hash table */
	if (scope == OBJ_GLOBAL && is_fd_type(type)) {
		int fd = fd_from_object(obj, type);
		if (!fd_hash_insert(fd, obj, type)) {
			outputerr("add_object: fd hash full for type %u, dropping fd %d\n",
				  type, fd);
			head->num_entries--;
			head->array[head->num_entries] = NULL;
			list_del(&obj->list);
			if (fd >= 0)
				close(fd);
			free(obj);
			goto out_unlock;
		}
	}

	if (head->dump != NULL)
		head->dump(obj, scope);

out_unlock:
	if (scope == OBJ_GLOBAL) {
		if (was_protected)
			freeze_global_objects();
		unlock(&shm->objlock);
	}

	/* if we just added something to a child list, check
	 * to see if we need to do some pruning.
	 */
	if (scope == OBJ_LOCAL)
		prune_objects();
}

void init_object_lists(enum obj_scope scope, struct childdata *child)
{
	unsigned int i;

	for (i = 0; i < MAX_OBJECT_TYPES; i++) {
		struct objhead *head;

		if (scope == OBJ_GLOBAL)
			head = &shm->global_objects[i];
		else {
			if (child == NULL)
				return;
			head = &child->objects[i];
		}

		head->list = NULL;
		head->num_entries = 0;

		if (scope == OBJ_GLOBAL) {
			/* Pre-allocate the parallel array in MAP_SHARED memory
			 * so children can safely read it.  Never realloc.
			 * Tagged global so freeze_global_objects() will mprotect
			 * it RO once init is done. */
			head->array = alloc_shared_global(GLOBAL_OBJ_MAX_CAPACITY *
							  sizeof(struct object *));
			memset(head->array, 0, GLOBAL_OBJ_MAX_CAPACITY *
			       sizeof(struct object *));
			head->array_capacity = GLOBAL_OBJ_MAX_CAPACITY;
		} else {
			head->array = NULL;
			head->array_capacity = 0;
		}

		/*
		 * child lists can inherit properties from global lists.
		 */
		if (scope == OBJ_LOCAL) {
			struct objhead *globalhead;
			globalhead = &shm->global_objects[i];
			head->max_entries = globalhead->max_entries;
			head->destroy = globalhead->destroy;
			head->dump = globalhead->dump;
		}
	}
}

struct object * get_random_object(enum objecttype type, enum obj_scope scope)
{
	struct objhead *head;
	struct object *obj;

	if (scope == OBJ_GLOBAL)
		lock(&shm->objlock);

	head = get_objhead(scope, type);

	if (head->num_entries == 0)
		obj = NULL;
	else
		obj = head->array[rand() % head->num_entries];

	if (scope == OBJ_GLOBAL)
		unlock(&shm->objlock);

	return obj;
}

bool objects_empty(enum objecttype type)
{
	return shm->global_objects[type].num_entries == 0;
}

/*
 * Invalidate the fd stored in an object by setting it to -1.
 * Used before calling the destructor when the fd was already closed
 * (e.g. after a successful close() syscall) to prevent double-close.
 * The destructor's close(-1) call will harmlessly return EBADF.
 */
static void invalidate_object_fd(struct object *obj, enum objecttype type)
{
	switch (type) {
	case OBJ_FD_PIPE:	obj->pipeobj.fd = -1; break;
	case OBJ_FD_DEVFILE:	obj->fileobj.fd = -1; break;
	case OBJ_FD_PROCFILE:	obj->fileobj.fd = -1; break;
	case OBJ_FD_SYSFILE:	obj->fileobj.fd = -1; break;
	case OBJ_FD_PERF:	obj->perfobj.fd = -1; break;
	case OBJ_FD_EPOLL:	obj->epollobj.fd = -1; break;
	case OBJ_FD_EVENTFD:	obj->eventfdobj.fd = -1; break;
	case OBJ_FD_TIMERFD:	obj->timerfdobj.fd = -1; break;
	case OBJ_FD_TESTFILE:	obj->testfileobj.fd = -1; break;
	case OBJ_FD_MEMFD:	obj->memfdobj.fd = -1; break;
	case OBJ_FD_DRM:	obj->drmfd = -1; break;
	case OBJ_FD_INOTIFY:	obj->inotifyobj.fd = -1; break;
	case OBJ_FD_SOCKET:	obj->sockinfo.fd = -1; break;
	case OBJ_FD_USERFAULTFD: obj->userfaultobj.fd = -1; break;
	case OBJ_FD_FANOTIFY:	obj->fanotifyobj.fd = -1; break;
	case OBJ_FD_BPF_MAP:	obj->bpfobj.map_fd = -1; break;
	case OBJ_FD_BPF_PROG:	obj->bpfprogobj.fd = -1; break;
	case OBJ_FD_IO_URING:	obj->io_uringobj.fd = -1; break;
	case OBJ_FD_LANDLOCK:	obj->landlockobj.fd = -1; break;
	case OBJ_FD_PIDFD:	obj->pidfdobj.fd = -1; break;
	case OBJ_FD_MQ:		obj->mqobj.fd = -1; break;
	case OBJ_FD_SECCOMP_NOTIF: obj->seccomp_notifobj.fd = -1; break;
	case OBJ_FD_IOMMUFD:	obj->iommufdobj.fd = -1; break;
	case OBJ_FD_FS_CTX:	obj->fsctxobj.fd = -1; break;
	default:		break;
	}
}

/*
 * Call the destructor for this object, and then release it.
 * Internal version — caller must hold objlock if operating on globals.
 *
 * If already_closed is true, the fd has already been closed by the
 * kernel (e.g. after a successful close() syscall).  We invalidate
 * the fd in the object so the destructor's close() call is a harmless
 * no-op, while any other cleanup (munmap, free, etc.) still runs.
 */
static void __destroy_object(struct object *obj, enum obj_scope scope,
			     enum objecttype type, bool already_closed)
{
	struct objhead *head;
	unsigned int idx, last;

	list_del(&obj->list);

	head = get_objhead(scope, type);

	/* Swap-with-last removal from the parallel array */
	idx = obj->array_idx;
	last = head->num_entries - 1;
	if (idx != last) {
		head->array[idx] = head->array[last];
		if (head->array[idx] != NULL)
			head->array[idx]->array_idx = idx;
	}
	head->array[last] = NULL;

	head->num_entries--;

	/* Remove from fd hash table */
	if (scope == OBJ_GLOBAL && is_fd_type(type))
		fd_hash_remove(fd_from_object(obj, type));

	if (already_closed && is_fd_type(type))
		invalidate_object_fd(obj, type);

	if (head->destroy != NULL)
		head->destroy(obj);

	free(obj);
}

void destroy_object(struct object *obj, enum obj_scope scope, enum objecttype type)
{
	bool was_protected = false;

	if (scope == OBJ_GLOBAL && getpid() != mainpid)
		return;

	if (scope == OBJ_GLOBAL) {
		lock(&shm->objlock);
		if (globals_are_protected()) {
			thaw_global_objects();
			was_protected = true;
		}
	}

	__destroy_object(obj, scope, type, false);

	if (scope == OBJ_GLOBAL) {
		if (was_protected)
			freeze_global_objects();
		unlock(&shm->objlock);
	}
}

/*
 * Destroy a whole list of objects.
 */
static void destroy_objects(enum objecttype type, enum obj_scope scope)
{
	struct list_head *node, *list, *tmp;
	struct objhead *head;

	head = get_objhead(scope, type);
	if (head->num_entries == 0)
		return;

	list = head->list;
	if (list == NULL)
		return;

	list_for_each_safe(node, tmp, list) {
		struct object *obj;

		obj = (struct object *) node;

		__destroy_object(obj, scope, type, false);
	}

	head->num_entries = 0;
	/* Only free private-heap arrays (OBJ_LOCAL).  OBJ_GLOBAL arrays
	 * were allocated with alloc_shared() and cannot be freed. */
	if (scope == OBJ_LOCAL) {
		free(head->array);
		head->array = NULL;
		head->array_capacity = 0;
		free(head->list);
		head->list = NULL;
	} else {
		/* Zero out the shared array for reuse. */
		memset(head->array, 0, head->array_capacity * sizeof(struct object *));
	}
}

/* Destroy all global objects on exit. */
void destroy_global_objects(void)
{
	unsigned int i;

	/* The list heads and parallel arrays were mprotected RO after
	 * init.  Cleanup needs to mutate them, so re-enable writes in
	 * this process first.  Children are gone by the time we get
	 * here so we do not need to coordinate with them. */
	thaw_global_objects();

	for (i = 0; i < MAX_OBJECT_TYPES; i++)
		destroy_objects(i, OBJ_GLOBAL);
}

/*
 * Store an fd into the appropriate union field for this object type.
 * The inverse of fd_from_object(); used by the generic post-hook that
 * registers fds returned by RET_FD syscalls without a custom handler.
 */
void set_object_fd(struct object *obj, enum objecttype type, int fd)
{
	switch (type) {
	case OBJ_FD_PIPE:	obj->pipeobj.fd = fd; break;
	case OBJ_FD_DEVFILE:
	case OBJ_FD_PROCFILE:
	case OBJ_FD_SYSFILE:	obj->fileobj.fd = fd; break;
	case OBJ_FD_PERF:	obj->perfobj.fd = fd; break;
	case OBJ_FD_EPOLL:	obj->epollobj.fd = fd; break;
	case OBJ_FD_EVENTFD:	obj->eventfdobj.fd = fd; break;
	case OBJ_FD_TIMERFD:	obj->timerfdobj.fd = fd; break;
	case OBJ_FD_TESTFILE:	obj->testfileobj.fd = fd; break;
	case OBJ_FD_MEMFD:	obj->memfdobj.fd = fd; break;
	case OBJ_FD_DRM:	obj->drmfd = fd; break;
	case OBJ_FD_INOTIFY:	obj->inotifyobj.fd = fd; break;
	case OBJ_FD_SOCKET:	obj->sockinfo.fd = fd; break;
	case OBJ_FD_USERFAULTFD: obj->userfaultobj.fd = fd; break;
	case OBJ_FD_FANOTIFY:	obj->fanotifyobj.fd = fd; break;
	case OBJ_FD_BPF_MAP:	obj->bpfobj.map_fd = fd; break;
	case OBJ_FD_BPF_PROG:	obj->bpfprogobj.fd = fd; break;
	case OBJ_FD_IO_URING:	obj->io_uringobj.fd = fd; break;
	case OBJ_FD_LANDLOCK:	obj->landlockobj.fd = fd; break;
	case OBJ_FD_PIDFD:	obj->pidfdobj.fd = fd; break;
	case OBJ_FD_MQ:		obj->mqobj.fd = fd; break;
	case OBJ_FD_SECCOMP_NOTIF: obj->seccomp_notifobj.fd = fd; break;
	case OBJ_FD_IOMMUFD:	obj->iommufdobj.fd = fd; break;
	case OBJ_FD_FS_CTX:	obj->fsctxobj.fd = fd; break;
	default:		break;
	}
}

/*
 * Linear search the per-child OBJ_LOCAL pool of one type for an fd.
 * Used by the generic post-hook to detect fds that a syscall-specific
 * post handler already registered, so we don't double-track them.
 * O(n) over a small n (typically tens of entries).
 */
struct object *find_local_object_by_fd(enum objecttype type, int fd)
{
	struct objhead *head;
	unsigned int i;

	if (fd < 0)
		return NULL;

	head = get_objhead(OBJ_LOCAL, type);
	if (head == NULL || head->num_entries == 0)
		return NULL;

	for (i = 0; i < head->num_entries; i++) {
		struct object *obj = head->array[i];

		if (obj != NULL && fd_from_object(obj, type) == fd)
			return obj;
	}
	return NULL;
}

/*
 * Extract the fd from an object, given its type.
 * Returns -1 for non-fd object types.
 */
int fd_from_object(struct object *obj, enum objecttype type)
{
	switch (type) {
	case OBJ_FD_PIPE:	return obj->pipeobj.fd;
	case OBJ_FD_DEVFILE:
	case OBJ_FD_PROCFILE:
	case OBJ_FD_SYSFILE:	return obj->fileobj.fd;
	case OBJ_FD_PERF:	return obj->perfobj.fd;
	case OBJ_FD_EPOLL:	return obj->epollobj.fd;
	case OBJ_FD_EVENTFD:	return obj->eventfdobj.fd;
	case OBJ_FD_TIMERFD:	return obj->timerfdobj.fd;
	case OBJ_FD_TESTFILE:	return obj->testfileobj.fd;
	case OBJ_FD_MEMFD:	return obj->memfdobj.fd;
	case OBJ_FD_DRM:	return obj->drmfd;
	case OBJ_FD_INOTIFY:	return obj->inotifyobj.fd;
	case OBJ_FD_SOCKET:	return obj->sockinfo.fd;
	case OBJ_FD_USERFAULTFD: return obj->userfaultobj.fd;
	case OBJ_FD_FANOTIFY:	return obj->fanotifyobj.fd;
	case OBJ_FD_BPF_MAP:	return obj->bpfobj.map_fd;
	case OBJ_FD_BPF_PROG:	return obj->bpfprogobj.fd;
	case OBJ_FD_IO_URING:	return obj->io_uringobj.fd;
	case OBJ_FD_LANDLOCK:	return obj->landlockobj.fd;
	case OBJ_FD_PIDFD:	return obj->pidfdobj.fd;
	case OBJ_FD_MQ:		return obj->mqobj.fd;
	case OBJ_FD_SECCOMP_NOTIF: return obj->seccomp_notifobj.fd;
	case OBJ_FD_IOMMUFD:	return obj->iommufdobj.fd;
	case OBJ_FD_FS_CTX:	return obj->fsctxobj.fd;
	default:		return -1;
	}
}

/*
 * Look up an fd in the hash table and destroy its object.
 * Called from fd_event_drain() after a child reported a close or dup2.
 *
 * The child closed its own copy of the fd (children have independent
 * fd tables after fork).  The parent's copy is still open and must be
 * closed here — pass already_closed=false so the destructor runs
 * close() on the parent's fd.  Without this, every child close event
 * leaks one fd in the parent, leading to fd exhaustion.
 */
void remove_object_by_fd(int fd)
{
	struct fd_hash_entry *entry;
	struct object *obj;
	enum objecttype type;
	bool was_protected = false;

	if (getpid() != mainpid)
		return;

	lock(&shm->objlock);

	if (globals_are_protected()) {
		thaw_global_objects();
		was_protected = true;
	}

	entry = fd_hash_lookup(fd);
	if (entry == NULL) {
		if (was_protected)
			freeze_global_objects();
		unlock(&shm->objlock);
		return;
	}

	obj = entry->obj;
	type = entry->type;

	__atomic_add_fetch(&shm->stats.fd_closed_tracked, 1, __ATOMIC_RELAXED);
	__destroy_object(obj, OBJ_GLOBAL, type, false);

	unlock(&shm->objlock);

	/* try_regenerate_fd() may call add_object() which sees the
	 * thawed state (globals_are_protected() returns false here)
	 * and skips its own thaw/refreeze.  We refreeze afterwards
	 * so the regeneration's writes stay covered by our window. */
	try_regenerate_fd(type);

	if (was_protected)
		freeze_global_objects();
}

static void __prune_objects(enum objecttype type, enum obj_scope scope)
{
	struct objhead *head;
	struct list_head *node, *list, *tmp;

	head = get_objhead(scope, type);

	/* 0 = don't ever prune. */
	if (head->max_entries == 0)
		return;

	/* only prune full lists. */
	if (head->num_entries < head->max_entries)
		return;

	/* Single pass: prune each entry with 1/10 probability. */
	list = head->list;
	list_for_each_safe(node, tmp, list) {
		if (ONE_IN(10)) {
			struct object *obj = (struct object *) node;

			destroy_object(obj, scope, type);
		}
	}
}

void prune_objects(void)
{
	unsigned int i;

	/* We don't want to over-prune things and growing a little
	 * bit past the ->max is fine, we'll clean it up next time.
	 */
	if (!(ONE_IN(10)))
		return;

	for (i = 0; i < MAX_OBJECT_TYPES; i++) {
		__prune_objects(i, OBJ_LOCAL);
		// For now, we're only pruning local objects.
		// __prune_objects(i, OBJ_GLOBAL);
	}
}
