#include <stdlib.h>
#include <string.h>
#include "fd.h"
#include "list.h"
#include "objects.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * Hash table mapping fd → (object, type) for O(1) lookup in
 * remove_object_by_fd().  Open-addressing with linear probing.
 */
static struct fd_hash_entry fd_hash[FD_HASH_SIZE];

static unsigned int fd_hash_count;

void fd_hash_init(void)
{
	unsigned int i;

	for (i = 0; i < FD_HASH_SIZE; i++)
		fd_hash[i].fd = -1;
	fd_hash_count = 0;
}

static unsigned int fd_hash_slot(int fd)
{
	return (unsigned int) fd & (FD_HASH_SIZE - 1);
}

/*
 * Internal insert that doesn't update fd_hash_count.
 * Used by fd_hash_remove to re-hash displaced entries
 * that are already counted.
 */
static void fd_hash_reinsert(int fd, struct object *obj, enum objecttype type)
{
	unsigned int slot;

	slot = fd_hash_slot(fd);
	while (fd_hash[slot].fd != -1)
		slot = (slot + 1) & (FD_HASH_SIZE - 1);

	fd_hash[slot].fd = fd;
	fd_hash[slot].obj = obj;
	fd_hash[slot].type = type;
}

void fd_hash_insert(int fd, struct object *obj, enum objecttype type)
{
	unsigned int slot;

	if (fd < 0)
		return;

	if (fd_hash_count >= FD_HASH_SIZE)
		return;

	slot = fd_hash_slot(fd);
	while (fd_hash[slot].fd != -1 && fd_hash[slot].fd != fd)
		slot = (slot + 1) & (FD_HASH_SIZE - 1);

	if (fd_hash[slot].fd == -1)
		fd_hash_count++;

	fd_hash[slot].fd = fd;
	fd_hash[slot].obj = obj;
	fd_hash[slot].type = type;
}

void fd_hash_remove(int fd)
{
	unsigned int slot, next, i;

	if (fd < 0)
		return;

	slot = fd_hash_slot(fd);
	for (i = 0; i < FD_HASH_SIZE; i++) {
		if (fd_hash[slot].fd == -1)
			return;
		if (fd_hash[slot].fd == fd) {
			/* Delete and re-hash any entries displaced by this one */
			fd_hash[slot].fd = -1;
			fd_hash_count--;
			next = (slot + 1) & (FD_HASH_SIZE - 1);
			while (fd_hash[next].fd != -1) {
				struct fd_hash_entry displaced = fd_hash[next];
				fd_hash[next].fd = -1;
				fd_hash_reinsert(displaced.fd, displaced.obj, displaced.type);
				next = (next + 1) & (FD_HASH_SIZE - 1);
			}
			return;
		}
		slot = (slot + 1) & (FD_HASH_SIZE - 1);
	}
}

static struct fd_hash_entry *fd_hash_lookup(int fd)
{
	unsigned int slot, i;

	if (fd < 0)
		return NULL;

	slot = fd_hash_slot(fd);
	for (i = 0; i < FD_HASH_SIZE; i++) {
		if (fd_hash[slot].fd == -1)
			return NULL;
		if (fd_hash[slot].fd == fd)
			return &fd_hash[slot];
		slot = (slot + 1) & (FD_HASH_SIZE - 1);
	}
	return NULL;
}

static bool is_fd_type(enum objecttype type)
{
	return type >= OBJ_FD_PIPE && type <= OBJ_FD_PIDFD;
}

struct object * alloc_object(void)
{
	struct object *obj;
	obj = zmalloc(sizeof(struct object));
	INIT_LIST_HEAD(&obj->list);
	return obj;
}

struct objhead * get_objhead(bool global, enum objecttype type)
{
	struct objhead *head;

	if (global == OBJ_GLOBAL)
		head = &shm->global_objects[type];
	else {
		struct childdata *child;

		child = this_child();
		head = &child->objects[type];
	}
	return head;
}


void add_object(struct object *obj, bool global, enum objecttype type)
{
	struct objhead *head;

	head = get_objhead(global, type);
	if (head->list == NULL) {
		head->list = zmalloc(sizeof(struct object));
		INIT_LIST_HEAD(head->list);
	}

	list_add_tail(&obj->list, head->list);

	/* Grow parallel array if needed */
	if (head->num_entries >= head->array_capacity) {
		struct object **newarray;
		unsigned int newcap;

		newcap = head->array_capacity ? head->array_capacity * 2 : 16;
		newarray = realloc(head->array, newcap * sizeof(struct object *));
		if (newarray == NULL)
			return;
		head->array = newarray;
		head->array_capacity = newcap;
	}
	head->array[head->num_entries] = obj;
	obj->array_idx = head->num_entries;

	head->num_entries++;

	/* Track global fd-type objects in the hash table */
	if (global == OBJ_GLOBAL && is_fd_type(type)) {
		int fd = fd_from_object(obj, type);
		fd_hash_insert(fd, obj, type);
	}

	if (head->dump != NULL)
		head->dump(obj, global);

	/* if we just added something to a child list, check
	 * to see if we need to do some pruning.
	 */
	if (global == OBJ_LOCAL)
		prune_objects();
}

void init_object_lists(bool global)
{
	unsigned int i;

	for (i = 0; i < MAX_OBJECT_TYPES; i++) {
		struct objhead *head;

		head = get_objhead(global, i);

		head->list = NULL;
		head->array = NULL;
		head->num_entries = 0;
		head->array_capacity = 0;

		/*
		 * child lists can inherit properties from global lists.
		 */
		if (global == OBJ_LOCAL) {
			struct objhead *globalhead;
			globalhead = get_objhead(OBJ_GLOBAL, i);
			head->max_entries = globalhead->max_entries;
			head->destroy = globalhead->destroy;
			head->dump = globalhead->dump;
		}
	}
}

struct object * get_random_object(enum objecttype type, bool global)
{
	struct objhead *head;

	head = get_objhead(global, type);

	if (head->num_entries == 0)
		return NULL;

	return head->array[rand() % head->num_entries];
}

bool objects_empty(enum objecttype type)
{
	return shm->global_objects[type].num_entries == 0;
}

/*
 * Call the destructor for this object, and then release it.
 */
void destroy_object(struct object *obj, bool global, enum objecttype type)
{
	struct objhead *head;
	unsigned int idx, last;

	list_del(&obj->list);

	head = get_objhead(global, type);

	/* Swap-with-last removal from the parallel array */
	idx = obj->array_idx;
	last = head->num_entries - 1;
	if (idx != last) {
		head->array[idx] = head->array[last];
		head->array[idx]->array_idx = idx;
	}
	head->array[last] = NULL;

	head->num_entries--;

	/* Remove from fd hash table */
	if (global == OBJ_GLOBAL && is_fd_type(type))
		fd_hash_remove(fd_from_object(obj, type));

	if (head->destroy != NULL)
		head->destroy(obj);

	free(obj);
}

/*
 * Destroy a whole list of objects.
 */
static void destroy_objects(enum objecttype type, bool global)
{
	struct list_head *node, *list, *tmp;
	struct objhead *head;

	if (objects_empty(type) == true)
		return;

	head = get_objhead(global, type);
	list = head->list;

	list_for_each_safe(node, tmp, list) {
		struct object *obj;

		obj = (struct object *) node;

		destroy_object(obj, global, type);
	}

	head->num_entries = 0;
	free(head->array);
	head->array = NULL;
	head->array_capacity = 0;
}

/* Destroy all the global objects.
 *
 * We close this before quitting. All OBJ_LOCAL's got destroyed
 * when the children exited, leaving just these OBJ_GLOBALs
 * to clean up.
 */
void destroy_global_objects(void)
{
	unsigned int i;

	for (i = 0; i < MAX_OBJECT_TYPES; i++)
		destroy_objects(i, OBJ_GLOBAL);
}

/*
 * Extract the fd from an object, given its type.
 * Returns -1 for non-fd object types.
 */
int fd_from_object(struct object *obj, enum objecttype type)
{
	switch (type) {
	case OBJ_FD_PIPE:	return obj->pipeobj.fd;
	case OBJ_FD_FILE:	return obj->fileobj.fd;
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
	default:		return -1;
	}
}

/*
 * Look up an fd in the hash table and destroy its object.
 * Called after a successful close() or dup2() to keep the pool in sync.
 */
void remove_object_by_fd(int fd)
{
	struct fd_hash_entry *entry;

	entry = fd_hash_lookup(fd);
	if (entry == NULL)
		return;

	__atomic_add_fetch(&shm->stats.fd_closed_tracked, 1, __ATOMIC_RELAXED);
	destroy_object(entry->obj, OBJ_GLOBAL, entry->type);
	try_regenerate_fd(entry->type);
}

/*
 * Think of this as a poor mans garbage collector, to prevent
 * us from exhausting all the available fd's in the system etc.
 */
static void __prune_objects(enum objecttype type, bool global)
{
	struct objhead *head;
	unsigned int num_to_prune;

	if (RAND_BOOL())
		return;

	head = get_objhead(global, type);

	/* 0 = don't ever prune. */
	if (head->max_entries == 0)
		return;

	/* only prune full lists. */
	if (head->num_entries < head->max_entries)
		return;

	num_to_prune = rand() % head->num_entries;

	while (num_to_prune > 0) {
		struct list_head *node, *list, *tmp;

		list = head->list;

		list_for_each_safe(node, tmp, list) {
			if (ONE_IN(10)) {
				struct object *obj;

				obj = (struct object *) node;
				destroy_object(obj, global, type);
				num_to_prune--;
				//TODO: log something
			}
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
