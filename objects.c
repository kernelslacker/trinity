#include "fd.h"
#include "list.h"
#include "objects.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

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
	head->num_entries++;

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
		head->num_entries = 0;

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
	struct list_head *node, *list;
	unsigned int i, j = 0, n;

	head = get_objhead(global, type);

	list = head->list;

	n = head->num_entries;
	if (n == 0)
		return NULL;
	i = rnd() % n;

	list_for_each(node, list) {
		struct object *m;

		m = (struct object *) node;

		if (i == j)
			return m;
		j++;
	}
	return NULL;
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

	list_del(&obj->list);

	head = get_objhead(global, type);
	head->num_entries--;

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

	if (objects_empty(type) == TRUE)
		return;

	head = get_objhead(global, type);
	list = head->list;

	list_for_each_safe(node, tmp, list) {
		struct object *obj;

		obj = (struct object *) node;

		destroy_object(obj, global, type);
	}

	head->num_entries = 0;
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
	case OBJ_FD_IO_URING:	return obj->io_uringobj.fd;
	case OBJ_FD_LANDLOCK:	return obj->landlockobj.fd;
	case OBJ_FD_PIDFD:	return obj->pidfdobj.fd;
	default:		return -1;
	}
}

/*
 * Scan all fd-type object pools and destroy any object holding this fd.
 * Called after a successful close() or dup2() to keep the pool in sync.
 */
void remove_object_by_fd(int fd)
{
	static const enum objecttype fd_types[] = {
		OBJ_FD_PIPE, OBJ_FD_FILE, OBJ_FD_PERF, OBJ_FD_EPOLL,
		OBJ_FD_EVENTFD, OBJ_FD_TIMERFD, OBJ_FD_TESTFILE,
		OBJ_FD_MEMFD, OBJ_FD_DRM, OBJ_FD_INOTIFY, OBJ_FD_SOCKET,
		OBJ_FD_USERFAULTFD, OBJ_FD_FANOTIFY, OBJ_FD_BPF_MAP,
		OBJ_FD_BPF_PROG, OBJ_FD_IO_URING, OBJ_FD_LANDLOCK,
		OBJ_FD_PIDFD,
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(fd_types); i++) {
		struct objhead *head;
		struct list_head *node, *tmp;

		head = get_objhead(OBJ_GLOBAL, fd_types[i]);
		if (head->list == NULL || head->num_entries == 0)
			continue;

		list_for_each_safe(node, tmp, head->list) {
			struct object *obj = (struct object *) node;

			if (fd_from_object(obj, fd_types[i]) == fd) {
				destroy_object(obj, OBJ_GLOBAL, fd_types[i]);
				try_regenerate_fd(fd_types[i]);
				return;
			}
		}
	}
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

	num_to_prune = rnd() % head->num_entries;

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
