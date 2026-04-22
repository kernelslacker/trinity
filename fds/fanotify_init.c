/* fanotify FDs */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fd.h"
#include "fanotify.h"
#include "list.h"
#include "objects.h"
#include "sanitise.h"
#include "shm.h"
#include "compat.h"
#include "trinity.h"
#include "utils.h"

#define NR_FANOTIFYFDS 10

static int fanotify_init(__unused__ unsigned int flags, __unused__ unsigned int eflags)
{
#ifdef SYS_fanotify_init
	return syscall(SYS_fanotify_init, flags, eflags);
#else
	return -ENOSYS;
#endif
}

static void fanotifyfd_destructor(struct object *obj)
{
	close(obj->fanotifyobj.fd);
}

/*
 * Cross-process safe: only reads obj->fanotifyobj fields (now in shm
 * via alloc_shared_obj) and the scope scalar.  No process-local
 * pointers are dereferenced, so it is correct to call this from a
 * different process than the one that allocated the obj.
 */
static void fanotifyfd_dump(struct object *obj, enum obj_scope scope)
{
	struct fanotifyobj *fo = &obj->fanotifyobj;

	output(2, "fanotify fd:%d flags:%x eventflags:%x scope:%d\n",
		fo->fd, fo->flags, fo->eventflags, scope);
}

static int open_fanotify_fd(void)
{
	struct object *obj;
	unsigned long flags, eventflags;
	int fd;

	eventflags = get_fanotify_init_event_flags();
	flags = get_fanotify_init_flags();
	fd = fanotify_init(flags, eventflags);
	if (fd < 0)
		return false;

	obj = alloc_shared_obj(sizeof(struct object));
	if (obj == NULL) {
		close(fd);
		return false;
	}
	INIT_LIST_HEAD(&obj->list);
	obj->fanotifyobj.fd = fd;
	obj->fanotifyobj.flags = flags;
	obj->fanotifyobj.eventflags = eventflags;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_FANOTIFY);
	return true;
}

static int init_fanotify_fds(void)
{
	struct objhead *head;
	unsigned int i;
	int ret = false;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_FANOTIFY);
	head->destroy = &fanotifyfd_destructor;
	head->dump = &fanotifyfd_dump;
	/*
	 * Opt this provider into the shared obj heap.  __destroy_object()
	 * checks this flag to route the obj struct release through
	 * free_shared_obj() instead of free().  fanotifyobj is
	 * {int fd; int flags; int eventflags;} with no pointer members,
	 * so this is a mechanical conversion matching the pidfd template.
	 */
	head->shared_alloc = true;

	for (i = 0; i < NR_FANOTIFYFDS; i++) {
		if (open_fanotify_fd())
			ret = true;
	}

	return ret;
}

static int get_rand_fanotifyfd(void)
{
	struct object *obj;

	/* check if fanotify unavailable/disabled. */
	if (objects_empty(OBJ_FD_FANOTIFY) == true)
		return -1;

	obj = get_random_object(OBJ_FD_FANOTIFY, OBJ_GLOBAL);
	if (obj == NULL)
		return -1;
	return obj->fanotifyobj.fd;
}

static const struct fd_provider fanotify_fd_provider = {
	.name = "fanotify",
	.objtype = OBJ_FD_FANOTIFY,
	.enabled = true,
	.init = &init_fanotify_fds,
	.get = &get_rand_fanotifyfd,
	.open = &open_fanotify_fd,
};

REG_FD_PROV(fanotify_fd_provider);
