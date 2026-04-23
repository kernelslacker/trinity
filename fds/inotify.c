/* inotify related fds */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/inotify.h>

#include "fd.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "utils.h"

static const char *watch_paths[] = {
	"/tmp", "/proc", "/sys", "/dev", "/dev/shm",
};

static const uint32_t watch_masks[] = {
	IN_ACCESS, IN_MODIFY, IN_ATTRIB, IN_CLOSE_WRITE,
	IN_CLOSE_NOWRITE, IN_OPEN, IN_MOVED_FROM, IN_MOVED_TO,
	IN_CREATE, IN_DELETE, IN_DELETE_SELF, IN_MOVE_SELF,
	IN_ALL_EVENTS,
};

/*
 * Add 1-3 random watches so the kernel actually has something
 * to monitor and can generate events on this inotify fd.
 */
static void arm_inotify(int fd)
{
	unsigned int i, count;

	count = 1 + (rand() % 3);
	for (i = 0; i < count; i++) {
		const char *path = watch_paths[rand() % ARRAY_SIZE(watch_paths)];
		uint32_t mask = watch_masks[rand() % ARRAY_SIZE(watch_masks)];

		/* OR in a second mask bit half the time */
		if (RAND_BOOL())
			mask |= watch_masks[rand() % ARRAY_SIZE(watch_masks)];

		inotify_add_watch(fd, path, mask);
	}
}

static void inotify_destructor(struct object *obj)
{
	close(obj->inotifyobj.fd);
}

/*
 * Cross-process safe: only reads obj->inotifyobj fields (now in shm
 * via alloc_shared_obj) and the scope scalar.  No process-local
 * pointers are dereferenced, so it is correct to call this from a
 * different process than the one that allocated the obj — which
 * matters because head->dump runs from dump_childdata() in the
 * parent's crash diagnostics path even when a child triggered the
 * crash.
 */
static void inotify_dump(struct object *obj, enum obj_scope scope)
{
	struct inotifyobj *io = &obj->inotifyobj;

	output(2, "inotify fd:%d flags:%x scope:%d\n", io->fd, io->flags, scope);
}

static int init_inotify_fds(void)
{
	struct objhead *head;
	struct object *obj;
	unsigned int i;
	int fd;
	int flags[] = {
		0,
		IN_NONBLOCK,
		IN_CLOEXEC,
		IN_NONBLOCK | IN_CLOEXEC,
	};

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_INOTIFY);
	head->destroy = &inotify_destructor;
	head->dump = &inotify_dump;
	/*
	 * Opt this provider into the shared obj heap.  __destroy_object()
	 * checks this flag to route the obj struct release through
	 * free_shared_obj() instead of free().  inotifyobj is {int fd; int flags;}
	 * with no pointer members, so this is a mechanical conversion that
	 * matches the pidfd template exactly.
	 */
	head->shared_alloc = true;

	fd = inotify_init();
	if (fd < 0)
		fd = inotify_init1(0);
	if (fd < 0)
		return false;

	arm_inotify(fd);

	obj = alloc_shared_obj(sizeof(struct object));
	if (obj == NULL) {
		close(fd);
		return false;
	}
	obj->inotifyobj.fd = fd;
	obj->inotifyobj.flags = 0;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_INOTIFY);

	for (i = 0; i < ARRAY_SIZE(flags); i++) {
		fd = inotify_init1(flags[i]);
		if (fd < 0)
			continue;

		arm_inotify(fd);

		obj = alloc_shared_obj(sizeof(struct object));
		if (obj == NULL) {
			close(fd);
			continue;
		}
		obj->inotifyobj.fd = fd;
		obj->inotifyobj.flags = flags[i];
		add_object(obj, OBJ_GLOBAL, OBJ_FD_INOTIFY);
	}

	return true;
}

static int get_rand_inotify_fd(void)
{
	struct object *obj;

	/* check if inotifyfd unavailable/disabled. */
	if (objects_empty(OBJ_FD_INOTIFY) == true)
		return -1;

	obj = get_random_object(OBJ_FD_INOTIFY, OBJ_GLOBAL);
	if (obj == NULL)
		return -1;
	return obj->inotifyobj.fd;
}

static int open_inotify_fd(void)
{
	struct object *obj;
	int fd, flags;

	flags = RAND_BOOL() ? IN_NONBLOCK : 0;
	if (RAND_BOOL())
		flags |= IN_CLOEXEC;

	fd = inotify_init1(flags);
	if (fd < 0)
		return false;

	arm_inotify(fd);

	obj = alloc_shared_obj(sizeof(struct object));
	if (obj == NULL) {
		close(fd);
		return false;
	}
	obj->inotifyobj.fd = fd;
	obj->inotifyobj.flags = flags;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_INOTIFY);
	return true;
}

static const struct fd_provider inotify_fd_provider = {
	.name = "inotify",
	.objtype = OBJ_FD_INOTIFY,
	.enabled = true,
	.init = &init_inotify_fds,
	.get = &get_rand_inotify_fd,
	.open = &open_inotify_fd,
};

REG_FD_PROV(inotify_fd_provider);
