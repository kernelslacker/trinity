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

static void inotify_dump(struct object *obj, bool global)
{
	struct inotifyobj *io = &obj->inotifyobj;

	output(2, "inotify fd:%d flags:%x global:%d\n", io->fd, io->flags, global);
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

	fd = inotify_init();
	if (fd < 0)
		return false;

	arm_inotify(fd);

	obj = alloc_object();
	obj->inotifyobj.fd = fd;
	obj->inotifyobj.flags = 0;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_INOTIFY);

	for (i = 0; i < ARRAY_SIZE(flags); i++) {
		fd = inotify_init1(flags[i]);
		if (fd < 0)
			return false;

		arm_inotify(fd);

		obj = alloc_object();
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

	obj = alloc_object();
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
