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

#define MAX_INOTIFY_FDS 5

static void inotify_destructor(struct object *obj)
{
	close(obj->inotifyobj.fd);
}

static void inotify_dump(struct object *obj, bool global)
{
	struct inotifyobj *io = &obj->inotifyobj;

	output(2, "inotify fd:%d flags:%x global:%d\n", io->fd, io->flags, global);
}

static int open_inotify_fds(void)
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
		return FALSE;

	obj = alloc_object();
	obj->inotifyobj.fd = fd;
	obj->inotifyobj.flags = 0;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_INOTIFY);

	for (i = 0; i < ARRAY_SIZE(flags); i++) {
		fd = inotify_init1(flags[i]);
		if (fd < 0)
			return FALSE;

		obj = alloc_object();
		obj->inotifyobj.fd = fd;
		obj->inotifyobj.flags = flags[i];
		add_object(obj, OBJ_GLOBAL, OBJ_FD_INOTIFY);
	}

	return TRUE;
}

static int get_rand_inotify_fd(void)
{
	struct object *obj;

	/* check if inotifyfd unavailable/disabled. */
	if (objects_empty(OBJ_FD_INOTIFY) == TRUE)
		return -1;

	obj = get_random_object(OBJ_FD_INOTIFY, OBJ_GLOBAL);
	return obj->inotifyobj.fd;
}

static const struct fd_provider inotify_fd_provider = {
	.name = "inotify",
	.enabled = TRUE,
	.open = &open_inotify_fds,
	.get = &get_rand_inotify_fd,
};

REG_FD_PROV(inotify_fd_provider);
