/* inotify related fds */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/inotify.h>

#include "inotify.h"
#include "fd.h"
#include "log.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"

static int open_inotify_fds(void)
{
	struct object *obj;
	unsigned int i;
	int fd;
	int flags[] = {
		0,
		IN_NONBLOCK,
		IN_CLOEXEC,
		IN_NONBLOCK | IN_CLOEXEC,
	};

	fd = inotify_init();
	if (fd < 0)
		return FALSE;

	obj = alloc_object();
	obj->inotifyfd = fd;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_INOTIFY);

	for (i = 0; i < ARRAY_SIZE(flags); i++) {
		fd = inotify_init1(flags[i]);
		if (fd < 0)
			return FALSE;

		obj = alloc_object();
		obj->inotifyfd = fd;
		add_object(obj, OBJ_GLOBAL, OBJ_FD_INOTIFY);
	}

	return TRUE;
}

static int get_rand_inotify_fd(void)
{
	struct object *obj;

	/* check if inotifyfd unavailable/disabled. */
	if (shm->global_objects[OBJ_FD_INOTIFY].num_entries == 0)
		return -1;

	obj = get_random_object(OBJ_FD_INOTIFY, OBJ_GLOBAL);
	return obj->inotifyfd;
}

const struct fd_provider inotify_fd_provider = {
	.name = "inotify",
	.enabled = TRUE,
	.open = &open_inotify_fds,
	.get = &get_rand_inotify_fd,
};
