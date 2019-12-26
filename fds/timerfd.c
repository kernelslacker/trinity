/* timerfd FDs */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/timerfd.h>

#include "fd.h"
#include "files.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "compat.h"

static void timerfd_destructor(struct object *obj)
{
	close(obj->timerfdobj.fd);
}

static void timerfd_dump(struct object *obj, bool global)
{
	struct timerfdobj *to = &obj->timerfdobj;

	output(2, "timerfd fd:%d clockid:%d flags:%x global:%d\n", to->fd, to->clockid, to->flags, global);
}

static int __open_timerfd_fds(int clockid)
{
	struct objhead *head;
	unsigned int i;
	unsigned int flags[] = {
		0,
		TFD_NONBLOCK,
		TFD_CLOEXEC,
		TFD_NONBLOCK | TFD_CLOEXEC,
	};

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_TIMERFD);
	head->destroy = &timerfd_destructor;
	head->dump = &timerfd_dump;

	for (i = 0; i < ARRAY_SIZE(flags); i++) {
		struct object *obj;
		int fd;

		fd = timerfd_create(clockid, flags[i]);
		if (fd == -1)
			if (errno == ENOSYS)
				return FALSE;

		obj = alloc_object();
		obj->timerfdobj.fd = fd;
		obj->timerfdobj.clockid = clockid;
		obj->timerfdobj.flags = flags[i];
		add_object(obj, OBJ_GLOBAL, OBJ_FD_TIMERFD);
	}
	return TRUE;
}

static int open_timerfd_fds(void)
{
	int ret;
	ret = __open_timerfd_fds(CLOCK_REALTIME);
	if (ret != FALSE)
		ret = __open_timerfd_fds(CLOCK_MONOTONIC);

	return ret;
}

static int get_rand_timerfd_fd(void)
{
	struct object *obj;

	/* check if timerfd unavailable/disabled. */
	if (objects_empty(OBJ_FD_TIMERFD) == TRUE)
		return -1;

	obj = get_random_object(OBJ_FD_TIMERFD, OBJ_GLOBAL);
	return obj->timerfdobj.fd;
}

static const struct fd_provider timerfd_fd_provider = {
	.name = "timerfd",
	.enabled = TRUE,
	.open = &open_timerfd_fds,
	.get = &get_rand_timerfd_fd,
};

REG_FD_PROV(timerfd_fd_provider);
