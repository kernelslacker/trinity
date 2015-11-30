/* timerfd FDs */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/timerfd.h>

#include "timerfd.h"
#include "fd.h"
#include "files.h"
#include "log.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "compat.h"

static int __open_timerfd_fds(int clockid)
{
	unsigned int i;
	unsigned int flags[] = {
		0,
		TFD_NONBLOCK,
		TFD_CLOEXEC,
		TFD_NONBLOCK | TFD_CLOEXEC,
	};

	for (i = 0; i < ARRAY_SIZE(flags); i++) {
		struct object *obj;
		int fd;

		fd = timerfd_create(clockid, flags[i]);
		if (fd == -1)
			if (errno == ENOSYS)
				return FALSE;

		obj = alloc_object();
		obj->timerfd = fd;
		add_object(obj, OBJ_GLOBAL, OBJ_FD_TIMERFD);
		output(2, "fd[%d] = timerfd\n", fd);
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
	if (no_objects(OBJ_FD_TIMERFD) == TRUE)
		return -1;

	obj = get_random_object(OBJ_FD_TIMERFD, OBJ_GLOBAL);
	return obj->timerfd;
}

const struct fd_provider timerfd_fd_provider = {
	.name = "timerfd",
	.enabled = TRUE,
	.open = &open_timerfd_fds,
	.get = &get_rand_timerfd_fd,
};
