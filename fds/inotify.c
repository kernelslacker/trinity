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

static int create_inotify(unsigned int i, int flags)
{
	int fd;

	fd = inotify_init1(flags);
	if (fd != -1) {
		output(2, "fd[%d] = inotify(%d)\n", fd, flags);
		shm->inotify_fds[i] = fd;
		return TRUE;
	} else {
		output(0, "create_inotify fail: %s\n", strerror(errno));
		return FALSE;
	}
}

static int open_inotify_fds(void)
{
	int ret;

	shm->inotify_fds[0] = inotify_init();
	ret = create_inotify(1, 0);
	if (ret == FALSE)
		return FALSE;

	ret = create_inotify(2, IN_NONBLOCK);
	if (ret == FALSE)
		return FALSE;

	ret = create_inotify(3, IN_CLOEXEC);
	if (ret == FALSE)
		return FALSE;

	ret = create_inotify(4, IN_NONBLOCK | IN_CLOEXEC);
	if (ret == FALSE)
		return FALSE;

	return TRUE;
}

static int get_rand_inotify_fd(void)
{
	return shm->inotify_fds[rand() % MAX_INOTIFY_FDS];
}

const struct fd_provider inotify_fd_provider = {
	.name = "inotify",
	.enabled = TRUE,
	.open = &open_inotify_fds,
	.get = &get_rand_inotify_fd,
};
