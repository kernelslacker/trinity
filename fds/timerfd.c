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

static int open_timerfd_fds(void)
{
	unsigned int i;

	shm->timerfd_fds[0] = timerfd_create(CLOCK_REALTIME, 0);
	if (shm->timerfd_fds[0] == -1)
		if (errno == ENOSYS)
			return FALSE;

	shm->timerfd_fds[1] = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK);
	shm->timerfd_fds[2] = timerfd_create(CLOCK_REALTIME, TFD_CLOEXEC);
	shm->timerfd_fds[3] = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK | TFD_CLOEXEC);

	shm->timerfd_fds[4] = timerfd_create(CLOCK_MONOTONIC, 0);
	shm->timerfd_fds[5] = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
	shm->timerfd_fds[6] = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
	shm->timerfd_fds[7] = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);

	for (i = 0; i < MAX_TIMERFD_FDS; i++)
		output(2, "fd[%d] = timerfd\n", shm->timerfd_fds[i]);

	return TRUE;
}

static int get_rand_timerfd_fd(void)
{
	return shm->timerfd_fds[rand() % MAX_TIMERFD_FDS];
}

const struct fd_provider timerfd_fd_provider = {
	.name = "timerfd",
	.enabled = TRUE,
	.open = &open_timerfd_fds,
	.get = &get_rand_timerfd_fd,
};
