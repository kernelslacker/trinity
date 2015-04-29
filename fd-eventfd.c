/* eventfd FDs */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/eventfd.h>

#include "eventfd.h"
#include "fd.h"
#include "files.h"
#include "log.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "compat.h"

static int open_eventfd_fds(void)
{
	unsigned int i;

	shm->eventfd_fds[0] = eventfd(rand32(), 0);
	shm->eventfd_fds[1] = eventfd(rand32(), EFD_CLOEXEC);
	shm->eventfd_fds[2] = eventfd(rand32(), EFD_NONBLOCK);
	shm->eventfd_fds[3] = eventfd(rand32(), EFD_SEMAPHORE);
	shm->eventfd_fds[4] = eventfd(rand32(), EFD_CLOEXEC | EFD_NONBLOCK);
	shm->eventfd_fds[5] = eventfd(rand32(), EFD_CLOEXEC | EFD_SEMAPHORE);
	shm->eventfd_fds[6] = eventfd(rand32(), EFD_NONBLOCK | EFD_SEMAPHORE);
	shm->eventfd_fds[7] = eventfd(rand32(), EFD_CLOEXEC | EFD_NONBLOCK | EFD_SEMAPHORE);
	// Check for ENOSYS

	for (i = 0; i < MAX_EVENTFD_FDS; i++)
		output(2, "fd[%d] = eventfd\n", shm->eventfd_fds[i]);

	return TRUE;
}

static int get_rand_eventfd_fd(void)
{
	return shm->eventfd_fds[rand() % MAX_EVENTFD_FDS];
}

const struct fd_provider eventfd_fd_provider = {
	.name = "eventfd",
	.enabled = TRUE,
	.open = &open_eventfd_fds,
	.get = &get_rand_eventfd_fd,
};
