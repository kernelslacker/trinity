/* eventfd FDs */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include "eventfd.h"
#include "files.h"
#include "log.h"
#include "net.h"
#include "params.h"
#include "pids.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "compat.h"

void open_eventfd_fds(void)
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

	for (i = 0; i < MAX_EVENTFD_FDS; i++)
		output(2, "fd[%d] = eventfd\n", shm->eventfd_fds[i]);
}

int rand_eventfd_fd(void)
{
	return shm->eventfd_fds[rand() % MAX_EVENTFD_FDS];
}
