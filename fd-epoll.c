/* epoll related fds */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include "epoll.h"
#include "log.h"
#include "net.h"
#include "params.h"
#include "pids.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

void open_epoll_fds(void)
{
	unsigned int i = 0;
	int fd = -1;

	while (i < MAX_EPOLL_FDS) {

		if (rand_bool())
			fd = epoll_create(1);
		else
			fd = epoll_create1(EPOLL_CLOEXEC);

		if (fd != -1) {
			shm->epoll_fds[i] = fd;
			output(2, "fd[%d] = epoll\n", shm->epoll_fds[i]);
			i++;
		}
	}
}

int rand_epoll_fd(void)
{
	return shm->epoll_fds[rand() % MAX_EPOLL_FDS];
}
