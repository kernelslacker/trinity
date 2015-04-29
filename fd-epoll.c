/* epoll related fds */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include "epoll.h"
#include "fd.h"
#include "log.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"

static int open_epoll_fds(void)
{
	unsigned int i = 0;
	int fd = -1;

	while (i < MAX_EPOLL_FDS) {

		if (RAND_BOOL())
			fd = epoll_create(1);
		else
			fd = epoll_create1(EPOLL_CLOEXEC);

		if (fd != -1) {
			shm->epoll_fds[i] = fd;
			output(2, "fd[%d] = epoll\n", shm->epoll_fds[i]);
			i++;
		} else {
			/* not sure what happened. */
			output(0, "epoll_create fail: %s\n", strerror(errno));
			return FALSE;
		}
	}
	return TRUE;
}

static int get_rand_epoll_fd(void)
{
	return shm->epoll_fds[rand() % MAX_EPOLL_FDS];
}

const struct fd_provider epoll_fd_provider = {
	.name = "epoll",
	.enabled = TRUE,
	.open = &open_epoll_fds,
	.get = &get_rand_epoll_fd,
};
