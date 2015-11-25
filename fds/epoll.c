/* epoll related fds */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>

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
			struct object *obj;

			obj = alloc_object();
			obj->perffd = fd;
			add_object(obj, OBJ_GLOBAL, OBJ_FD_EPOLL);

			output(2, "fd[%d] = epoll\n", fd);
			i++;
		} else {
			/* not sure what happened. */
			output(0, "open_epoll_fds fail: %s\n", strerror(errno));
			return FALSE;
		}
	}
	return TRUE;
}

static int get_rand_epoll_fd(void)
{
	struct object *obj;

	obj = get_random_object(OBJ_FD_EPOLL, OBJ_GLOBAL);
	return obj->epollfd;
}

const struct fd_provider epoll_fd_provider = {
	.name = "epoll",
	.enabled = TRUE,
	.open = &open_epoll_fds,
	.get = &get_rand_epoll_fd,
};
