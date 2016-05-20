/* epoll related fds */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>

#include "fd.h"
#include "log.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"

#define MAX_EPOLL_FDS 10

static void epoll_destructor(struct object *obj)
{
	close(obj->epollfd);
}

static int open_epoll_fds(void)
{
	struct objhead *head;
	unsigned int i = 0;
	int fd = -1;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_EPOLL);
	head->destroy = &epoll_destructor;

	while (i < MAX_EPOLL_FDS) {

		if (RAND_BOOL())
			fd = epoll_create(1);
		else
			fd = epoll_create1(EPOLL_CLOEXEC);

		if (fd != -1) {
			struct object *obj;

			obj = alloc_object();
			obj->epollfd = fd;
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

	if (objects_empty(OBJ_FD_EPOLL) == TRUE)
		return -1;

	obj = get_random_object(OBJ_FD_EPOLL, OBJ_GLOBAL);
	return obj->epollfd;
}

static const struct fd_provider epoll_fd_provider = {
	.name = "epoll",
	.enabled = TRUE,
	.open = &open_epoll_fds,
	.get = &get_rand_epoll_fd,
};

REG_FD_PROV(epoll_fd_provider);
