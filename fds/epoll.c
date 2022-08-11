/* epoll related fds */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>

#include "fd.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"

#define MAX_EPOLL_FDS 10

static void epoll_destructor(struct object *obj)
{
	close(obj->epollobj.fd);
}

static void epoll_dump(struct object *obj, bool global)
{
	struct epollobj *eo = &obj->epollobj;

	output(2, "epoll fd:%d used create1?:%d flags:%x global:%d\n",
		eo->fd, eo->create1, eo->flags, global);
}

static int open_epoll_fds(void)
{
	struct object *obj = NULL;
	struct objhead *head;
	unsigned int i = 0;
	int fd = -1;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_EPOLL);
	head->destroy = &epoll_destructor;
	head->dump = &epoll_dump;

	while (i < MAX_EPOLL_FDS) {

		if (obj == NULL)
			obj = alloc_object();

		if (RAND_BOOL()) {
			obj->epollobj.create1 = FALSE;
			obj->epollobj.flags = 0;
			fd = epoll_create(1);
		} else{
			obj->epollobj.create1 = TRUE;
			obj->epollobj.flags = EPOLL_CLOEXEC;
			fd = epoll_create1(EPOLL_CLOEXEC);
		}

		if (fd != -1) {
			obj->epollobj.fd = fd;
			add_object(obj, OBJ_GLOBAL, OBJ_FD_EPOLL);
			i++;
			obj = NULL;	// alloc a new obj.
		} else {
			/* not sure what happened. */
			output(0, "open_epoll_fds fail: %s\n", strerror(errno));
			free(obj);
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
	return obj->epollobj.fd;
}

static const struct fd_provider epoll_fd_provider = {
	.name = "epoll",
	.enabled = TRUE,
	.open = &open_epoll_fds,
	.get = &get_rand_epoll_fd,
};

REG_FD_PROV(epoll_fd_provider);
