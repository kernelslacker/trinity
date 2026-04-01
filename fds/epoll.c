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

static const uint32_t epoll_events[] = {
	EPOLLIN, EPOLLOUT, EPOLLRDHUP, EPOLLPRI,
	EPOLLET, EPOLLONESHOT,
};

/*
 * Register 1-3 random fds with the epoll instance so that
 * epoll_wait/epoll_pwait actually have something to monitor.
 */
static void arm_epoll(int epfd)
{
	unsigned int i, count;

	count = 1 + (rand() % 3);
	for (i = 0; i < count; i++) {
		struct epoll_event ev;
		int target_fd;
		unsigned int j, nbits;

		target_fd = get_random_fd();
		if (target_fd < 0)
			continue;

		/* Don't add an epoll fd to itself */
		if (target_fd == epfd)
			continue;

		ev.events = 0;
		nbits = 1 + (rand() % ARRAY_SIZE(epoll_events));
		for (j = 0; j < nbits; j++)
			ev.events |= epoll_events[rand() % ARRAY_SIZE(epoll_events)];
		ev.data.fd = target_fd;

		epoll_ctl(epfd, EPOLL_CTL_ADD, target_fd, &ev);
	}
}

static void epoll_destructor(struct object *obj)
{
	close(obj->epollobj.fd);
}

static void epoll_dump(struct object *obj, enum obj_scope scope)
{
	struct epollobj *eo = &obj->epollobj;

	output(2, "epoll fd:%d used create1?:%d flags:%x scope:%d\n",
		eo->fd, eo->create1, eo->flags, scope);
}

static int init_epoll_fds(void)
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
			obj->epollobj.create1 = false;
			obj->epollobj.flags = 0;
			fd = epoll_create(1);
		} else{
			obj->epollobj.create1 = true;
			obj->epollobj.flags = EPOLL_CLOEXEC;
			fd = epoll_create1(EPOLL_CLOEXEC);
		}

		if (fd != -1) {
			obj->epollobj.fd = fd;
			add_object(obj, OBJ_GLOBAL, OBJ_FD_EPOLL);
			arm_epoll(fd);
			i++;
			obj = NULL;	// alloc a new obj.
		} else {
			/* not sure what happened. */
			output(0, "init_epoll_fds fail: %s\n", strerror(errno));
			free(obj);
			return false;
		}
	}
	return true;
}

static int open_epoll_fd(void)
{
	struct object *obj;
	int fd;

	obj = alloc_object();
	if (RAND_BOOL()) {
		obj->epollobj.create1 = false;
		obj->epollobj.flags = 0;
		fd = epoll_create(1);
	} else {
		obj->epollobj.create1 = true;
		obj->epollobj.flags = EPOLL_CLOEXEC;
		fd = epoll_create1(EPOLL_CLOEXEC);
	}

	if (fd == -1) {
		free(obj);
		return false;
	}

	obj->epollobj.fd = fd;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_EPOLL);
	arm_epoll(fd);
	return true;
}

static int get_rand_epoll_fd(void)
{
	struct object *obj;

	if (objects_empty(OBJ_FD_EPOLL) == true)
		return -1;

	obj = get_random_object(OBJ_FD_EPOLL, OBJ_GLOBAL);
	if (obj == NULL)
		return -1;
	return obj->epollobj.fd;
}

static const struct fd_provider epoll_fd_provider = {
	.name = "epoll",
	.objtype = OBJ_FD_EPOLL,
	.enabled = true,
	.init = &init_epoll_fds,
	.get = &get_rand_epoll_fd,
	.open = &open_epoll_fd,
};

REG_FD_PROV(epoll_fd_provider);
