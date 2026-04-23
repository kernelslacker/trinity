/* timerfd FDs */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/timerfd.h>

#include "fd.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "utils.h"
#include "compat.h"

static void timerfd_destructor(struct object *obj)
{
	close(obj->timerfdobj.fd);
}

/*
 * Cross-process safe: only reads obj->timerfdobj fields (now in shm
 * via alloc_shared_obj) and the scope scalar.  No process-local
 * pointers are dereferenced, so it is correct to call this from a
 * different process than the one that allocated the obj — which
 * matters because head->dump runs from dump_childdata() in the
 * parent's crash diagnostics path even when a child triggered the
 * crash.
 */
static void timerfd_dump(struct object *obj, enum obj_scope scope)
{
	struct timerfdobj *to = &obj->timerfdobj;

	output(2, "timerfd fd:%d clockid:%d flags:%x scope:%d\n", to->fd, to->clockid, to->flags, scope);
}

/*
 * Arm a timerfd with a random expiration so the kernel actually
 * processes timer events when this fd is used in read/poll/epoll.
 */
static void arm_timerfd(int fd)
{
	struct itimerspec its;

	memset(&its, 0, sizeof(its));

	switch (rand() % 4) {
	case 0:
		/* One-shot, fires soon */
		its.it_value.tv_sec = 0;
		its.it_value.tv_nsec = 1 + (rand() % 999999999);
		break;
	case 1:
		/* Repeating, short interval */
		its.it_value.tv_sec = 0;
		its.it_value.tv_nsec = 1000;
		its.it_interval.tv_sec = 0;
		its.it_interval.tv_nsec = 1000 + (rand() % 999999);
		break;
	case 2:
		/* One-shot, fires in 1-5 seconds */
		its.it_value.tv_sec = 1 + (rand() % 5);
		break;
	case 3:
		/* Repeating, 1 second interval */
		its.it_value.tv_sec = 1;
		its.it_interval.tv_sec = 1;
		break;
	}

	timerfd_settime(fd, 0, &its, NULL);
}

static int __init_timerfd_fds(int clockid)
{
	struct objhead *head;
	unsigned int i;
	unsigned int flags[] = {
		0,
		TFD_NONBLOCK,
		TFD_CLOEXEC,
		TFD_NONBLOCK | TFD_CLOEXEC,
	};

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_TIMERFD);
	head->destroy = &timerfd_destructor;
	head->dump = &timerfd_dump;
	/*
	 * Opt this provider into the shared obj heap.  __destroy_object()
	 * checks this flag to route the obj struct release through
	 * free_shared_obj() instead of free().  timerfdobj is {int fd;
	 * int clockid; int flags;} — no pointer members — so the migration
	 * is mechanical and scoped entirely to this file.
	 */
	head->shared_alloc = true;

	for (i = 0; i < ARRAY_SIZE(flags); i++) {
		struct object *obj;
		int fd;

		fd = timerfd_create(clockid, flags[i]);
		if (fd == -1) {
			if (errno == ENOSYS)
				return false;
			continue;
		}

		arm_timerfd(fd);

		obj = alloc_shared_obj(sizeof(struct object));
		if (obj == NULL) {
			close(fd);
			continue;
		}
		obj->timerfdobj.fd = fd;
		obj->timerfdobj.clockid = clockid;
		obj->timerfdobj.flags = flags[i];
		add_object(obj, OBJ_GLOBAL, OBJ_FD_TIMERFD);
	}
	return true;
}

static int init_timerfd_fds(void)
{
	int ret;
	ret = __init_timerfd_fds(CLOCK_REALTIME);
	if (ret != false)
		ret = __init_timerfd_fds(CLOCK_MONOTONIC);
	if (ret != false)
		ret = __init_timerfd_fds(CLOCK_BOOTTIME);
	if (ret != false)
		ret = __init_timerfd_fds(CLOCK_REALTIME_ALARM);
	if (ret != false)
		ret = __init_timerfd_fds(CLOCK_BOOTTIME_ALARM);

	return ret;
}

static int get_rand_timerfd_fd(void)
{
	struct object *obj;

	/* check if timerfd unavailable/disabled. */
	if (objects_empty(OBJ_FD_TIMERFD) == true)
		return -1;

	obj = get_random_object(OBJ_FD_TIMERFD, OBJ_GLOBAL);
	if (obj == NULL)
		return -1;
	return obj->timerfdobj.fd;
}

static int open_timerfd_fd(void)
{
	struct object *obj;
	int fd, clockid = CLOCK_REALTIME, flags;

	switch (rand() % 5) {
	case 0: clockid = CLOCK_REALTIME; break;
	case 1: clockid = CLOCK_MONOTONIC; break;
	case 2: clockid = CLOCK_BOOTTIME; break;
	case 3: clockid = CLOCK_REALTIME_ALARM; break;
	case 4: clockid = CLOCK_BOOTTIME_ALARM; break;
	}
	flags = RAND_BOOL() ? TFD_NONBLOCK : 0;
	if (RAND_BOOL())
		flags |= TFD_CLOEXEC;

	fd = timerfd_create(clockid, flags);
	if (fd == -1)
		return false;

	arm_timerfd(fd);

	obj = alloc_shared_obj(sizeof(struct object));
	if (obj == NULL) {
		close(fd);
		return false;
	}
	obj->timerfdobj.fd = fd;
	obj->timerfdobj.clockid = clockid;
	obj->timerfdobj.flags = flags;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_TIMERFD);
	return true;
}

static const struct fd_provider timerfd_fd_provider = {
	.name = "timerfd",
	.objtype = OBJ_FD_TIMERFD,
	.enabled = true,
	.init = &init_timerfd_fds,
	.get = &get_rand_timerfd_fd,
	.open = &open_timerfd_fd,
};

REG_FD_PROV(timerfd_fd_provider);
