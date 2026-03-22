/* eventfd FDs */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/eventfd.h>

#include "fd.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "compat.h"

static void eventfd_destructor(struct object *obj)
{
	close(obj->eventfdobj.fd);
}

static void eventfd_dump(struct object *obj, bool global)
{
	struct eventfdobj *eo = &obj->eventfdobj;

	output(2, "eventfd fd:%d count:%d flags:%x global:%d\n",
		eo->fd, eo->count, eo->flags, global);
}

static int init_eventfd_fds(void)
{
	struct objhead *head;
	unsigned int i;
	const unsigned int flags[] = {
		0,
		EFD_NONBLOCK,
		EFD_NONBLOCK | EFD_SEMAPHORE,
		EFD_CLOEXEC,
		EFD_CLOEXEC  | EFD_NONBLOCK,
		EFD_CLOEXEC  | EFD_SEMAPHORE,
		EFD_CLOEXEC  | EFD_NONBLOCK | EFD_SEMAPHORE,
		EFD_SEMAPHORE,
	};

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_EVENTFD);
	head->destroy = &eventfd_destructor;
	head->dump = &eventfd_dump;

	for (i = 0; i < ARRAY_SIZE(flags); i++) {
		struct object *obj;
		int fd;
		int count = rand32();

		fd = eventfd(count, flags[i]);
		if (fd < 0)
			continue;

		obj = alloc_object();
		obj->eventfdobj.fd = fd;
		obj->eventfdobj.count = count;
		obj->eventfdobj.flags = flags[i];
		add_object(obj, OBJ_GLOBAL, OBJ_FD_EVENTFD);
	}

	return true;
}

static int get_rand_eventfd_fd(void)
{
	struct object *obj;

	/* check if eventfd unavailable/disabled. */
	if (objects_empty(OBJ_FD_EVENTFD) == true)
		return -1;

	obj = get_random_object(OBJ_FD_EVENTFD, OBJ_GLOBAL);
	return obj->eventfdobj.fd;
}

static int open_eventfd_fd(void)
{
	struct object *obj;
	int fd, count, flags;

	count = rand32();
	flags = RAND_BOOL() ? EFD_NONBLOCK : 0;
	if (RAND_BOOL())
		flags |= EFD_CLOEXEC;
	if (RAND_BOOL())
		flags |= EFD_SEMAPHORE;

	fd = eventfd(count, flags);
	if (fd < 0)
		return false;

	obj = alloc_object();
	obj->eventfdobj.fd = fd;
	obj->eventfdobj.count = count;
	obj->eventfdobj.flags = flags;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_EVENTFD);
	return true;
}

static const struct fd_provider eventfd_fd_provider = {
	.name = "eventfd",
	.objtype = OBJ_FD_EVENTFD,
	.enabled = true,
	.init = &init_eventfd_fds,
	.get = &get_rand_eventfd_fd,
	.open = &open_eventfd_fd,
};

REG_FD_PROV(eventfd_fd_provider);
