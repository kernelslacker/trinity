/* eventfd FDs */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/eventfd.h>

#include "fd.h"
#include "files.h"
#include "log.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "compat.h"

static void eventfd_destructor(struct object *obj)
{
	close(obj->eventfd);
}

static int open_eventfd_fds(void)
{
	struct objhead *head;
	unsigned int i;
	unsigned int flags[] = {
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

	for (i = 0; i < ARRAY_SIZE(flags); i++) {
		struct object *obj;
		int fd;

		fd = eventfd(rand32(), flags[i]);
		if (fd < 0)
			continue;

		obj = alloc_object();
		obj->eventfd = fd;
		add_object(obj, OBJ_GLOBAL, OBJ_FD_EVENTFD);

		output(2, "fd[%d] = eventfd\n", fd);
	}

	return TRUE;
}

static int get_rand_eventfd_fd(void)
{
	struct object *obj;

	/* check if eventfd unavailable/disabled. */
	if (objects_empty(OBJ_FD_EVENTFD) == TRUE)
		return -1;

	obj = get_random_object(OBJ_FD_EVENTFD, OBJ_GLOBAL);
	return obj->eventfd;
}

static const struct fd_provider eventfd_fd_provider = {
	.name = "eventfd",
	.enabled = TRUE,
	.open = &open_eventfd_fds,
	.get = &get_rand_eventfd_fd,
};

REG_FD_PROV(eventfd_fd_provider);
