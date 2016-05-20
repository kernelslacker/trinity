/* fanotify FDs */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fd.h"
#include "log.h"
#include "fanotify.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "compat.h"
#include "trinity.h"
#include "utils.h"

#define NR_INOTIFYFDS 10

static int fanotify_init(__unused__ unsigned int flags, __unused__ unsigned int eflags)
{
#ifdef SYS_fanotify_init
	return syscall(SYS_fanotify_init, flags, eflags);
#else
	return -ENOSYS;
#endif
}

static void fanotifyfd_destructor(struct object *obj)
{
	close(obj->fanotifyfd);
}

static int open_fanotify_fds(void)
{
	struct objhead *head;
	unsigned int i;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_FANOTIFY);
	head->destroy = &fanotifyfd_destructor;

	for (i = 0; i < NR_INOTIFYFDS; i++) {
		struct object *obj;
		unsigned long flags, eventflags;
		int fd;

		eventflags = get_fanotify_init_event_flags();
		flags = get_fanotify_init_flags();
		fd = fanotify_init(flags, eventflags);
		if (fd < 0)
			continue;

		obj = alloc_object();
		obj->fanotifyfd = fd;
		add_object(obj, OBJ_GLOBAL, OBJ_FD_FANOTIFY);

		output(2, "fd[%d] = fanotify_init(%lx, %lx)\n", fd, flags, eventflags);
	}

	//FIXME: right now, returning FALSE means "abort everything", not
	// "skip this provider", so on -ENOSYS, we have to still register.

	return TRUE;
}

static int get_rand_fanotifyfd(void)
{
	struct object *obj;

	/* check if eventfd unavailable/disabled. */
	if (objects_empty(OBJ_FD_FANOTIFY) == TRUE)
		return -1;

	obj = get_random_object(OBJ_FD_FANOTIFY, OBJ_GLOBAL);
	return obj->fanotifyfd;
}

static const struct fd_provider fanotify_fd_provider = {
	.name = "fanotify",
	.enabled = TRUE,
	.open = &open_fanotify_fds,
	.get = &get_rand_fanotifyfd,
};

REG_FD_PROV(fanotify_fd_provider);
