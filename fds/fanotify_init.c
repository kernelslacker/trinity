/* fanotify FDs */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fd.h"
#include "fanotify.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "compat.h"
#include "trinity.h"
#include "utils.h"

#define NR_FANOTIFYFDS 10

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
	close(obj->fanotifyobj.fd);
}

static void fanotifyfd_dump(struct object *obj, bool global)
{
	struct fanotifyobj *fo = &obj->fanotifyobj;

	output(2, "fanotify fd:%d flags:%x eventflags:%x global:%d\n",
		fo->fd, fo->flags, fo->eventflags, global);
}

static int open_fanotify_fds(void)
{
	struct objhead *head;
	unsigned int i;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_FANOTIFY);
	head->destroy = &fanotifyfd_destructor;
	head->dump = &fanotifyfd_dump;

	for (i = 0; i < NR_FANOTIFYFDS; i++) {
		struct object *obj;
		unsigned long flags, eventflags;
		int fd;

		eventflags = get_fanotify_init_event_flags();
		flags = get_fanotify_init_flags();
		fd = fanotify_init(flags, eventflags);
		if (fd < 0)
			continue;

		obj = alloc_object();
		obj->fanotifyobj.fd = fd;
		obj->fanotifyobj.flags = flags;
		obj->fanotifyobj.eventflags = eventflags;
		add_object(obj, OBJ_GLOBAL, OBJ_FD_FANOTIFY);
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
	return obj->fanotifyobj.fd;
}

static const struct fd_provider fanotify_fd_provider = {
	.name = "fanotify",
	.enabled = TRUE,
	.open = &open_fanotify_fds,
	.get = &get_rand_fanotifyfd,
};

REG_FD_PROV(fanotify_fd_provider);
