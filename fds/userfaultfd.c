/* userfaultfd FDs */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fd.h"
#include "userfaultfd.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "compat.h"
#include "trinity.h"

static int userfaultfd_create(__unused__ unsigned int flag)
{
#ifdef SYS_userfaultfd
	return syscall(SYS_userfaultfd, flag);
#else
	return -ENOSYS;
#endif
}

static void userfaultfd_destructor(struct object *obj)
{
	close(obj->userfaultobj.fd);
}

static void userfaultfd_dump(struct object *obj, bool global)
{
	struct userfaultobj *uo = &obj->userfaultobj;

	output(2, "userfault fd:%d flags:%x global:%d\n", uo->fd, uo->flags, global);
}

static int open_userfaultfds(void)
{
	struct objhead *head;
	unsigned int i;
	unsigned int flags[] = {
		0,
		O_CLOEXEC,
		O_NONBLOCK,
		O_CLOEXEC | O_NONBLOCK,
	};

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_USERFAULTFD);
	head->destroy = &userfaultfd_destructor;
	head->dump = &userfaultfd_dump;

	for (i = 0; i < ARRAY_SIZE(flags); i++) {
		struct object *obj;
		int fd;

		fd = userfaultfd_create(flags[i]);
		if (fd < 0)
			continue;

		obj = alloc_object();
		obj->userfaultobj.fd = fd;
		obj->userfaultobj.flags = flags[i];
		add_object(obj, OBJ_GLOBAL, OBJ_FD_USERFAULTFD);
	}

	//FIXME: right now, returning FALSE means "abort everything", not
	// "skip this provider", so on -ENOSYS, we have to still register.

	return TRUE;
}

static int get_rand_userfaultfd(void)
{
	struct object *obj;

	/* check if eventfd unavailable/disabled. */
	if (objects_empty(OBJ_FD_USERFAULTFD) == TRUE)
		return -1;

	obj = get_random_object(OBJ_FD_USERFAULTFD, OBJ_GLOBAL);
	return obj->userfaultobj.fd;
}

static const struct fd_provider userfaultfd_provider = {
	.name = "userfaultfd",
	.enabled = TRUE,
	.open = &open_userfaultfds,
	.get = &get_rand_userfaultfd,
};

REG_FD_PROV(userfaultfd_provider);
