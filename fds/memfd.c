/* memfd FDs */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include "fd.h"
#include "memfd.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "compat.h"
#include "trinity.h"

#ifndef USE_MEMFD_CREATE

#ifndef memfd_create
static int memfd_create(__unused__ const char *uname, __unused__ unsigned int flag)
{
#ifdef SYS_memfd_create
	return syscall(SYS_memfd_create, uname, flag);
#else
	return -ENOSYS;
#endif
}
#endif
#endif

static void memfd_destructor(struct object *obj)
{
	free(obj->memfdobj.name);
	close(obj->memfdobj.fd);
}

static void memfd_dump(struct object *obj, bool global)
{
	struct memfdobj *mo = &obj->memfdobj;

	output(2, "memfd fd:%d name:%s flags:%x global:%d\n",
		mo->fd, mo->name, mo->flags, global);
}

static int open_memfd_fds(void)
{
	struct objhead *head;
	unsigned int i;
	unsigned int flags[] = {
		0,
		MFD_CLOEXEC,
		MFD_CLOEXEC | MFD_ALLOW_SEALING,
		MFD_ALLOW_SEALING, MFD_HUGETLB,
	};

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_MEMFD);
	head->destroy = &memfd_destructor;
	head->dump = &memfd_dump;

	for (i = 0; i < ARRAY_SIZE(flags); i++) {
		struct object *obj;
		char namestr[] = "memfdN";
		int fd;

		sprintf(namestr, "memfd%u", i + 1);

		fd = memfd_create(namestr, flags[i]);
		if (fd < 0)
			continue;

		obj = alloc_object();
		obj->memfdobj.fd = fd;
		obj->memfdobj.name = strdup(namestr);
		obj->memfdobj.flags = flags[i];
		add_object(obj, OBJ_GLOBAL, OBJ_FD_MEMFD);
	}

	//FIXME: right now, returning FALSE means "abort everything", not
	// "skip this provider", so on -ENOSYS, we have to still register.

	return TRUE;
}

static int get_rand_memfd_fd(void)
{
	struct object *obj;

	/* check if eventfd unavailable/disabled. */
	if (objects_empty(OBJ_FD_MEMFD) == TRUE)
		return -1;

	obj = get_random_object(OBJ_FD_MEMFD, OBJ_GLOBAL);
	return obj->memfdobj.fd;
}

static const struct fd_provider memfd_fd_provider = {
	.name = "memfd",
	.enabled = TRUE,
	.open = &open_memfd_fds,
	.get = &get_rand_memfd_fd,
};

REG_FD_PROV(memfd_fd_provider);
