/* memfd FDs */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fd.h"
#include "log.h"
#include "memfd.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "compat.h"
#include "trinity.h"

static int memfd_create(__unused__ const char *uname, __unused__ unsigned int flag)
{
#ifdef SYS_memfd_create
	return syscall(SYS_memfd_create, uname, flag);
#else
	return -ENOSYS;
#endif
}

static int open_memfd_fds(void)
{
	unsigned int i;
	unsigned int flags[] = {
		0,
		MFD_CLOEXEC,
		MFD_CLOEXEC | MFD_ALLOW_SEALING,
		MFD_ALLOW_SEALING,
	};

	for (i = 0; i < ARRAY_SIZE(flags); i++) {
		struct object *obj;
		char namestr[] = "memfdN";
		int fd;

		sprintf(namestr, "memfd%d", i + 1);

		fd = memfd_create(namestr, flags[i]);
		if (fd < 0)
			continue;

		obj = alloc_object();
		obj->memfd = fd;
		add_object(obj, OBJ_GLOBAL, OBJ_FD_MEMFD);

		output(2, "fd[%d] = memfd\n", fd);
	}

	//FIXME: right now, returning FALSE means "abort everything", not
	// "skip this provider", so on -ENOSYS, we have to still register.

	return TRUE;
}

static int get_rand_memfd_fd(void)
{
	struct object *obj;

	/* check if eventfd unavailable/disabled. */
	if (no_objects(OBJ_FD_MEMFD) == TRUE)
		return -1;

	obj = get_random_object(OBJ_FD_MEMFD, OBJ_GLOBAL);
	return obj->memfd;
}

const struct fd_provider memfd_fd_provider = {
	.name = "memfd",
	.enabled = TRUE,
	.open = &open_memfd_fds,
	.get = &get_rand_memfd_fd,
};
