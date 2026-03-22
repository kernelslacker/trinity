/* io_uring FD provider. */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "fd.h"
#include "objects.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

static void io_uring_destructor(struct object *obj)
{
	close(obj->io_uringobj.fd);
}

static void io_uring_dump(struct object *obj, bool global)
{
	output(2, "io_uring fd:%d global:%d\n",
		obj->io_uringobj.fd, global);
}

static int open_io_uring_fds(void)
{
	struct objhead *head;
	struct object *obj;
	int fd;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_IO_URING);
	head->destroy = &io_uring_destructor;
	head->dump = &io_uring_dump;

#ifdef __NR_io_uring_setup
	{
		/*
		 * io_uring_setup(entries, params) needs a zeroed
		 * io_uring_params struct on the stack.  We only need
		 * 120 bytes (sizeof kernel struct), zero it all.
		 */
		unsigned char params[120];

		memset(params, 0, sizeof(params));

		fd = syscall(__NR_io_uring_setup, 4, params);
		if (fd < 0)
			return FALSE;

		obj = alloc_object();
		obj->io_uringobj.fd = fd;
		add_object(obj, OBJ_GLOBAL, OBJ_FD_IO_URING);
	}
#else
	(void)fd;
	(void)obj;
#endif

	return TRUE;
}

static int get_rand_io_uring_fd(void)
{
	struct object *obj;

	if (objects_empty(OBJ_FD_IO_URING) == TRUE)
		return -1;

	obj = get_random_object(OBJ_FD_IO_URING, OBJ_GLOBAL);
	return obj->io_uringobj.fd;
}

static const struct fd_provider io_uring_fd_provider = {
	.name = "io_uring",
	.objtype = OBJ_FD_IO_URING,
	.enabled = TRUE,
	.init = &open_io_uring_fds,
	.get = &get_rand_io_uring_fd,
};

REG_FD_PROV(io_uring_fd_provider);
