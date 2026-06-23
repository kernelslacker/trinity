/* Detached mount FDs (open_tree(OPEN_TREE_CLONE)). */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "compat.h"
#include "fd.h"
#include "syscall-gate.h"
#include "objects.h"
#include "publish_resource.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "utils.h"

#ifndef OPEN_TREE_CLONE
#define OPEN_TREE_CLONE		1
#endif

static int do_open_tree(void)
{
#ifdef __NR_open_tree
	return trinity_raw_syscall(__NR_open_tree, AT_FDCWD, "/tmp",
		       OPEN_TREE_CLONE | AT_RECURSIVE | AT_SYMLINK_NOFOLLOW);
#else
	errno = ENOSYS;
	return -1;
#endif
}

#define MOUNT_INIT_POOL 4

static int init_mount_fds(void)
{
	struct objhead *head;
	unsigned int i;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_MOUNT);
	head->destroy = &close_fd_destructor;
	head->dump = &generic_fd_dump;

	for (i = 0; i < MOUNT_INIT_POOL; i++) {
		struct object *obj;
		int fd;

		fd = do_open_tree();
		if (fd < 0)
			continue;

		obj = alloc_object();
		if (obj == NULL) {
			close(fd);
			return false;
		}
		obj->mountfdobj.fd = fd;
		add_object(obj, OBJ_GLOBAL, OBJ_FD_MOUNT);
	}

	return true;
}

static int get_rand_mount_fd(void)
{
	if (objects_empty(OBJ_FD_MOUNT) == true)
		return -1;

	/*
	 * Versioned slot pick + objpool_check() before the
	 * obj->mountfdobj.fd deref.  A version-validated object-slot read
	 * guards the lockless reader against a recycled object
	 * (cf. get_rand_socketinfo in fds/sockets.c).  Same OBJ_GLOBAL
	 * lockless-reader UAF window:
	 * between the lockless slot pick and the consumer's read of
	 * the mount fd handed to move_mount/open_tree/fsmount via the fd_provider .get callback,
	 * the parent can destroy the obj; release_obj() zeroes the chunk
	 * and routes it through deferred-free, so the stale slot pointer
	 * can read a zeroed or recycled chunk.
	 */
	for (int i = 0; i < 1000; i++) {
		struct object *obj;
		int fd;

		obj = get_random_object(OBJ_FD_MOUNT, OBJ_GLOBAL);
		if (!objpool_check(obj, OBJ_FD_MOUNT))
			continue;

		fd = obj->mountfdobj.fd;
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

void post_mount_fd(struct syscallrecord *rec)
{
	int fd = rec->retval;

	if ((long)rec->retval < 0)
		return;
	if (fd < 0 || fd >= (1 << 20))
		return;

	if (publish_resource(OBJ_FD_MOUNT, fd, NULL) == NULL)
		close(fd);
}

static const struct fd_provider mount_fd_provider = {
	.name = "mount",
	.objtype = OBJ_FD_MOUNT,
	.enabled = true,
	.init = &init_mount_fds,
	.get = &get_rand_mount_fd,
};

REG_FD_PROV(mount_fd_provider);
