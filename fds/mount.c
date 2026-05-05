/* Detached mount FDs (open_tree(OPEN_TREE_CLONE)). */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "fd.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "utils.h"

#ifndef OPEN_TREE_CLONE
#define OPEN_TREE_CLONE		1
#endif
#ifndef AT_RECURSIVE
#define AT_RECURSIVE		0x8000
#endif

static void mount_destructor(struct object *obj)
{
	close(obj->mountfdobj.fd);
}

static void mount_dump(struct object *obj, enum obj_scope scope)
{
	output(2, "mount fd:%d scope:%d\n", obj->mountfdobj.fd, scope);
}

static int do_open_tree(void)
{
#ifdef __NR_open_tree
	return syscall(__NR_open_tree, AT_FDCWD, "/tmp",
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
	head->destroy = &mount_destructor;
	head->dump = &mount_dump;
	head->shared_alloc = true;

	for (i = 0; i < MOUNT_INIT_POOL; i++) {
		struct object *obj;
		int fd;

		fd = do_open_tree();
		if (fd < 0)
			continue;

		obj = alloc_shared_obj(sizeof(struct object));
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
	 * Versioned slot pick + validate_object_handle() before the
	 * obj->mountfdobj.fd deref, mirroring the wireup at 15b6257b8206
	 * (fds/sockets.c get_rand_socketinfo) and 5ef98298f6ad
	 * (syscalls/keyctl.c KEYCTL_WATCH_KEY).  Same OBJ_GLOBAL lockless-
	 * reader UAF window the framework commit a7fdbb97830c spelled out:
	 * between the lockless slot pick and the consumer's read of
	 * the mount fd handed to move_mount/open_tree/fsmount via the fd_provider .get callback,
	 * the parent can destroy the obj, free_shared_obj() returns the
	 * chunk to the shared-heap freelist, and a concurrent
	 * alloc_shared_obj() recycles it underneath us.
	 */
	for (int i = 0; i < 1000; i++) {
		unsigned int slot_idx, slot_version;
		struct object *obj;
		int fd;

		obj = get_random_object_versioned(OBJ_FD_MOUNT, OBJ_GLOBAL,
						  &slot_idx, &slot_version);
		if (obj == NULL)
			continue;

		/*
		 * Heap pointers land at >= 0x10000 and below the 47-bit
		 * user/kernel boundary; anything outside that window can't
		 * be a real obj struct.  Reject before deref.
		 */
		if ((uintptr_t)obj < 0x10000UL ||
		    (uintptr_t)obj >= 0x800000000000UL) {
			outputerr("get_rand_mount_fd: bogus obj %p in "
				  "OBJ_FD_MOUNT pool\n", obj);
			continue;
		}

		if (!validate_object_handle(OBJ_FD_MOUNT, OBJ_GLOBAL, obj,
					    slot_idx, slot_version))
			continue;

		fd = obj->mountfdobj.fd;
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

static int open_mount_fd(void)
{
	struct object *obj;
	int fd;

	fd = do_open_tree();
	if (fd < 0)
		return false;

	obj = alloc_shared_obj(sizeof(struct object));
	if (obj == NULL) {
		close(fd);
		return false;
	}
	obj->mountfdobj.fd = fd;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_MOUNT);
	return true;
}

void post_mount_fd(struct syscallrecord *rec)
{
	struct object *new;
	int fd = rec->retval;

	if ((long)rec->retval < 0)
		return;
	if (fd < 0 || fd >= (1 << 20))
		return;

	new = alloc_object();
	new->mountfdobj.fd = fd;
	add_object(new, OBJ_LOCAL, OBJ_FD_MOUNT);
}

static const struct fd_provider mount_fd_provider = {
	.name = "mount",
	.objtype = OBJ_FD_MOUNT,
	.enabled = true,
	.init = &init_mount_fds,
	.get = &get_rand_mount_fd,
	.open = &open_mount_fd,
};

REG_FD_PROV(mount_fd_provider);
