/* fs_context FDs (fsopen). */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "fd.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "utils.h"

#ifndef FSOPEN_CLOEXEC
#define FSOPEN_CLOEXEC 0x00000001
#endif

static void fsctx_destructor(struct object *obj)
{
	close(obj->fsctxobj.fd);
}

static void fsctx_dump(struct object *obj, enum obj_scope scope)
{
	output(2, "fs_ctx fd:%d scope:%d\n", obj->fsctxobj.fd, scope);
}

static int do_fsopen(const char *fstype, unsigned int flags)
{
#ifdef __NR_fsopen
	return syscall(__NR_fsopen, fstype, flags);
#else
	(void) fstype;
	(void) flags;
	errno = ENOSYS;
	return -1;
#endif
}

static const char *fsctx_fstypes[] = {
	"tmpfs",
	"ramfs",
	"proc",
};

static const unsigned int fsctx_flags[] = {
	0,
	FSOPEN_CLOEXEC,
};

static int init_fs_ctx_fds(void)
{
	struct objhead *head;
	unsigned int i, j;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_FS_CTX);
	head->destroy = &fsctx_destructor;
	head->dump = &fsctx_dump;
	head->shared_alloc = true;

	for (i = 0; i < ARRAY_SIZE(fsctx_fstypes); i++) {
		for (j = 0; j < ARRAY_SIZE(fsctx_flags); j++) {
			struct object *obj;
			int fd;

			fd = do_fsopen(fsctx_fstypes[i], fsctx_flags[j]);
			if (fd < 0) {
				/*
				 * Skip filesystems the kernel doesn't have
				 * (-ENODEV) or that we can't open in this
				 * userns/cap context (-EPERM).  Continue with
				 * other fstype/flag combinations.
				 */
				if (errno == ENODEV || errno == EPERM)
					break;
				continue;
			}

			obj = alloc_shared_obj(sizeof(struct object));
			if (obj == NULL) {
				close(fd);
				return false;
			}
			obj->fsctxobj.fd = fd;
			add_object(obj, OBJ_GLOBAL, OBJ_FD_FS_CTX);
		}
	}

	return true;
}

static int get_rand_fs_ctx_fd(void)
{
	if (objects_empty(OBJ_FD_FS_CTX) == true)
		return -1;

	/*
	 * Versioned slot pick + validate_object_handle() before the
	 * obj->fsctxobj.fd deref, mirroring the wireup at 15b6257b8206
	 * (fds/sockets.c get_rand_socketinfo) and 5ef98298f6ad
	 * (syscalls/keyctl.c KEYCTL_WATCH_KEY).  Same OBJ_GLOBAL lockless-
	 * reader UAF window the framework commit a7fdbb97830c spelled out:
	 * between the lockless slot pick and the consumer's read of
	 * the fs_context fd handed to fsconfig/fsmount via the fd_provider .get callback,
	 * the parent can destroy the obj, free_shared_obj() returns the
	 * chunk to the shared-heap freelist, and a concurrent
	 * alloc_shared_obj() recycles it underneath us.
	 */
	for (int i = 0; i < 1000; i++) {
		unsigned int slot_idx, slot_version;
		struct object *obj;
		int fd;

		obj = get_random_object_versioned(OBJ_FD_FS_CTX, OBJ_GLOBAL,
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
			outputerr("get_rand_fs_ctx_fd: bogus obj %p in "
				  "OBJ_FD_FS_CTX pool\n", obj);
			continue;
		}

		if (!validate_object_handle(OBJ_FD_FS_CTX, OBJ_GLOBAL, obj,
					    slot_idx, slot_version))
			continue;

		fd = obj->fsctxobj.fd;
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

static int open_fs_ctx_fd(void)
{
	struct object *obj;
	const char *fstype;
	unsigned int flags;
	int fd;

	fstype = fsctx_fstypes[rand() % ARRAY_SIZE(fsctx_fstypes)];
	flags = RAND_BOOL() ? FSOPEN_CLOEXEC : 0;

	fd = do_fsopen(fstype, flags);
	if (fd < 0)
		return false;

	obj = alloc_shared_obj(sizeof(struct object));
	if (obj == NULL) {
		close(fd);
		return false;
	}
	obj->fsctxobj.fd = fd;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_FS_CTX);
	return true;
}

static const struct fd_provider fs_ctx_fd_provider = {
	.name = "fs_ctx",
	.objtype = OBJ_FD_FS_CTX,
	.enabled = true,
	.init = &init_fs_ctx_fds,
	.get = &get_rand_fs_ctx_fd,
	.open = &open_fs_ctx_fd,
};

REG_FD_PROV(fs_ctx_fd_provider);
