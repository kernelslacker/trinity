/* fs_context FDs (fsopen). */

#include <errno.h>
#include <sys/syscall.h>

#include "fd.h"
#include "syscall-gate.h"
#include "objects.h"
#include "publish_resource.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "utils.h"

#ifndef FSOPEN_CLOEXEC
#define FSOPEN_CLOEXEC 0x00000001
#endif

static int do_fsopen(const char *fstype, unsigned int flags)
{
#ifdef __NR_fsopen
	return trinity_raw_syscall(__NR_fsopen, fstype, flags);
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
	head->destroy = &close_fd_destructor;
	head->dump = &generic_fd_dump;

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

			obj = alloc_object();
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
	 * Versioned slot pick + objpool_check() before the
	 * obj->fsctxobj.fd deref.  A version-validated object-slot read
	 * guards the lockless reader against a recycled object
	 * (cf. get_rand_socketinfo in fds/sockets.c).  Same OBJ_GLOBAL
	 * lockless-reader UAF window:
	 * between the lockless slot pick and the consumer's read of
	 * the fs_context fd handed to fsconfig/fsmount via the fd_provider .get callback,
	 * the parent can destroy the obj; release_obj() zeroes the chunk
	 * and routes it through deferred-free, so the stale slot pointer
	 * can read a zeroed or recycled chunk.
	 */
	for (int i = 0; i < 1000; i++) {
		struct object *obj;
		int fd;

		obj = get_random_object(OBJ_FD_FS_CTX, OBJ_GLOBAL);
		if (!objpool_check(obj, OBJ_FD_FS_CTX))
			continue;

		fd = obj->fsctxobj.fd;
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

void post_fs_ctx_fd(struct syscallrecord *rec)
{
	int fd = rec->retval;

	if ((long)rec->retval < 0)
		return;
	if (fd < 0 || fd >= (1 << 20))
		return;

	if (publish_resource(OBJ_FD_FS_CTX, fd, NULL) == NULL)
		close(fd);
}

static const struct fd_provider fs_ctx_fd_provider = {
	.name = "fs_ctx",
	.objtype = OBJ_FD_FS_CTX,
	.enabled = true,
	.init = &init_fs_ctx_fds,
	.get = &get_rand_fs_ctx_fd,
};

REG_FD_PROV(fs_ctx_fd_provider);
