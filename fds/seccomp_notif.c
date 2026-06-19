/* seccomp notification FDs */

#ifdef USE_SECCOMP

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#include "fd.h"
#include "syscall-gate.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "compat.h"
#include "trinity.h"
#include "utils.h"

#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif
#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif
#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF 0x7fc00000U
#endif
#ifndef SECCOMP_RET_ALLOW
#define SECCOMP_RET_ALLOW 0x7fff0000U
#endif

/*
 * Build a minimal BPF program that returns SECCOMP_RET_USER_NOTIF for
 * an obsolete syscall and SECCOMP_RET_ALLOW for everything else.  This
 * gives us a notification fd without interfering with normal operation.
 *
 * The filter target MUST be a syscall trinity does not invoke (directly
 * or via libc) AND that the random picker does not select; otherwise
 * the seccomp filter — which is inherited across fork and is permanent
 * — wedges the parent and every child until somebody services the
 * listener fd, and nothing in the codebase services it as part of
 * normal scheduling.  __NR_query_module fits: the in-kernel slot is
 * sys_ni_syscall, trinity's table entry for it is syscall_ni_syscall,
 * and validate_specific_syscall_silent() skips NI_SYSCALL entries at
 * activation time so the random picker never reaches it.
 */
static int create_seccomp_notif_fd(void)
{
	struct sock_filter filter[] = {
		/* A = syscall number */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, nr)),
		/* if (A == __NR_query_module) goto notify */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_query_module, 0, 1),
		/* notify: return USER_NOTIF */
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
		/* allow: return ALLOW */
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
		.filter = filter,
	};

	return trinity_raw_syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
		       SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
}

static int open_seccomp_notif(void)
{
	struct object *obj;
	int fd;

	fd = create_seccomp_notif_fd();
	if (fd < 0) {
		int err = errno;
		enum fd_init_reason reason = (err == ENOSYS) ?
				FD_INIT_REASON_CONFIG_ABSENT :
				(err == EACCES || err == EPERM) ?
				FD_INIT_REASON_CAP_MISSING :
				FD_INIT_REASON_ERRNO;
		outputerr("open_seccomp_notif: seccomp(SET_MODE_FILTER, NEW_LISTENER) failed: %s\n",
			strerror(err));
		fd_provider_init_fail(reason, err,
				      "seccomp(SET_MODE_FILTER, NEW_LISTENER)");
		return false;
	}

	obj = alloc_object();
	if (obj == NULL) {
		outputerr("open_seccomp_notif: alloc_object failed\n");
		fd_provider_init_fail(FD_INIT_REASON_RESOURCE, 0, "alloc_object");
		close(fd);
		return false;
	}
	obj->seccomp_notifobj.fd = fd;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_SECCOMP_NOTIF);
	return true;
}

static int init_seccomp_notif_fds(void)
{
	struct objhead *head;
	int ret = false;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_SECCOMP_NOTIF);
	head->destroy = &close_fd_destructor;
	head->dump = &generic_fd_dump;
	/*
	 * seccomp_notifobj is {int fd;} with no pointer members, so the
	 * OBJ_GLOBAL pool's scalars stay valid across fork/COW and
	 * cross-process reads are safe.
	 */

	/* Create a small pool.  Each call installs a new seccomp filter,
	 * so don't go overboard. */
	if (open_seccomp_notif())
		ret = true;
	if (open_seccomp_notif())
		ret = true;

	return ret;
}

static int get_rand_seccomp_notif_fd(void)
{
	if (objects_empty(OBJ_FD_SECCOMP_NOTIF) == true)
		return -1;

	/*
	 * Versioned slot pick + objpool_check() before the
	 * obj->seccomp_notifobj.fd deref.  A version-validated object-slot
	 * read guards the lockless reader against a recycled object
	 * (cf. get_rand_socketinfo in fds/sockets.c).  Same OBJ_GLOBAL
	 * lockless-reader UAF window:
	 * between the lockless slot pick and the consumer's read of
	 * the seccomp notif fd handed to ioctl(SECCOMP_IOCTL_NOTIF_*) via the fd_provider .get callback,
	 * the parent can destroy the obj; release_obj() zeroes the chunk
	 * and routes it through deferred-free, so the stale slot pointer
	 * can read a zeroed or recycled chunk.
	 */
	for (int i = 0; i < 1000; i++) {
		struct object *obj;
		int fd;

		obj = get_random_object(OBJ_FD_SECCOMP_NOTIF, OBJ_GLOBAL);
		if (!objpool_check(obj, OBJ_FD_SECCOMP_NOTIF))
			continue;

		fd = obj->seccomp_notifobj.fd;
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

static const struct fd_provider seccomp_notif_fd_provider = {
	.name = "seccomp-notif",
	.objtype = OBJ_FD_SECCOMP_NOTIF,
	.enabled = true,
	.init = &init_seccomp_notif_fds,
	.get = &get_rand_seccomp_notif_fd,
	.poll_can_block = true,
};

REG_FD_PROV(seccomp_notif_fd_provider);

#endif /* USE_SECCOMP */
