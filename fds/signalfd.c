/* signalfd FDs (signalfd4). */

#include <errno.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>

#include "fd.h"
#include "syscall-gate.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "utils.h"

#ifndef SFD_CLOEXEC
#define SFD_CLOEXEC 02000000
#endif
#ifndef SFD_NONBLOCK
#define SFD_NONBLOCK 04000
#endif

static int do_signalfd4(void)
{
	sigset_t mask;

	sigemptyset(&mask);
	sigaddset(&mask, SIGUSR1);
	sigaddset(&mask, SIGUSR2);
	sigaddset(&mask, SIGCHLD);

#ifdef __NR_signalfd4
	return trinity_raw_syscall(__NR_signalfd4, -1, &mask, sizeof(sigset_t),
		       SFD_CLOEXEC | SFD_NONBLOCK);
#else
	errno = ENOSYS;
	return -1;
#endif
}

#define SIGNALFD_INIT_POOL 4

static int init_signalfd_fds(void)
{
	struct objhead *head;
	unsigned int i;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_SIGNALFD);
	head->destroy = &close_fd_destructor;
	head->dump = &generic_fd_dump;

	for (i = 0; i < SIGNALFD_INIT_POOL; i++) {
		struct object *obj;
		int fd;

		fd = do_signalfd4();
		if (fd < 0)
			continue;

		obj = alloc_object();
		if (obj == NULL) {
			close(fd);
			return false;
		}
		obj->signalfdobj.fd = fd;
		add_object(obj, OBJ_GLOBAL, OBJ_FD_SIGNALFD);
	}

	return true;
}

static int get_rand_signalfd_fd(void)
{
	if (objects_empty(OBJ_FD_SIGNALFD) == true)
		return -1;

	/*
	 * Versioned slot pick + objpool_check() before the
	 * obj->signalfdobj.fd deref.  A version-validated object-slot read
	 * guards the lockless reader against a recycled object
	 * (cf. get_rand_socketinfo in fds/sockets.c).  Same OBJ_GLOBAL
	 * lockless-reader UAF window:
	 * between the lockless slot pick and the consumer's read of
	 * the signalfd routed into read/poll via the fd_provider .get callback,
	 * the parent can destroy the obj; release_obj() zeroes the chunk
	 * and routes it through deferred-free, so the stale slot pointer
	 * can read a zeroed or recycled chunk.
	 */
	for (int i = 0; i < 1000; i++) {
		struct object *obj;
		int fd;

		obj = get_random_object(OBJ_FD_SIGNALFD, OBJ_GLOBAL);
		if (!objpool_check(obj, OBJ_FD_SIGNALFD))
			continue;

		fd = obj->signalfdobj.fd;
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

static const struct fd_provider signalfd_fd_provider = {
	.name = "signalfd",
	.objtype = OBJ_FD_SIGNALFD,
	.enabled = true,
	.init = &init_signalfd_fds,
	.get = &get_rand_signalfd_fd,
};

REG_FD_PROV(signalfd_fd_provider);
