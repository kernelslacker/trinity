/* signalfd FDs (signalfd4). */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "fd.h"
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

static void signalfd_destructor(struct object *obj)
{
	close(obj->signalfdobj.fd);
}

static void signalfd_dump(struct object *obj, enum obj_scope scope)
{
	output(2, "signalfd fd:%d scope:%d\n", obj->signalfdobj.fd, scope);
}

static int do_signalfd4(void)
{
	sigset_t mask;

	sigemptyset(&mask);
	sigaddset(&mask, SIGUSR1);
	sigaddset(&mask, SIGUSR2);
	sigaddset(&mask, SIGCHLD);

#ifdef __NR_signalfd4
	return syscall(__NR_signalfd4, -1, &mask, sizeof(sigset_t),
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
	head->destroy = &signalfd_destructor;
	head->dump = &signalfd_dump;
	head->shared_alloc = true;

	for (i = 0; i < SIGNALFD_INIT_POOL; i++) {
		struct object *obj;
		int fd;

		fd = do_signalfd4();
		if (fd < 0)
			continue;

		obj = alloc_shared_obj(sizeof(struct object));
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
	 * Versioned slot pick + validate_object_handle() before the
	 * obj->signalfdobj.fd deref, mirroring the wireup at 15b6257b8206
	 * (fds/sockets.c get_rand_socketinfo) and 5ef98298f6ad
	 * (syscalls/keyctl.c KEYCTL_WATCH_KEY).  Same OBJ_GLOBAL lockless-
	 * reader UAF window the framework commit a7fdbb97830c spelled out:
	 * between the lockless slot pick and the consumer's read of
	 * the signalfd routed into read/poll via the fd_provider .get callback,
	 * the parent can destroy the obj, free_shared_obj() returns the
	 * chunk to the shared-heap freelist, and a concurrent
	 * alloc_shared_obj() recycles it underneath us.
	 */
	for (int i = 0; i < 1000; i++) {
		unsigned int slot_idx, slot_version;
		struct object *obj;
		int fd;

		obj = get_random_object_versioned(OBJ_FD_SIGNALFD, OBJ_GLOBAL,
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
			outputerr("get_rand_signalfd_fd: bogus obj %p in "
				  "OBJ_FD_SIGNALFD pool\n", obj);
			continue;
		}

		if (!validate_object_handle(OBJ_FD_SIGNALFD, OBJ_GLOBAL, obj,
					    slot_idx, slot_version))
			continue;

		fd = obj->signalfdobj.fd;
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

static int open_signalfd_fd(void)
{
	struct object *obj;
	int fd;

	fd = do_signalfd4();
	if (fd < 0)
		return false;

	obj = alloc_shared_obj(sizeof(struct object));
	if (obj == NULL) {
		close(fd);
		return false;
	}
	obj->signalfdobj.fd = fd;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_SIGNALFD);
	return true;
}

static const struct fd_provider signalfd_fd_provider = {
	.name = "signalfd",
	.objtype = OBJ_FD_SIGNALFD,
	.enabled = true,
	.init = &init_signalfd_fds,
	.get = &get_rand_signalfd_fd,
	.open = &open_signalfd_fd,
};

REG_FD_PROV(signalfd_fd_provider);
