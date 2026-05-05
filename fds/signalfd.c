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
	struct object *obj;

	if (objects_empty(OBJ_FD_SIGNALFD) == true)
		return -1;

	obj = get_random_object(OBJ_FD_SIGNALFD, OBJ_GLOBAL);
	if (obj == NULL)
		return -1;
	return obj->signalfdobj.fd;
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
