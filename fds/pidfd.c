/* pidfd FD provider. */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "child.h"
#include "fd.h"
#include "objects.h"
#include "params.h"
#include "pids.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

/* PIDFD_NONBLOCK == O_NONBLOCK on Linux */
#ifndef PIDFD_NONBLOCK
#define PIDFD_NONBLOCK O_NONBLOCK
#endif

static void pidfd_destructor(struct object *obj)
{
	close(obj->pidfdobj.fd);
}

static void pidfd_dump(struct object *obj, enum obj_scope scope)
{
	struct pidfdobj *po = &obj->pidfdobj;

	output(2, "pidfd fd:%d pid:%d scope:%d\n",
		po->fd, po->pid, scope);
}

static int open_pidfd(pid_t pid, unsigned int flags)
{
#ifdef __NR_pidfd_open
	return syscall(__NR_pidfd_open, pid, flags);
#else
	errno = ENOSYS;
	return -1;
#endif
}

static int open_pidfd_fd(void)
{
	struct object *obj;
	unsigned int flags;
	pid_t pid = 1;
	int fd;

	flags = RAND_BOOL() ? PIDFD_NONBLOCK : 0;

	/* Try to get a random child process pid. Fall back to pid 1 if
	 * no children are running yet or the slot is empty. */
	if (shm->running_childs > 0) {
		unsigned int i = rand() % max_children;

		if (__atomic_load_n(&pids[i], __ATOMIC_RELAXED) != EMPTY_PIDSLOT)
			pid = __atomic_load_n(&pids[i], __ATOMIC_RELAXED);
	}

	fd = open_pidfd(pid, flags);
	if (fd < 0)
		return false;

	obj = alloc_object();
	obj->pidfdobj.fd = fd;
	obj->pidfdobj.pid = pid;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_PIDFD);
	return true;
}

static int init_pidfd_fds(void)
{
	struct objhead *head;
	struct object *obj;
	int fd;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_PIDFD);
	head->destroy = &pidfd_destructor;
	head->dump = &pidfd_dump;

	/* Children haven't been forked yet at init time, so only pid 1
	 * is available.  open_pidfd_fd() will pick child pids at runtime. */
	fd = open_pidfd(1, 0);
	if (fd >= 0) {
		obj = alloc_object();
		obj->pidfdobj.fd = fd;
		obj->pidfdobj.pid = 1;
		add_object(obj, OBJ_GLOBAL, OBJ_FD_PIDFD);
	}

	return fd >= 0;
}

static int get_rand_pidfd(void)
{
	struct object *obj;
	int fd;

	if (objects_empty(OBJ_FD_PIDFD) == true)
		return -1;

	obj = get_random_object(OBJ_FD_PIDFD, OBJ_GLOBAL);
	if (obj == NULL)
		return -1;

	fd = obj->pidfdobj.fd;
	if (fcntl(fd, F_GETFD) < 0) {
		destroy_object(obj, OBJ_GLOBAL, OBJ_FD_PIDFD);
		return -1;
	}
	return fd;
}

static const struct fd_provider pidfd_fd_provider = {
	.name = "pidfd",
	.objtype = OBJ_FD_PIDFD,
	.enabled = true,
	.init = &init_pidfd_fds,
	.get = &get_rand_pidfd,
	.open = &open_pidfd_fd,
};

REG_FD_PROV(pidfd_fd_provider);

