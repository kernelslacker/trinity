/* pidfd FD provider. */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "child.h"
#include "fd-event.h"
#include "fd.h"
#include "objects.h"
#include "params.h"
#include "pids.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/* PIDFD_NONBLOCK == O_NONBLOCK on Linux */
#ifndef PIDFD_NONBLOCK
#define PIDFD_NONBLOCK O_NONBLOCK
#endif

static void pidfd_destructor(struct object *obj)
{
	close(obj->pidfdobj.fd);
}

/*
 * Cross-process safe: only reads obj->pidfdobj fields (now in shm
 * via alloc_shared_obj) and the scope scalar.  No process-local
 * pointers are dereferenced, so it is correct to call this from a
 * different process than the one that allocated the obj — which
 * matters because head->dump runs from dump_childdata() in the
 * parent's crash diagnostics path even when a child triggered the
 * crash.
 */
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

	obj = alloc_shared_obj(sizeof(struct object));
	if (obj == NULL) {
		close(fd);
		return false;
	}
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
	/*
	 * Opt this provider into the shared obj heap.  __destroy_object()
	 * checks this flag to route the obj struct release through
	 * free_shared_obj() instead of free().  pidfd is the PoC for
	 * the structural fix to the OBJ_GLOBAL-in-parent-heap class of
	 * crashes; the rest of the providers stay on alloc_object()
	 * until each is converted in turn.
	 */
	head->shared_alloc = true;

	/* Children haven't been forked yet at init time, so only pid 1
	 * is available.  open_pidfd_fd() will pick child pids at runtime. */
	fd = open_pidfd(1, 0);
	if (fd >= 0) {
		obj = alloc_shared_obj(sizeof(struct object));
		if (obj == NULL) {
			close(fd);
			return false;
		}
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
		struct childdata *child = this_child();

		if (child != NULL && child->fd_event_ring != NULL)
			fd_event_enqueue(child->fd_event_ring, FD_EVENT_CLOSE,
					 fd, -1, 0, 0, 0);
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

