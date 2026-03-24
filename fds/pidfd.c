/* pidfd FD provider. */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "fd.h"
#include "objects.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

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

static int open_pidfd(pid_t pid)
{
#ifdef __NR_pidfd_open
	return syscall(__NR_pidfd_open, pid, 0);
#else
	errno = ENOSYS;
	return -1;
#endif
}

static int open_pidfd_fd(void)
{
	struct object *obj;
	int fd;

	/* Don't create a pidfd for our own pid — children inherit global
	 * objects and would use it with pidfd_getfd/pidfd_send_signal,
	 * triggering ptrace_may_access() on the parent.  Use pid 1 instead. */
	fd = open_pidfd(1);
	if (fd < 0)
		return false;

	obj = alloc_object();
	obj->pidfdobj.fd = fd;
	obj->pidfdobj.pid = 1;
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

	/* Only create a pidfd for pid 1 (init).  Don't create one for
	 * our own pid — children inherit global objects and would use
	 * it with pidfd_getfd/pidfd_send_signal, triggering
	 * ptrace_may_access() on the parent process. */
	fd = open_pidfd(1);
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

	if (objects_empty(OBJ_FD_PIDFD) == true)
		return -1;

	obj = get_random_object(OBJ_FD_PIDFD, OBJ_GLOBAL);
	return obj->pidfdobj.fd;
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
