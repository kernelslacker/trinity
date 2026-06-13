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
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/* PIDFD_NONBLOCK == O_NONBLOCK on Linux */
#ifndef PIDFD_NONBLOCK
#define PIDFD_NONBLOCK O_NONBLOCK
#endif

/*
 * Cross-process safe: only reads obj->pidfdobj scalar fields and the
 * scope scalar.  These survive fork/COW and no process-local pointers
 * are dereferenced, so it is correct to call this from a different
 * process than the one that allocated the obj — which matters because
 * head->dump runs from dump_childdata() in the parent's crash
 * diagnostics path even when a child triggered the crash.
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

static int init_pidfd_fds(void)
{
	struct objhead *head;
	struct object *obj;
	int fd;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_PIDFD);
	head->destroy = &close_fd_destructor;
	head->dump = &pidfd_dump;
	/*
	 * pidfdobj holds only scalars, so the OBJ_GLOBAL pool's contents
	 * stay valid across fork/COW and cross-process reads are safe.
	 */

	/* Children haven't been forked yet at init time, so only pid 1
	 * is available.  open_pidfd_fd() will pick child pids at runtime. */
	fd = open_pidfd(1, 0);
	if (fd >= 0) {
		obj = alloc_object();
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
	if (objects_empty(OBJ_FD_PIDFD) == true)
		return -1;

	/*
	 * Versioned slot pick + objpool_check() before the
	 * obj->pidfdobj.fd deref.  A version-validated object-slot read
	 * guards the lockless reader against a recycled object
	 * (cf. get_rand_socketinfo in fds/sockets.c).  Same OBJ_GLOBAL
	 * lockless-reader UAF window:
	 * between the lockless slot pick and the consumer's read of the
	 * pidfd handed to pidfd_send_signal/pidfd_open/etc via the
	 * fd_provider .get callback, the parent can destroy the obj;
	 * release_obj() zeroes the chunk and routes it through
	 * deferred-free, so the stale slot pointer can read a zeroed or
	 * recycled chunk.
	 *
	 * Adapted shape: pidfd already had a post-deref fcntl(F_GETFD)
	 * sanity probe to catch already-closed pidfds, with an
	 * fd_event_enqueue(FD_EVENT_CLOSE) to evict the stale entry.  Keep
	 * that probe inside the loop so a fcntl(EBADF) drops the candidate
	 * and re-picks from the pool instead of returning -1 to the caller
	 * after a single try — the version-validate covers the recycled-obj
	 * race, fcntl covers the closed-but-still-published-fd race, and
	 * both want the same retry budget.
	 */
	for (int i = 0; i < 1000; i++) {
		struct object *obj;
		int fd;

		obj = get_random_object(OBJ_FD_PIDFD, OBJ_GLOBAL);
		if (!objpool_check(obj, OBJ_FD_PIDFD))
			continue;

		fd = obj->pidfdobj.fd;
		if (fd < 0)
			continue;

		if (fcntl(fd, F_GETFD) < 0) {
			struct childdata *child = this_child();

			/* Publish the stale fd to the parent and drop the
			 * local snapshots.  get_rand_pidfd() runs in child
			 * context (called from arg-generation), so
			 * this_child() resolves the producing child here.
			 * The live_fds ring eviction inside the helper
			 * keeps the same fd from being re-picked through
			 * the live-fd cache on the next syscall before the
			 * parent drains the FD_EVENT_CLOSE. */
			if (child != NULL)
				notify_child_fd_closed(child, fd);
			continue;
		}

		return fd;
	}

	return -1;
}

static const struct fd_provider pidfd_fd_provider = {
	.name = "pidfd",
	.objtype = OBJ_FD_PIDFD,
	.enabled = true,
	.init = &init_pidfd_fds,
	.get = &get_rand_pidfd,
	/*
	 * pidfd_poll() returns ready only when the referenced task exits;
	 * for a long-running target, ep_item_poll parks on the task's
	 * exit waitqueue with no bound.  Bar from epoll/select/poll watch
	 * sets; direct waitid()/pidfd_send_signal() remains available.
	 */
	.poll_can_block = true,
};

REG_FD_PROV(pidfd_fd_provider);

