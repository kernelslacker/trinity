/*
 * fd_stress - intentionally exercise the fd-table mutation paths the
 * default random-syscall mode hits only by accident.
 *
 * Trinity's default mode picks fds randomly and feeds them to syscalls,
 * which spends most of its budget on read/write/ioctl-style consumers
 * and rarely lands on the fd-table-mutation paths (close racing
 * regen, dup2 over an in-use fd, type confusion via dup, CLOEXEC
 * toggling).  Those paths carry the fd refcount and fdtable
 * locking invariants the kernel is most likely to get wrong, but
 * random selection makes them extremely rare to reach.
 *
 * Each invocation picks one of four stress modes:
 *
 *   close-and-reopen   close a tracked fd, then let the parent's
 *                      regen path immediately re-create one of the
 *                      same type.  Drives the fd-pool turnover loop
 *                      hard so any UAF in destructor/regen ordering
 *                      surfaces fast.
 *
 *   dup2-replace       dup2 a known-live fd over another live fd.
 *                      The destination is silently closed by the
 *                      kernel; if any task held that fd in flight
 *                      we have a race window for refcount bugs.
 *
 *   type-confusion     dup2 an fd of one trinity object type over an
 *                      fd of a different type.  The pool still
 *                      believes the destination is its original
 *                      type, so subsequent type-aware syscalls feed
 *                      a wrong-flavoured file struct into kernel
 *                      handlers that expected something else.
 *
 *   cloexec-toggle     rapidly flip FD_CLOEXEC on a tracked fd.
 *                      Stresses the F_SETFD path and the fdtable
 *                      cloexec bitmap update under concurrent
 *                      readers in sibling children.
 *
 * Every fd we touch comes from the existing global pool.  We never
 * allocate a fresh fd here, so leak accounting is trivial: zero ins,
 * dup2-induced closes get reported via the fd_event_ring so the
 * parent prunes the destination from its pool and triggers regen.
 *
 * Goto-cleanup discipline: a single "out" label per mode, all early
 * exits goto it, and the cleanup path is bounded — we may re-arm the
 * cloexec bit but never leak fds.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#include "child.h"
#include "fd.h"
#include "fd-event.h"
#include "objects.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

/*
 * Pick two distinct typed fds whose object types differ.  Returns
 * true if it found such a pair; sets out_fd_a/out_fd_b and the
 * matching types.  Used by type-confusion to guarantee the dup2
 * source and destination are genuinely different kinds of object.
 */
static bool pick_two_typed_fds(int *out_fd_a, int *out_fd_b,
			       enum objecttype *out_type_a,
			       enum objecttype *out_type_b)
{
	static const enum argtype typed_args[] = {
		ARG_FD_EPOLL, ARG_FD_EVENTFD, ARG_FD_TIMERFD,
		ARG_FD_INOTIFY, ARG_FD_FANOTIFY, ARG_FD_MEMFD,
		ARG_FD_PIDFD, ARG_FD_SOCKET, ARG_FD_PIPE,
	};
	int fd_a, fd_b;
	enum argtype arg_a, arg_b;
	unsigned int tries;

	for (tries = 0; tries < 8; tries++) {
		arg_a = typed_args[rand() % ARRAY_SIZE(typed_args)];
		arg_b = typed_args[rand() % ARRAY_SIZE(typed_args)];
		if (arg_a == arg_b)
			continue;

		fd_a = get_typed_fd(arg_a);
		fd_b = get_typed_fd(arg_b);
		if (fd_a <= 2 || fd_b <= 2 || fd_a == fd_b)
			continue;

		*out_fd_a = fd_a;
		*out_fd_b = fd_b;
		/*
		 * Map ARG_FD_* back to OBJ_FD_* for the caller.  Trinity
		 * doesn't expose this mapping directly, so duplicate the
		 * tiny switch here rather than thread the objtype through
		 * get_typed_fd's API.
		 */
		switch (arg_a) {
		case ARG_FD_EPOLL:	*out_type_a = OBJ_FD_EPOLL;	break;
		case ARG_FD_EVENTFD:	*out_type_a = OBJ_FD_EVENTFD;	break;
		case ARG_FD_TIMERFD:	*out_type_a = OBJ_FD_TIMERFD;	break;
		case ARG_FD_INOTIFY:	*out_type_a = OBJ_FD_INOTIFY;	break;
		case ARG_FD_FANOTIFY:	*out_type_a = OBJ_FD_FANOTIFY;	break;
		case ARG_FD_MEMFD:	*out_type_a = OBJ_FD_MEMFD;	break;
		case ARG_FD_PIDFD:	*out_type_a = OBJ_FD_PIDFD;	break;
		case ARG_FD_SOCKET:	*out_type_a = OBJ_FD_SOCKET;	break;
		case ARG_FD_PIPE:	*out_type_a = OBJ_FD_PIPE;	break;
		default:		*out_type_a = OBJ_NONE;		break;
		}
		switch (arg_b) {
		case ARG_FD_EPOLL:	*out_type_b = OBJ_FD_EPOLL;	break;
		case ARG_FD_EVENTFD:	*out_type_b = OBJ_FD_EVENTFD;	break;
		case ARG_FD_TIMERFD:	*out_type_b = OBJ_FD_TIMERFD;	break;
		case ARG_FD_INOTIFY:	*out_type_b = OBJ_FD_INOTIFY;	break;
		case ARG_FD_FANOTIFY:	*out_type_b = OBJ_FD_FANOTIFY;	break;
		case ARG_FD_MEMFD:	*out_type_b = OBJ_FD_MEMFD;	break;
		case ARG_FD_PIDFD:	*out_type_b = OBJ_FD_PIDFD;	break;
		case ARG_FD_SOCKET:	*out_type_b = OBJ_FD_SOCKET;	break;
		case ARG_FD_PIPE:	*out_type_b = OBJ_FD_PIPE;	break;
		default:		*out_type_b = OBJ_NONE;		break;
		}
		return true;
	}
	return false;
}

/*
 * Notify the parent that the child closed an fd it formerly tracked.
 * The parent's drain loop will issue remove_object_by_fd() and a
 * try_regenerate_fd() against the corresponding object type.
 */
static void notify_close(struct childdata *child, int fd)
{
	if (child == NULL || child->fd_event_ring == NULL)
		return;
	if (fd < 0)
		return;
	fd_event_enqueue(child->fd_event_ring, FD_EVENT_CLOSE, fd, -1, 0, 0, 0);
}

static bool fd_stress_close_reopen(struct childdata *child)
{
	int fd;

	fd = get_random_fd();
	if (fd <= 2)
		return true;

	if (close(fd) == 0) {
		notify_close(child, fd);
		__atomic_add_fetch(&shm->stats.fdstress_close_reopen, 1,
				   __ATOMIC_RELAXED);
	}
	return true;
}

static bool fd_stress_dup2_replace(struct childdata *child)
{
	int fd_src, fd_dst;
	unsigned int tries;

	for (tries = 0; tries < 8; tries++) {
		fd_src = get_random_fd();
		fd_dst = get_random_fd();
		if (fd_src > 2 && fd_dst > 2 && fd_src != fd_dst)
			break;
	}
	if (tries == 8)
		return true;

	if (dup2(fd_src, fd_dst) >= 0) {
		notify_close(child, fd_dst);
		__atomic_add_fetch(&shm->stats.fdstress_dup2_replace, 1,
				   __ATOMIC_RELAXED);
	}
	return true;
}

static bool fd_stress_type_confusion(struct childdata *child)
{
	int fd_a, fd_b;
	enum objecttype type_a __unused__, type_b;

	if (!pick_two_typed_fds(&fd_a, &fd_b, &type_a, &type_b))
		return true;

	/*
	 * dup2 closes fd_b silently and replaces it with a copy of
	 * fd_a's struct file.  The pool still records fd_b as type_b,
	 * so subsequent get_typed_fd(arg-of-type_b) will hand out an
	 * fd that's actually backed by an object of type_a.  That's
	 * the whole point — see if any consumer assumes the file_ops
	 * match the trinity-side type label.
	 */
	if (dup2(fd_a, fd_b) >= 0) {
		notify_close(child, fd_b);
		__atomic_add_fetch(&shm->stats.fdstress_type_confusion, 1,
				   __ATOMIC_RELAXED);
	}
	return true;
}

static bool fd_stress_cloexec_toggle(struct childdata *child __unused__)
{
	int fd;
	int flags;
	unsigned int i;

	fd = get_random_fd();
	if (fd <= 2)
		return true;

	/* A few rapid flips to bias toward landing in a window where a
	 * concurrent reader sees the bitmap mid-update. */
	for (i = 0; i < 4; i++) {
		flags = fcntl(fd, F_GETFD);
		if (flags < 0)
			return true;
		(void)fcntl(fd, F_SETFD, flags ^ FD_CLOEXEC);
	}

	__atomic_add_fetch(&shm->stats.fdstress_cloexec_toggle, 1,
			   __ATOMIC_RELAXED);
	return true;
}

bool fd_stress(struct childdata *child)
{
	switch (rand() % 4) {
	case 0:	return fd_stress_close_reopen(child);
	case 1:	return fd_stress_dup2_replace(child);
	case 2:	return fd_stress_type_confusion(child);
	case 3:	return fd_stress_cloexec_toggle(child);
	}
	return true;
}
