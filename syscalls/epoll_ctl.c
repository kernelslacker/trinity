/*
 * SYSCALL_DEFINE4(epoll_ctl, int, epfd, int, op, int, fd, struct epoll_event __user *, event)
 *
 * When successful, epoll_ctl() returns zero.
 * When an error occurs, epoll_ctl() returns -1 and errno is set appropriately.
 */
#include <stdlib.h>
#include <sys/epoll.h>
#include "deferred-free.h"
#include "fd.h"
#include "sanitise.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "compat.h"

#ifndef EPOLLEXCLUSIVE
#define EPOLLEXCLUSIVE (1 << 28)
#endif

#ifndef EPOLL_URING_WAKE
#define EPOLL_URING_WAKE (1U << 27)
#endif

#ifndef EPOLLNVAL
#define EPOLLNVAL 0x00000020
#endif

static const unsigned long epoll_flags[] = {
	EPOLLIN, EPOLLOUT, EPOLLRDHUP, EPOLLPRI,
	EPOLLERR, EPOLLHUP, EPOLLET, EPOLLONESHOT,
	EPOLLWAKEUP, EPOLLEXCLUSIVE,
	EPOLLNVAL, EPOLLRDNORM, EPOLLRDBAND,
	EPOLLWRNORM, EPOLLWRBAND, EPOLLMSG,
	EPOLL_URING_WAKE,
};

static void sanitise_epoll_ctl(struct syscallrecord *rec)
{
	struct epoll_event *ep;
	int target_fd;
	unsigned int tries;

	ep = zmalloc(sizeof(struct epoll_event));

	/*
	 * Reroll target_fd until we land on one whose fd_provider has not
	 * opted into poll_can_block.  ep_item_poll runs the target's
	 * f_op->poll synchronously for both EPOLL_CTL_ADD and EPOLL_CTL_MOD
	 * (the kernel calls ep_modify → ep_item_poll on every MOD), and a
	 * blocking ->poll wedges the child in TASK_UNINTERRUPTIBLE — see the
	 * matching guard in arm_epoll() for the full callchain context.
	 * EPOLL_CTL_DEL takes a different path that does not invoke ->poll,
	 * but the op selection happens after we pick the fd, so reject
	 * uniformly rather than coupling the two.  Bounded retry budget so a
	 * pool dominated by blocking-poll fds (rare) still terminates; if we
	 * fall through with a tagged fd, the count is bumped and the kernel
	 * is allowed to handle it (the syscall will pin one child, recoverable
	 * via the watchdog's is_child_making_progress() path).
	 */
	for (tries = 0; tries < 16; tries++) {
		target_fd = get_random_fd();
		if (target_fd < 0)
			break;
		if (!fd_poll_can_block(target_fd))
			break;
		__atomic_add_fetch(&shm->stats.epoll_blocking_poll_skipped, 1,
				   __ATOMIC_RELAXED);
	}

	ep->data.fd = target_fd;
	ep->events = set_rand_bitmask(ARRAY_SIZE(epoll_flags), epoll_flags);
	rec->a4 = (unsigned long) ep;

	/* Snapshot for the post handler -- a4 may be scribbled by a sibling
	 * syscall before post_epoll_ctl() runs. */
	rec->post_state = (unsigned long) ep;
}

static void post_epoll_ctl(struct syscallrecord *rec)
{
	void *ep = (void *) rec->post_state;

	if (ep == NULL)
		return;

	if (looks_like_corrupted_ptr(rec, ep)) {
		outputerr("post_epoll_ctl: rejected suspicious ep=%p "
			  "(pid-scribbled?)\n", ep);
		rec->a4 = 0;
		rec->post_state = 0;
		return;
	}
	rec->a4 = 0;
	deferred_freeptr(&rec->post_state);
}

static unsigned long epoll_ctl_ops[] = {
	EPOLL_CTL_ADD, EPOLL_CTL_MOD, EPOLL_CTL_DEL,
};

struct syscallentry syscall_epoll_ctl = {
	.name = "epoll_ctl",
	.num_args = 4,
	.argtype = { [0] = ARG_FD_EPOLL, [1] = ARG_OP, [2] = ARG_FD, [3] = ARG_STRUCT_PTR_IN },
	.argname = { [0] = "epfd", [1] = "op", [2] = "fd", [3] = "event" },
	.arg_params[1].list = ARGLIST(epoll_ctl_ops),
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.sanitise = sanitise_epoll_ctl,
	.post = post_epoll_ctl,
	.group = GROUP_VFS,
};
