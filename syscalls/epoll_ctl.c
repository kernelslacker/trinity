/*
 * SYSCALL_DEFINE4(epoll_ctl, int, epfd, int, op, int, fd, struct epoll_event __user *, event)
 *
 * When successful, epoll_ctl() returns zero.
 * When an error occurs, epoll_ctl() returns -1 and errno is set appropriately.
 */
#include <stdlib.h>
#include <sys/epoll.h>
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

	ep = zmalloc(sizeof(struct epoll_event));
	ep->data.fd = get_random_fd();
	ep->events = set_rand_bitmask(ARRAY_SIZE(epoll_flags), epoll_flags);
	rec->a4 = (unsigned long) ep;
}

static void post_epoll_ctl(struct syscallrecord *rec)
{
	void *ep = (void *) rec->a4;

	if (ep == NULL)
		return;

	/*
	 * epoll_ctl free()s rec->a4 directly (not via deferred_free_enqueue),
	 * so the central guard in deferred-free.c won't catch a pid-scribbled
	 * value here -- check inline.  Cluster-1/2/3 guard.
	 */
	if (looks_like_corrupted_ptr(ep)) {
		outputerr("post_epoll_ctl: rejected suspicious ep=%p "
			  "(pid-scribbled?)\n", ep);
		__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
		return;
	}
	free(ep);
}

static unsigned long epoll_ctl_ops[] = {
	EPOLL_CTL_ADD, EPOLL_CTL_MOD, EPOLL_CTL_DEL,
};

struct syscallentry syscall_epoll_ctl = {
	.name = "epoll_ctl",
	.num_args = 4,
	.argtype = { [0] = ARG_FD_EPOLL, [1] = ARG_OP, [2] = ARG_FD },
	.argname = { [0] = "epfd", [1] = "op", [2] = "fd", [3] = "event" },
	.arg_params[1].list = ARGLIST(epoll_ctl_ops),
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.sanitise = sanitise_epoll_ctl,
	.post = post_epoll_ctl,
	.group = GROUP_VFS,
};
