/*
 * SYSCALL_DEFINE4(epoll_ctl, int, epfd, int, op, int, fd, struct epoll_event __user *, event)
 *
 * When successful, epoll_ctl() returns zero.
 * When an error occurs, epoll_ctl() returns -1 and errno is set appropriately.
 */
#include <sys/epoll.h>
#include "fd.h"
#include "sanitise.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/epoll.h"
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

/*
 * The base struct epoll_event buffer is allocated and zero-filled by
 * ARG_STRUCT_PTR_IN's catalog-driven generator (registered against
 * arg 4) before this runs, and is freed via the deferred-free queue
 * the catalog enqueues at generation time.  All this hook does is
 * tweak two fields the catalog can't reasonably populate on its own:
 *
 *   - .data is a union and the catalog only walks named scalar fields,
 *     so .data.fd is left zero (== stdin) without a tweak here.
 *   - .events is a uint32 the catalog will randomise, but a wild u32
 *     almost never hits a valid EPOLL* bit-set; pin it to a random
 *     subset of the real epoll flags so the kernel's event-mask
 *     validators actually accept the value occasionally.
 */
static void sanitise_epoll_ctl(struct syscallrecord *rec)
{
	struct epoll_event *ep = (struct epoll_event *) rec->a4;
	int target_fd = -1;
	unsigned int tries;

	if (ep == NULL)
		return;

	/*
	 * Reroll the polled fd (rec->a3) until we land on one whose
	 * fd_provider has not opted into poll_can_block.  ep_item_poll runs
	 * the target's f_op->poll synchronously for both EPOLL_CTL_ADD and
	 * EPOLL_CTL_MOD (the kernel calls ep_modify → ep_item_poll on every
	 * MOD), and a blocking ->poll wedges the child in
	 * TASK_UNINTERRUPTIBLE — see the matching guard in arm_epoll() for
	 * the full callchain context.  EPOLL_CTL_DEL takes a different path
	 * that does not invoke ->poll, but the op selection happens after we
	 * pick the fd, so reject uniformly rather than coupling the two.
	 *
	 * The fd the kernel actually polls is rec->a3 (populated from
	 * .argtype[2] = ARG_FD before this hook runs); ep->data.fd is just a
	 * user cookie the kernel echoes back and never dereferences, so
	 * vetting it in isolation would leave a blocking-poll fd on the
	 * syscall arg.  Overwrite rec->a3 with the vetted value, and on
	 * retry-exhaust fail closed with -1 rather than letting an unvetted
	 * fd through.
	 */
	for (tries = 0; tries < 16; tries++) {
		int candidate = get_random_fd();

		if (candidate < 0)
			break;
		if (!fd_poll_can_block(candidate)) {
			target_fd = candidate;
			break;
		}
		__atomic_add_fetch(&shm->stats.epoll_volatility.blocking_poll_skipped, 1,
				   __ATOMIC_RELAXED);
	}

	rec->a3 = (unsigned long) target_fd;
	ep->data.fd = target_fd;
	ep->events = set_rand_bitmask(ARRAY_SIZE(epoll_flags), epoll_flags);

	avoid_shared_buffer_inout(&rec->a4, sizeof(struct epoll_event));
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
	.group = GROUP_VFS,
};
