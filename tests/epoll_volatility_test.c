/*
 * Self-check for epoll_volatility's MOD arm: do_epoll_ctl() refuses a MOD
 * carrying EPOLLEXCLUSIVE before ep_modify() runs, so the arm sends one
 * rarely, as a probe of that reject, not as often as ADD offers it.
 */

#include <stdbool.h>
#include <sys/epoll.h>

#include "child.h"		/* struct childdata */
#include "child-api.h"	/* epoll_volatility, CHILD_OP_EPOLL_VOLATILITY */
#include "debug.h"		/* BUG */

/* MODs to judge by: a quarter of them carrying the bit is some 15
 * standard deviations above one in 16, and 10 below one in 2. */
#define MODS	400

static unsigned int mods, exclusive_mods;

/* epoll_ctl() stand-in: the real call, counting the MODs it carries. */
int __real_epoll_ctl(int epfd, int op, int fd, struct epoll_event *ev);
int __wrap_epoll_ctl(int epfd, int op, int fd, struct epoll_event *ev);
int __wrap_epoll_ctl(int epfd, int op, int fd, struct epoll_event *ev)
{
	if (op == EPOLL_CTL_MOD && ev != NULL) {
		mods++;
		if (ev->events & EPOLLEXCLUSIVE)
			exclusive_mods++;
	}
	return __real_epoll_ctl(epfd, op, fd, ev);
}

void epoll_volatility_self_check(void);
void epoll_volatility_self_check(void)
{
	static struct childdata child;
	unsigned int runs;

	child.op_type = CHILD_OP_EPOLL_VOLATILITY;
	mods = 0;
	exclusive_mods = 0;
	for (runs = 0; runs < 256 && mods < MODS; runs++)
		epoll_volatility(&child);

	if (mods < MODS)
		BUG("epoll_volatility: too few MODs to judge the arm by");
	if (exclusive_mods * 4 > mods)
		BUG("epoll_volatility: MODs carry EPOLLEXCLUSIVE as often as ADDs");
}
