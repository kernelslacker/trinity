/*
 * sys_poll(struct pollfd __user *ufds, unsigned int nfds, int timeout);
 */
#include <stdlib.h>
#include <signal.h>
#include <asm/poll.h>
#include "fd.h"
#include "random.h"
#include "sanitise.h"
#include "utils.h"
#include "compat.h"

static const unsigned long poll_events[] = {
	POLLIN, POLLPRI, POLLOUT, POLLERR,
	POLLHUP, POLLNVAL, POLLRDBAND, POLLWRNORM,
	POLLWRBAND, POLLMSG, POLLREMOVE, POLLRDHUP,
	POLLFREE, POLL_BUSY_LOOP,
};

static void sanitise_poll(struct syscallrecord *rec)
{
	struct pollfd *pollfd;
	unsigned int i;
	unsigned int num_fds = rnd() % 10;

	pollfd = zmalloc(num_fds * sizeof(struct pollfd));

	for (i = 0; i < num_fds; i++) {
		pollfd[i].fd = get_random_fd();
		pollfd[i].events = set_rand_bitmask(ARRAY_SIZE(poll_events), poll_events);
	}

	rec->a1 = (unsigned long) pollfd;
	rec->a2 = num_fds;
}

static void post_poll(struct syscallrecord *rec)
{
	freeptr(&rec->a1);
}

struct syscallentry syscall_poll = {
	.name = "poll",
	.num_args = 3,
	.arg1name = "ufds",
	.arg2name = "nfds",
	.arg3name = "timeout_msecs",
	.arg3type = ARG_RANGE,
	.low3range = 0,
	.hi3range = 1,
	.flags = NEED_ALARM,
	.sanitise = sanitise_poll,
	.post = post_poll,
};

/*
 * SYSCALL_DEFINE5(ppoll, struct pollfd __user *, ufds, unsigned int, nfds,
	 struct timespec __user *, tsp, const sigset_t __user *, sigmask, size_t, sigsetsize)
 */

static void sanitise_ppoll(struct syscallrecord *rec)
{
	struct pollfd *fds;
	struct timespec *ts;

	sanitise_poll(rec);

	fds = (struct pollfd *) rec->a1;
	if (fds == NULL)
		return;

	ts = zmalloc(sizeof(struct timespec));
	rec->a3 = (unsigned long) ts;
	ts->tv_sec = 1;
	ts->tv_nsec = 0;

	rec->a5 = sizeof(sigset_t);
}

static void post_ppoll(struct syscallrecord *rec)
{
	freeptr(&rec->a1);
	freeptr(&rec->a3);
}

struct syscallentry syscall_ppoll = {
	.name = "ppoll",
	.num_args = 5,
	.arg1name = "ufds",
	.arg2name = "nfds",
	.arg3name= "tsp",
	.arg4name = "sigmask",
	.arg4type = ARG_ADDRESS,
	.arg5name = "sigsetsize",
	.flags = NEED_ALARM,
	.sanitise = sanitise_ppoll,
	.post = post_ppoll,
};
