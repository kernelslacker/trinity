/*
 * sys_poll(struct pollfd __user *ufds, unsigned int nfds, int timeout);
 */
#include <stdlib.h>
#include <signal.h>
#include <asm/poll.h>
#include "fd.h"
#include "random.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
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
	unsigned int num_fds = rand() % 10;

	pollfd = zmalloc(num_fds * sizeof(struct pollfd));

	for (i = 0; i < num_fds; i++) {
		pollfd[i].fd = get_random_fd();
		pollfd[i].events = set_rand_bitmask(ARRAY_SIZE(poll_events), poll_events);
	}

	rec->a1 = (unsigned long) pollfd;
	rec->a2 = num_fds;
	/* Snapshot for the post handler -- a1 may be scribbled by a sibling
	 * syscall before post_poll() runs. */
	rec->post_state = (unsigned long) pollfd;
}

static void post_poll(struct syscallrecord *rec)
{
	void *ufds = (void *) rec->post_state;

	if (ufds == NULL)
		return;

	if (looks_like_corrupted_ptr(ufds)) {
		outputerr("post_poll: rejected suspicious ufds=%p (pid-scribbled?)\n", ufds);
		__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
		rec->a1 = 0;
		rec->post_state = 0;
		return;
	}

	rec->a1 = 0;
	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_poll = {
	.name = "poll",
	.num_args = 3,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_LEN, [2] = ARG_RANGE },
	.argname = { [0] = "ufds", [1] = "nfds", [2] = "timeout_msecs" },
	.arg_params[2].range.low = 0,
	.arg_params[2].range.hi = 100,
	.flags = NEED_ALARM,
	.sanitise = sanitise_poll,
	.post = post_poll,
	.group = GROUP_VFS,
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
	deferred_freeptr(&rec->a1);
	deferred_freeptr(&rec->a3);
}

struct syscallentry syscall_ppoll = {
	.name = "ppoll",
	.num_args = 5,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_LEN, [2] = ARG_ADDRESS, [3] = ARG_ADDRESS, [4] = ARG_LEN },
	.argname = { [0] = "ufds", [1] = "nfds", [2] = "tsp", [3] = "sigmask", [4] = "sigsetsize" },
	.flags = NEED_ALARM,
	.sanitise = sanitise_ppoll,
	.post = post_ppoll,
	.group = GROUP_VFS,
};
