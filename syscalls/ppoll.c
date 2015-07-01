/*
 * SYSCALL_DEFINE5(ppoll, struct pollfd __user *, ufds, unsigned int, nfds,
	 struct timespec __user *, tsp, const sigset_t __user *, sigmask, size_t, sigsetsize)
 */

#include <stdlib.h>
#include <signal.h>
//#include <poll.h>
#include <asm/poll.h>
#include "random.h"
#include "sanitise.h"
#include "utils.h"

static const unsigned long poll_events[] = {
	POLLIN, POLLPRI, POLLOUT, POLLERR,
	POLLHUP, POLLNVAL, POLLRDBAND, POLLWRNORM,
	POLLWRBAND, POLLMSG, POLLREMOVE, POLLRDHUP,
	POLLFREE, POLL_BUSY_LOOP,
};

static short rand_events(void)
{
	unsigned long r;

	r = set_rand_bitmask(ARRAY_SIZE(poll_events), poll_events);

	return r;
}

static void sanitise_ppoll(struct syscallrecord *rec)
{
	struct pollfd *fds;
	struct timespec *ts;
	unsigned int num = rand() % 1024;
	unsigned int i;

	fds = malloc(sizeof(struct pollfd) * num);
	rec->a1 = (unsigned long) fds;
	if (fds == NULL)
		return;

	rec->a2 = num;

	for (i = 0 ; i < num; i++) {
		fds[i].fd = get_random_fd();
		fds[i].events = rand_events();
		fds[i].revents = rand_events();
	}

	ts = malloc(sizeof(struct timespec));
	rec->a3 = (unsigned long) ts;
	if (ts == NULL) {
		/* if we set ts to null, ppoll will block indefinitely */
		rec->a3 = 1;
		return;
	}
	ts->tv_sec = 1;
	ts->tv_nsec = 0;

	rec->a5 = sizeof(sigset_t);
}

static void post_ppoll(struct syscallrecord *rec)
{
	void *ptr;

	ptr = (void *) rec->a1;
	if (ptr != NULL)
		free(ptr);

	ptr = (void *) rec->a4;
	free(ptr);
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
