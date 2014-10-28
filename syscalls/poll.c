/*
 * sys_poll(struct pollfd __user *ufds, unsigned int nfds, int timeout);
 */
#include <poll.h>
#include "random.h"
#include "sanitise.h"
#include "utils.h"

static void sanitise_poll(struct syscallrecord *rec)
{
	struct pollfd *pollfd;
	unsigned int i;
	unsigned int num_fds = rand() % 10;
	unsigned long flags[] = {
		POLLIN, POLLPRI, POLLOUT, POLLRDHUP,
		POLLERR, POLLHUP, POLLNVAL, POLLRDNORM,
		POLLRDBAND, POLLWRNORM, POLLWRBAND, POLLMSG
	};

	pollfd = zmalloc(num_fds * sizeof(struct pollfd));

	for (i = 0; i < num_fds; i++) {
		pollfd[i].fd = get_random_fd();
		pollfd[i].events = set_rand_bitmask(ARRAY_SIZE(flags), flags);
	}

	rec->a1 = (unsigned long) pollfd;
	rec->a2 = num_fds;
}

static void post_poll(struct syscallrecord *rec)
{
	free((void *) rec->a1);
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
