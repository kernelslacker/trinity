/*
SYSCALL_DEFINE6(epoll_pwait, int, epfd, struct epoll_event __user *, events,
                int, maxevents, int, timeout, const sigset_t __user *, sigmask,
                size_t, sigsetsize)

SYSCALL_DEFINE6(epoll_pwait2, int, epfd, struct epoll_event __user *, events,
                int, maxevents, const struct __kernel_timespec __user *, timeout,
                const sigset_t __user *, sigmask, size_t, sigsetsize)

 * When  successful, returns the number of file descriptors ready for the requested I/O,
 * or zero if no file descriptor became ready during the requested timeout milliseconds.
 * When an error occurs, returns -1 and errno is set appropriately.
 */
#include <sys/epoll.h>
#include "random.h"
#include "sanitise.h"

static void sanitise_epoll_pwait(struct syscallrecord *rec)
{
	/* timeout: -1 = block, 0 = return immediately, >0 = ms to wait */
	switch (rand() % 4) {
	case 0: rec->a4 = (unsigned long) -1; break;	/* block */
	case 1: rec->a4 = 0; break;			/* immediate */
	default: rec->a4 = 1 + (rand() % 100); break;	/* short wait */
	}
	avoid_shared_buffer(&rec->a2, rec->a3 * sizeof(struct epoll_event));
}

static void sanitise_epoll_pwait2(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a2, rec->a3 * sizeof(struct epoll_event));
}

struct syscallentry syscall_epoll_pwait = {
	.name = "epoll_pwait",
	.num_args = 6,
	.argtype = { [0] = ARG_FD_EPOLL, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_RANGE, [4] = ARG_ADDRESS, [5] = ARG_LEN },
	.argname = { [0] = "epfd", [1] = "events", [2] = "maxevents", [3] = "timeout", [4] = "sigmask", [5] = "sigsetsize" },
	.arg_params[2].range.low = 1,
	.arg_params[2].range.hi = 128,
	.sanitise = sanitise_epoll_pwait,
	.rettype = RET_BORING,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};

struct syscallentry syscall_epoll_pwait2 = {
	.name = "epoll_pwait2",
	.num_args = 6,
	.argtype = { [0] = ARG_FD_EPOLL, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_RANGE, [3] = ARG_ADDRESS, [4] = ARG_ADDRESS, [5] = ARG_LEN },
	.argname = { [0] = "epfd", [1] = "events", [2] = "maxevents", [3] = "timeout", [4] = "sigmask", [5] = "sigsetsize" },
	.arg_params[2].range.low = 1,
	.arg_params[2].range.hi = 128,
	.sanitise = sanitise_epoll_pwait2,
	.rettype = RET_BORING,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
