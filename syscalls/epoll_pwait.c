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
}

struct syscallentry syscall_epoll_pwait = {
	.name = "epoll_pwait",
	.num_args = 6,
	.arg1name = "epfd",
	.arg1type = ARG_FD_EPOLL,
	.arg2name = "events",
	.arg2type = ARG_ADDRESS,
	.arg3name = "maxevents",
	.arg3type = ARG_RANGE,
	.low3range = 1,
	.hi3range = 128,
	.arg4name = "timeout",
	.arg5name = "sigmask",
	.arg5type = ARG_ADDRESS,
	.arg6name = "sigsetsize",
	.arg6type = ARG_LEN,
	.sanitise = sanitise_epoll_pwait,
	.rettype = RET_BORING,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};

struct syscallentry syscall_epoll_pwait2 = {
	.name = "epoll_pwait2",
	.num_args = 6,
	.arg1name = "epfd",
	.arg1type = ARG_FD_EPOLL,
	.arg2name = "events",
	.arg2type = ARG_ADDRESS,
	.arg3name = "maxevents",
	.arg3type = ARG_RANGE,
	.low3range = 1,
	.hi3range = 128,
	.arg4name = "timeout",
	.arg4type = ARG_ADDRESS,
	.arg5name = "sigmask",
	.arg5type = ARG_ADDRESS,
	.arg6name = "sigsetsize",
	.arg6type = ARG_LEN,
	.rettype = RET_BORING,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
