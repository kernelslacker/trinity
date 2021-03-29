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
#include "sanitise.h"

struct syscallentry syscall_epoll_pwait = {
	.name = "epoll_pwait",
	.num_args = 6,
	.arg1name = "epfd",
	.arg1type = ARG_FD,
	.arg2name = "events",
	.arg2type = ARG_ADDRESS,
	.arg3name = "maxevents",
	.arg4name = "timeout",
	.arg5name = "sigmask",
	.arg6name = "sigsetsize",
	.rettype = RET_BORING,
	.flags = NEED_ALARM,
};

struct syscallentry syscall_epoll_pwait2 = {
	.name = "epoll_pwait2",
	.num_args = 6,
	.arg1name = "epfd",
	.arg1type = ARG_FD,
	.arg2name = "events",
	.arg2type = ARG_ADDRESS,
	.arg3name = "maxevents",
	.arg4name = "timeout",
	.arg5name = "sigmask",
	.arg6name = "sigsetsize",
	.rettype = RET_BORING,
	.flags = NEED_ALARM,
};
