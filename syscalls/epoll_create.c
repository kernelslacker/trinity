/*
 * SYSCALL_DEFINE1(epoll_create, int, size)
 *
 * On success, returns a nonnegative file descriptor.
 * On error, -1 is returned, and errno is set to indicate the error.
 */
#include "sanitise.h"

struct syscallentry syscall_epoll_create = {
	.name = "epoll_create",
	.num_args = 1,
	.arg1name = "size",
	.arg1type = ARG_LEN,
	.rettype = RET_FD,
};

/*
 * SYSCALL_DEFINE1(epoll_create1, int, flags)
 *
 * On success, returns a nonnegative file descriptor.
 * On error, -1 is returned, and errno is set to indicate the error.
*
 * If flags is 0, then, other than the fact that the obsolete size argument is dropped,
 * epoll_create1() is the same as epoll_create().
 */

#define EPOLL_CLOEXEC 02000000

struct syscallentry syscall_epoll_create1 = {
	.name = "epoll_create1",
	.num_args = 1,
	.arg1name = "flags",
	.arg1type = ARG_LIST,
	.arg1list = {
		.num = 1,
		.values = { EPOLL_CLOEXEC },
	},
	.rettype = RET_FD,
};
