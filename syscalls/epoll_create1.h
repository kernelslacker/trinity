/*
 * SYSCALL_DEFINE1(epoll_create1, int, flags)
 */

#define EPOLL_CLOEXEC 02000000

{
	.name = "epoll_create1",
	.num_args = 1,
	.arg1name = "flags",
	.arg1type = ARG_LIST,
	.arg1list = {
		.num = 1,
		.values = { EPOLL_CLOEXEC },
	},
},
