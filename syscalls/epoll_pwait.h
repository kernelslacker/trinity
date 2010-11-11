/*
 * SYSCALL_DEFINE4(epoll_wait, int, epfd, struct epoll_event __user *, events,
	 int, maxevents, int, timeout)
 */
{
	.name = "epoll_pwait",
	.num_args = 4,
	.arg1name = "epfd",
	.arg1type = ARG_FD,
	.arg2name = "events",
	.arg2type = ARG_ADDRESS,
	.arg3name = "maxevents",
	.arg4name = "timeout",
},
