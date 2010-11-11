/*
 * SYSCALL_DEFINE3(getsockname, int, fd, struct sockaddr __user *, usockaddr, int __user *, usockaddr_len)
 */
{
	.name = "getsockname",
	.num_args = 3,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "usockaddr",
	.arg2type = ARG_ADDRESS,
	.arg3name = "usockaddr_len",
	.arg3type = ARG_ADDRESS,
},
