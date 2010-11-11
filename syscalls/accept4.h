/*
 * SYSCALL_DEFINE4(accept4, int, fd, struct sockaddr __user *, upeer_sockaddr,
	 int __user *, upeer_addrlen, int, flags)
 */
{
	.name = "accept4",
	.num_args = 4,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "upeer_sockaddr",
	.arg2type = ARG_ADDRESS,
	.arg3name = "upeer_addrlen",
	.arg3type = ARG_ADDRESS,
	.arg4name = "flags",
},
