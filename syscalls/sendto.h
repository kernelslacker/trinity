/*
 * SYSCALL_DEFINE6(sendto, int, fd, void __user *, buff, size_t, len,
	 unsigned, flags, struct sockaddr __user *, addr,
	 int, addr_len)
 */
{
	.name = "sendto",
	.num_args = 6,
	.sanitise = sanitise_sendto,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "buff",
	.arg2type = ARG_ADDRESS,
	.arg3name = "len",
	.arg3type = ARG_LEN,
	.arg4name = "flags",
	.arg5name = "addr",
	.arg5type = ARG_ADDRESS,
	.arg6name = "addr_len",
	.arg6type = ARG_LEN,
},
