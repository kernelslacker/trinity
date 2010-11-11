/*
 * SYSCALL_DEFINE(fallocate)(int fd, int mode, loff_t offset, loff_t len)
 */
{
	.name = "fallocate",
	.num_args = 4,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "mode",
	.arg3name = "offset",
	.arg4name = "len",
	.arg4type = ARG_LEN,
},
