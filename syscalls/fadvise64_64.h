/*
 * SYSCALL_DEFINE(fadvise64_64)(int fd, loff_t offset, loff_t len, int advice)
 */
{
	.name = "fadvise64",
	.num_args = 4,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "offset",
	.arg3name = "len",
	.arg3type = ARG_LEN,
	.arg4name = "advice",
},
