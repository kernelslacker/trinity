/*
 * SYSCALL_DEFINE3(readv, unsigned long, fd, const struct iovec __user *, vec, unsigned long>
 */
{
	.name = "readv",
	.num_args = 3,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "vec",
	.arg2type = ARG_ADDRESS,
	.arg3name = "vlen",
	.arg3type = ARG_LEN,
},
