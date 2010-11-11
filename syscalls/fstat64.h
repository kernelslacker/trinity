/*
 * SYSCALL_DEFINE2(fstat64, unsigned long, fd, struct stat64 __user *, statbuf)
 */
{
	.name = "fstat64",
	.num_args = 2,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "statbuf",
	.arg2type = ARG_ADDRESS,
},
