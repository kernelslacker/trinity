/*
 * SYSCALL_DEFINE4(readlinkat, int, dfd, const char __user *, pathname,
	 char __user *, buf, int, bufsiz)
 */
{
	.name = "readlinkat",
	.num_args = 4,
	.arg1name = "dfd",
	.arg1type = ARG_FD,
	.arg2name = "pathname",
	.arg2type = ARG_ADDRESS,
	.arg3name = "buf",
	.arg3type = ARG_ADDRESS,
	.arg4name = "bufsiz",
	.arg4type = ARG_LEN,
},
