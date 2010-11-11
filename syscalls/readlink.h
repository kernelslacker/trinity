/*
 * SYSCALL_DEFINE3(readlink, const char __user *, path, char __user *, buf, int, bufsiz)
 */
{
	.name = "readlink",
	.num_args = 3,
	.arg1name = "path",
	.arg1type = ARG_ADDRESS,
	.arg2name = "buf",
	.arg2type = ARG_ADDRESS,
	.arg3name = "bufsiz",
	.arg3type = ARG_LEN,
},
