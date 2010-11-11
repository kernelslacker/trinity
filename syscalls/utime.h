/*
 * SYSCALL_DEFINE2(utime, char __user *, filename, struct utimbuf __user *, times)
 */
{
	.name = "utime",
	.num_args = 2,
	.arg1name = "filename",
	.arg1type = ARG_ADDRESS,
	.arg2name = "times",
	.arg2type = ARG_ADDRESS,
},
