/*
 * SYSCALL_DEFINE2(utimes, char __user *, filename, struct timeval __user *, utimes)
 */
{
	.name = "utimes",
	.num_args = 2,
	.arg1name = "filename",
	.arg1type = ARG_ADDRESS,
	.arg2name = "utimes",
	.arg2type = ARG_ADDRESS,
},
