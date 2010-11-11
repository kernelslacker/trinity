/*
 * SYSCALL_DEFINE2(newlstat, const char __user *, filename, struct stat __user *, statbuf)
 */
{
	.name = "newlstat",
	.num_args = 2,
	.arg1name = "filename",
	.arg1type = ARG_ADDRESS,
	.arg2name = "statbuf",
	.arg2type = ARG_ADDRESS,
},
