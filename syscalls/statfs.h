/*
 * SYSCALL_DEFINE2(statfs, const char __user *, pathname, struct statfs __user *, buf)
 */
{
	.name = "statfs",
	.num_args = 2,
	.arg1name = "pathname",
	.arg1type = ARG_ADDRESS,
	.arg2name = "buf",
	.arg2type = ARG_ADDRESS,
},
