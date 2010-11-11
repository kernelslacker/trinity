/*
 * SYSCALL_DEFINE2(getrlimit, unsigned int, resource, struct rlimit __user *, rlim)
 */
{
	.name = "getrlimit",
	.num_args = 2,
	.arg1name = "resource",
	.arg2name = "rlim",
	.arg2type = ARG_ADDRESS,
},
