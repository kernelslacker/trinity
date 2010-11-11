/*
 * SYSCALL_DEFINE2(setrlimit, unsigned int, resource, struct rlimit __user *, rlim)
 */
{
	.name = "setrlimit",
	.num_args = 2,
	.arg1name = "resource",
	.arg1type = ARG_ADDRESS,
	.arg2name = "rlim",
},
