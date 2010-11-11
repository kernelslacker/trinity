/*
 * SYSCALL_DEFINE1(sysctl, struct __sysctl_args __user *, args
 */
{
	.name = "sysctl",
	.num_args = 1,
	.arg1name = "args",
	.arg1type = ARG_ADDRESS,
},
