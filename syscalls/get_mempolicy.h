/*
 * SYSCALL_DEFINE5(get_mempolicy, int __user *, policy,
	unsigned long __user *, nmask, unsigned long, maxnode,
	unsigned long, addr, unsigned long, flags)
 */
{
	.name = "get_mempolicy",
	.num_args = 5,
	.arg1name = "policy",
	.arg1type = ARG_ADDRESS,
	.arg2name = "nmask",
	.arg2type = ARG_ADDRESS,
	.arg3name = "maxnode",
	.arg4name = "addr",
	.arg4type = ARG_ADDRESS,
	.arg5name = "flags",
},
