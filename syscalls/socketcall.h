/*
 * SYSCALL_DEFINE2(socketcall, int, call, unsigned long __user *, args)
 */
{
	.name = "socketcall",
	.num_args = 2,
	.arg1name = "call",
	.arg2name = "args",
	.arg2type = ARG_ADDRESS,
},
