/*
 * SYSCALL_DEFINE2(creat, const char __user *, pathname, int, mode)
 */
{
	.name = "creat",
	.num_args = 2,
	.arg1name = "pathname",
	.arg1type = ARG_ADDRESS,
	.arg2name = "mode",
},
