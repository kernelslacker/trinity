/*
 * SYSCALL_DEFINE2(mkdir, const char __user *, pathname, int, mode)
 */
{
	.name = "mkdir",
	.num_args = 2,
	.arg1name = "pathname",
	.arg1type = ARG_ADDRESS,
	.arg2name = "mode",
},
