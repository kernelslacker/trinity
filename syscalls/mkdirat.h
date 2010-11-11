/*
 * SYSCALL_DEFINE3(mkdirat, int, dfd, const char __user *, pathname, int, mode)
 */
{
	.name = "mkdirat",
	.num_args = 3,
	.arg1name = "dfd",
	.arg1type = ARG_FD,
	.arg2name = "pathname",
	.arg2type = ARG_ADDRESS,
	.arg3name = "mode",
},
