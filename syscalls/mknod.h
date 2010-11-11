/*
 * SYSCALL_DEFINE3(mknod, const char __user *, filename, int, mode, unsigned, dev)
 */
{
	.name = "mknod",
	.num_args = 3,
	.arg1name = "filename",
	.arg1type = ARG_ADDRESS,
	.arg2name = "mode",
	.arg3name = "dev",
},
