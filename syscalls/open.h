/*
 * SYSCALL_DEFINE3(open, const char __user *, filename, int, flags, int, mode)
 */
{
	.name = "open",
	.num_args = 3,
	.arg1name = "filename",
	.arg1type = ARG_ADDRESS,
	.arg2name = "flags",
	.arg3name = "mode",
},
