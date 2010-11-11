/*
 * SYSCALL_DEFINE3(statfs64, const char __user *, pathname, size_t, sz, struct statfs64 __user *, buf)
 */
{
	.name = "statfs64",
	.num_args = 2,
	.arg1name = "pathname",
	.arg1type = ARG_ADDRESS,
	.arg2name = "sz",
	.arg3name = "buf",
	.arg3type = ARG_ADDRESS,
},
