/*
 * SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,
                   struct stat __user *, statbuf, int, flag)
 */
{
	.name = "newfstatat",
	.num_args = 4,
	.arg1name = "dfd",
	.arg1type = ARG_FD,
	.arg2name = "filename",
	.arg2type = ARG_ADDRESS,
	.arg3name = "statbug",
	.arg3type = ARG_ADDRESS,
	.arg4name = "flag",
	.arg4type = ARG_LIST,
	.arg4list = {
		.num = 2,
		.values = { 0, AT_SYMLINK_NOFOLLOW },
	},
},
