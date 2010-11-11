/*
 * SYSCALL_DEFINE3(inotify_add_watch, int, fd, const char __user *, pathname, u32, mask)
 */
{
	.name = "inotify_add_watch",
	.num_args = 3,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "pathname",
	.arg2type = ARG_ADDRESS,
	.arg3name = "mask",
},
