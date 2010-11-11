/*
 * SYSCALL_DEFINE(fanotify_mark)(int fanotify_fd, unsigned int flags,
	__u64 mask, int dfd, const char  __user * pathname)
 */
{
	.name = "fanotify_mark",
	.num_args = 5,
	.arg1name = "fanotify_fd",
	.arg1type = ARG_FD,
	.arg2name = "flags",
	.arg3name = "mask",
	.arg4name = "dfd",
	.arg4type = ARG_FD,
	.arg5name = "pathname",
	.arg5type = ARG_ADDRESS,
	.sanitise = sanitise_fanotify_mark,
},
