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
	.arg2type = ARG_LIST,
	.arg2list = {
		.num = 8,
		.values = { FAN_MARK_ADD, FAN_MARK_REMOVE, FAN_MARK_DONT_FOLLOW, FAN_MARK_ONLYDIR,
			    FAN_MARK_MOUNT, FAN_MARK_IGNORED_MASK, FAN_MARK_IGNORED_SURV_MODIFY, FAN_MARK_FLUSH },
	},
	.arg3name = "mask",
	.arg4name = "dfd",
	.arg4type = ARG_FD,
	.arg5name = "pathname",
	.arg5type = ARG_ADDRESS,
	.sanitise = sanitise_fanotify_mark,
},


