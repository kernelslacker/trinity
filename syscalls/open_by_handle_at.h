/*
 * SYSCALL_DEFINE3(open_by_handle_at, int, mountdirfd,
 *               struct file_handle __user *, handle,
 *               int, flags)
 */

{
	.name = "open_by_handle_at",
	.num_args = 3,
	.arg1name = "mountdirfd",
	.arg1type = ARG_FD,
	.arg2name = "handle",
	.arg2type = ARG_ADDRESS,
	.arg3name = "flags",
},
