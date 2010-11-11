/*
 * SYSCALL_DEFINE6(move_pages, pid_t, pid, unsigned long, nr_pages,
	const void __user * __user *, pages,
	const int __user *, nodes,
	int __user *, status, int, flags)
 */
{
	.name = "move_pages",
	.num_args = 6,
	.arg1name = "pid",
	.arg1type = ARG_PID,
	.arg2name = "nr_pages",
	.arg2type = ARG_LEN,
	.arg3name = "pages",
	.arg3type = ARG_ADDRESS,
	.arg4name = "nodes",
	.arg4type = ARG_ADDRESS,
	.arg5name = "status",
	.arg5type = ARG_ADDRESS,
	.arg6name = "flags",
},
