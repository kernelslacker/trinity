/*
 * SYSCALL_DEFINE2(fremovexattr, int, fd, const char __user *, name)
 */
{
	.name = "fremovexattr",
	.num_args = 2,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "name",
	.arg2type = ARG_ADDRESS,
},
