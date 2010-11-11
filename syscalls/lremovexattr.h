/*
 * SYSCALL_DEFINE2(lremovexattr, const char __user *, pathname, const char __user *, name)
 */
{
	.name = "lremovexattr",
	.num_args = 2,
	.arg1name = "pathname",
	.arg1type = ARG_ADDRESS,
	.arg2name = "name",
	.arg2type = ARG_ADDRESS,
},
