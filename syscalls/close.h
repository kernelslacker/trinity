/*
 * SYSCALL_DEFINE1(close, unsigned int, fd)
 */
{
	.name = "close",
	.num_args = 1,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.flags = AVOID_SYSCALL,
},
