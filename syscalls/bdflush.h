/*
 * SYSCALL_DEFINE2(bdflush, int, func, long, data)
 */
{
	.name = "bdflush",
	.num_args = 2,
	.arg1name = "func",
	.arg2name = "data",
	.arg2type = ARG_ADDRESS,
},
