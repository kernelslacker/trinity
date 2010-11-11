/*
 * SYSCALL_DEFINE2(pipe2, int __user *, fildes, int, flags)
 */
{
	.name = "pipe2",
	.num_args = 2,
	.arg1name = "fildes",
	.arg1type = ARG_ADDRESS,
	.arg2name = "flags",
},
