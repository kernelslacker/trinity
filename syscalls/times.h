/*
 * SYSCALL_DEFINE1(times, struct tms __user *, tbuf)
 */
{
	.name = "times",
	.num_args = 1,
	.arg1name = "tbuf",
	.arg1type = ARG_ADDRESS,
},
