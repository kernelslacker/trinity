/*
 * SYSCALL_DEFINE1(stime, time_t __user *, tptr)
 */
{
	.name = "stime",
	.num_args = 1,
	.arg1name = "tptr",
	.arg1type = ARG_ADDRESS,
},
