/*
 * SYSCALL_DEFINE1(time, time_t __user *, tloc)
 */
{
	.name = "time",
	.num_args = 1,
	.arg1name = "tloc",
	.arg1type = ARG_ADDRESS,
},
