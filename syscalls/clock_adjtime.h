/*
 *SYSCALL_DEFINE2(clock_adjtime, const clockid_t, which_clock,
 *		struct timex __user *, utx)
 */

{
	.name = "clock_adjtime",
	.num_args = 2,
	.arg1name = "which_clock",
	.arg2name = "utx",
	.arg2type = ARG_ADDRESS,
},
