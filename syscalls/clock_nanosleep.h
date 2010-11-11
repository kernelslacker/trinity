/*
 * SYSCALL_DEFINE4(clock_nanosleep, const clockid_t, which_clock, int, flags,
	const struct timespec __user *, rqtp,
	struct timespec __user *, rmtp)
 */
{
	.name = "clock_nanosleep",
	.num_args = 4,
	.arg1name = "which_clock",
	.arg2name = "flags",
	.arg3name = "rqtp",
	.arg3type = ARG_ADDRESS,
	.arg4name = "rmtp",
	.arg4type = ARG_ADDRESS,
},
