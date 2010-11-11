/*
 * SYSCALL_DEFINE4(timerfd_settime, int, ufd, int, flags,
	 const struct itimerspec __user *, utmr,
	 struct itimerspec __user *, otmr)
 */
{
	.name = "timerfd_settime",
	.num_args = 4,
	.arg1name = "ufd",
	.arg1type = ARG_FD,
	.arg2name = "flags",
	.arg3name = "utmr",
	.arg3type = ARG_ADDRESS,
	.arg4name = "otmr",
	.arg4type = ARG_ADDRESS,
},
