/*
 * SYSCALL_DEFINE4(signalfd4, int, ufd, sigset_t __user *, user_mask,
	 size_t, sizemask, int, flags)
 */
{
	.name = "signalfd4",
	.num_args = 4,
	.arg1name = "ufd",
	.arg1type = ARG_FD,
	.arg2name = "user_mask",
	.arg2type = ARG_ADDRESS,
	.arg3name = "sizemask",
	.arg4name = "flags",
},
