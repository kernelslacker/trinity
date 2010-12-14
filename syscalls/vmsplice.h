/*
 * SYSCALL_DEFINE4(vmsplice, int, fd, const struct iovec __user *, iov,
	 unsigned long, nr_segs, unsigned int, flags)
 */
{
	.name = "vmsplice",
	.num_args = 4,
	.sanitise = sanitise_vmsplice,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "iov",
	.arg2type = ARG_ADDRESS,
	.arg3name = "nr_segs",
	.arg3type = ARG_LEN,
	.arg4name = "flags",
	.arg4type = ARG_LIST,
	.arg4list = {
		.num = 23,
		.values = { SPLICE_F_MOVE, SPLICE_F_NONBLOCK, SPLICE_F_MORE, SPLICE_F_GIFT },
	}
},
