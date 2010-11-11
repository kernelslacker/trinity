/*
 * SYSCALL_DEFINE4(kexec_load, unsigned long, entry, unsigned long, nr_segments,
	struct kexec_segment __user *, segments, unsigned long, flags)
 */
{
	.name = "kexec_load",
	.num_args = 4,
	.flags = CAPABILITY_CHECK,
	.arg1name = "entry",
	.arg1type = ARG_ADDRESS,
	.arg2name = "nr_segments",
	.arg2type = ARG_LEN,
	.arg3name = "segments",
	.arg3type = ARG_ADDRESS,
	.arg4name = "flags",
},
