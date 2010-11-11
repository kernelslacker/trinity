/*
 * SYSCALL_DEFINE4(tee, int, fdin, int, fdout, size_t, len, unsigned int, flags)
 */
{
	.name = "tee",
	.num_args = 4,
	.arg1name = "fdin",
	.arg1type = ARG_FD,
	.arg2name = "fdout",
	.arg2type = ARG_FD,
	.arg3name = "len",
	.arg3type = ARG_LEN,
	.arg4name = "flags",
},
