/*
 * SYSCALL_DEFINE2(signal, int, sig, __sighandler_t, handler)
 */
{
	.name = "signal",
	.num_args = 2,
	.arg1name = "sig",
	.arg2name = "handler",
	.arg2type = ARG_ADDRESS,
},
