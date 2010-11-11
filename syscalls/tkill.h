/*
 * SYSCALL_DEFINE2(tkill, pid_t, pid, int, sig)
 */
{
	.name = "tkill",
	.num_args = 2,
	.arg1name = "pid",
	.arg1type = ARG_PID,
	.arg2name = "sig",
},
