/*
 * SYSCALL_DEFINE2(kill, pid_t, pid, int, sig)
 */
{
	.name = "kill",
	.num_args = 2,
	.arg1name = "pid",
	.arg1type = ARG_PID,
	.arg2name = "sig",
},
