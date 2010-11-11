/*
 * SYSCALL_DEFINE1(sched_getscheduler, pid_t, pid)
 */
{
	.name = "sched_getscheduler",
	.num_args = 1,
	.arg1name = "pid",
	.arg1type = ARG_PID,
},
