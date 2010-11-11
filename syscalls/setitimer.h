/*
 * SYSCALL_DEFINE3(setitimer, int, which, struct itimerval __user *, value, struct itimerval __user *, ovalue)
 */
{
	.name = "setitimer",
	.num_args = 3,
	.arg1name = "which",
	.arg2name = "value",
	.arg2type = ARG_ADDRESS,
	.arg3name = "ovalue",
	.arg3type = ARG_ADDRESS,
},
