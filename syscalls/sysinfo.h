/*
 * SYSCALL_DEFINE1(sysinfo, struct sysinfo __user *, info)
 */
{
	.name = "sysinfo",
	.num_args = 1,
	.arg1name = "info",
	.arg1type = ARG_ADDRESS,
},
