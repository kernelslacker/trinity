/*
 * SYSCALL_DEFINE2(getrusage, int, who, struct rusage __user *, ru)
 */
{
	.name = "getrusage",
	.num_args = 2,
	.arg1name = "who",
	.arg2name = "ru",
	.arg2type = ARG_ADDRESS,
},
