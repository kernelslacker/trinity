/*
 * SYSCALL_DEFINE1(uselib, const char __user *, library)
 */
{
	.name = "ni_syscall (uselib)",
	.num_args = 0,
	.flags = NI_SYSCALL,
	.arg1name = "library",
	.arg1type = ARG_ADDRESS,
},
