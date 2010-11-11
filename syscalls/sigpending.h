/*
 * SYSCALL_DEFINE1(sigpending, old_sigset_t __user *, set)
 */
{
	.name = "sigpending",
	.num_args = 1,
	.arg1name = "set",
	.arg1type = ARG_ADDRESS,
},
