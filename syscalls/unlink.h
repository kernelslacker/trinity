/*
 * SYSCALL_DEFINE1(unlink, const char __user *, pathname)
 */
{
	.name = "unlink",
	.num_args = 1,
	.arg1name = "pathname",
	.arg1type = ARG_ADDRESS,
},
