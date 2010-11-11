/*
 * SYSCALL_DEFINE1(chdir, const char __user *, filename)
 */
{
	.name = "chdir",
	.num_args = 1,
	.arg1name = "filename",
	.arg1type = ARG_ADDRESS,
},
