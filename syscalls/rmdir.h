/*
 * SYSCALL_DEFINE1(rmdir, const char __user *, pathname)
 */
{
	.name =  "rmdir",
	.num_args = 1,
	.arg1name = "pathname",
	.arg1type = ARG_ADDRESS,
},
