/*
 * SYSCALL_DEFINE1(chroot, const char __user *, filename)
 */
{
	.name = "chroot",
	.num_args = 1,
	.arg1name = "filename",
	.arg1type = ARG_ADDRESS,
},
