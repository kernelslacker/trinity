/*
 * SYSCALL_DEFINE1(swapoff, const char __user *, specialfile)
 */
{
	.name = "swapoff",
	.num_args = 1,
	.arg1name = "specialfile",
	.arg1type = ARG_ADDRESS,
},
