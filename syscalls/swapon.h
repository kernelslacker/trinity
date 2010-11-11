/*
 * SYSCALL_DEFINE2(swapon, const char __user *, specialfile, int, swap_flags
 */
{
	.name = "swapon",
	.num_args = 2,
	.arg1name = "specialfile",
	.arg1type = ARG_ADDRESS,
	.arg2name = "swap_flags",
},
