/*
 * SYSCALL_DEFINE1(acct, const char __user *, name)
 */
{
	.name = "acct",
	.num_args = 1,
	.arg1name = "name",
	.arg1type = ARG_ADDRESS,
},
