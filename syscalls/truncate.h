/*
 * SYSCALL_DEFINE2(truncate, const char __user *, path, long, length)
 */
{
	.name = "truncate",
	.num_args = 2,
	.arg1name = "path",
	.arg1type = ARG_ADDRESS,
	.arg2name = "length",
	.arg2type = ARG_LEN,
},
