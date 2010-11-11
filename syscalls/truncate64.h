/*
 * SYSCALL_DEFINE(truncate64)(const char __user * path, loff_t length)
 */
{
	.name = "truncate64",
	.num_args = 2,
	.arg1name = "path",
	.arg1type = ARG_ADDRESS,
	.arg2name = "length",
	.arg2type = ARG_LEN,
},
