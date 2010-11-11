/*
 * SYSCALL_DEFINE2(ustat, unsigned, dev, struct ustat __user *, ubuf)
 */
{
	.name = "ustat",
	.num_args = 2,
	.arg1name = "dev",
	.arg2name = "ubuf",
	.arg2type = ARG_ADDRESS,
},
