/*
 * SYSCALL_DEFINE3(llistxattr, const char __user *, pathname, char __user *, list, size_t, size)
 */
{
	.name = "llistxattr",
	.arg1name = "pathname",
	.arg1type = ARG_ADDRESS,
	.arg2name = "list",
	.arg2type = ARG_ADDRESS,
	.arg3name = "size",
	.arg3type = ARG_LEN,
	.num_args = 3,
},
