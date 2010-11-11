/*
 * SYSCALL_DEFINE3(listxattr, const char __user *, pathname, char __user *, list, size_t, size
 */
{
	.name = "listxattr",
	.num_args = 3,
	.arg1name = "pathname",
	.arg1type = ARG_ADDRESS,
	.arg2name = "list",
	.arg2type = ARG_ADDRESS,
	.arg3name = "size",
	.arg3type = ARG_LEN,
},
