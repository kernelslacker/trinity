/*
 * SYSCALL_DEFINE3(getdents, unsigned int, fd,
    struct linux_dirent __user *, dirent, unsigned int, count)
 */
{
	.name = "getdents",
	.num_args = 3,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "dirent",
	.arg2type = ARG_ADDRESS,
	.arg3name = "count",
	.arg3type = ARG_LEN,
},
