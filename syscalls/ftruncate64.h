/*
 * SYSCALL_DEFINE(ftruncate64)(unsigned int fd, loff_t length)
 */
{
	.name = "ftruncate64",
	.num_args = 2,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "length",
	.arg2type = ARG_LEN,
},
