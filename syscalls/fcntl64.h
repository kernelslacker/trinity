/*
 * SYSCALL_DEFINE3(fcntl64, unsigned int, fd, unsigned int, cmd,
                 unsigned long, arg)
 */
{
	.name = "fcntl64",
	.num_args = 3,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "cmd",
	.arg3name = "arg",
},
