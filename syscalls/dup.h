/*
 * SYSCALL_DEFINE1(dup, unsigned int, fildes)
 */
{
	.name = "dup",
	.num_args = 1,
	.arg1name = "fildes",
	.arg1type = ARG_FD,
},
