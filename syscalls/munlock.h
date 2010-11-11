/*
 * SYSCALL_DEFINE2(munlock, unsigned long, start, size_t, len)
 */
{
	.name = "munlock",
	.num_args = 2,
	.arg1name = "start",
	.arg2name = "len",
	.arg2type = ARG_LEN,
},
