/*
 * SYSCALL_DEFINE2(munmap, unsigned long, addr, size_t, len)
 */
{
	.name = "munmap",
	.num_args = 2,
	.arg1name = "addr",
	.arg1type = ARG_ADDRESS,
	.arg2name = "len",
	.arg2type = ARG_LEN,
},
