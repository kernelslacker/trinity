/*
 * SYSCALL_DEFINE3(mprotect, unsigned long, start, size_t, len, unsigned long, prot)
 */
{
	.name = "mprotect",
	.num_args = 3,
	.arg1name = "start",
	.arg1type = ARG_ADDRESS,
	.arg2name = "len",
	.arg2type = ARG_LEN,
	.arg3name = "prot",
	.sanitise = sanitise_mprotect,
},
