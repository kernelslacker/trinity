/*
 * SYSCALL_DEFINE6(mmap_pgoff, unsigned long, addr, unsigned long, len,
                 unsigned long, prot, unsigned long, flags,
                 unsigned long, fd, unsigned long, pgoff)
 */
{
	.name = "mmap_pgoff",
	.num_args = 6,
	.arg1name = "addr",
	.arg1type = ARG_ADDRESS,
	.arg2name = "len",
	.arg2type = ARG_LEN,
	.arg3name = "prot",
	.arg4name = "flags",
	.arg5name = "fd",
	.arg5type = ARG_FD,
	.arg6name = "pgoff",
},
