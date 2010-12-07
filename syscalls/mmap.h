/*
 * SYSCALL_DEFINE6(mmap, unsigned long, addr, unsigned long, len,
	unsigned long, prot, unsigned long, flags,
	unsigned long, fd, unsigned long, off)
 */
{
	.name = "mmap",
	.num_args = 6,
	.sanitise = sanitise_mmap,
	.arg1name = "addr",
	.arg1type = ARG_ADDRESS,
	.arg2name = "len",
	.arg2type = ARG_LEN,
	.arg3name = "prot",
	.arg4name = "flags",
	.arg4type = ARG_LIST,
	.arg4list = {
		.num = 9,
		.values = { MAP_GROWSDOWN, MAP_DENYWRITE, MAP_EXECUTABLE, MAP_LOCKED, MAP_NORESERVE, MAP_POPULATE, MAP_NONBLOCK, MAP_STACK, MAP_HUGETLB },
	},
	.arg5name = "fd",
	.arg5type = ARG_FD,
	.arg6name = "off",
},
