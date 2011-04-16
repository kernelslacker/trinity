/*
 * SYSCALL_DEFINE5(remap_file_pages, unsigned long, start, unsigned long, size,
	 unsigned long, prot, unsigned long, pgoff, unsigned long, flags)
 */
{
	.name = "remap_file_pages",
	.sanitise = sanitise_remap_file_pages,
	.num_args = 5,
	.arg1name = "start",
	.arg1type = ARG_ADDRESS,
	.arg2name = "size",
	.arg2type = ARG_LEN,
	.arg3name = "prot",
	.arg4name = "pgoff",
	.arg5name = "flags",
	.arg5type = ARG_LIST,
	.arg5list = {
		.num = 1,
		.values = { MAP_NONBLOCK },
	},
},
