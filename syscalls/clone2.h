/*
 * sys_clone2(u64 flags, u64 ustack_base, u64 ustack_size, u64 parent_tidptr, u64 child_tidptr,
              u64 tls)
 */
{
	.name = "clone",
	.num_args = 6,
	.flags = AVOID_SYSCALL,
	.arg1name = "flags",
	.arg2name = "ustack_base",
	.arg2type = ARG_ADDRESS,
	.arg3name = "ustack_size",
	.arg4name = "parent_tidptr",
	.arg4type = ARG_ADDRESS,
	.arg5name = "child_tidptr",
	.arg5type = ARG_ADDRESS,
	.arg6name = "tls",
	.arg6type = ARG_ADDRESS,

},
