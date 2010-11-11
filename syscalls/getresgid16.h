/*
 * SYSCALL_DEFINE3(getresgid16, old_gid_t __user *, rgid, old_gid_t __user *, egid, old_gid_t __user *, sgid)
 */
{
	.name = "getresgid16",
	.num_args = 3,
	.arg1name = "rgid",
	.arg2name = "egid",
	.arg2type = ARG_ADDRESS,
	.arg3name = "sgid",
	.arg3type = ARG_ADDRESS,
},
