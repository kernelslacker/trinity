/*
 * SYSCALL_DEFINE5(fchownat, int, dfd, const char __user *, filename, uid_t, user,
	gid_t, group, int, flag)
 */
{
	.name = "fchownat",
	.num_args = 5,
	.arg1name = "dfd",
	.arg1type = ARG_FD,
	.arg2name = "filename",
	.arg2type = ARG_ADDRESS,
	.arg3name = "user",
	.arg4name = "group",
	.arg5name = "flag",
},
