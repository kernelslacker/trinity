/*
 * SYSCALL_DEFINE3(lchown16, const char __user *, filename, old_uid_t, user, old_gid_t, group)
 */
{
	.name = "lchown16",
	.num_args = 3,
	.arg1name = "filename",
	.arg1type = ARG_ADDRESS,
	.arg2name = "user",
	.arg3name = "group",
},
