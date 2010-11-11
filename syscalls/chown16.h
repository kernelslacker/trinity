/*
 * SYSCALL_DEFINE3(chown16, const char __user *, filename, old_uid_t, user, old_gid_t, group)
 */
{
	.name = "chown",
	.num_args = 3,
	.arg1name = "filename",
	.arg1type = ARG_ADDRESS,
	.arg2name = "user",
	.arg3name = "group",
},
