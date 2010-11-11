/*
 * SYSCALL_DEFINE3(fchown, unsigned int, fd, uid_t, user, gid_t, group)
 */
{
	.name = "fchown",
	.num_args = 3,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "user",
	.arg3name = "group",
},
