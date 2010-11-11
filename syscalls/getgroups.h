/*
 * SYSCALL_DEFINE2(getgroups, int, gidsetsize, gid_t __user *, grouplist)
 */
{
	.name = "getgroups",
	.num_args = 2,
	.arg1name = "gidsetsize",
	.arg2type = ARG_ADDRESS,
	.arg2name = "grouplist",
},
