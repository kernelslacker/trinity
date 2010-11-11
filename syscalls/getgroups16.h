/*
 * SYSCALL_DEFINE2(getgroups16, int, gidsetsize, old_gid_t __user *, grouplist)
 */
{
	.name = "getgroups16",
	.num_args = 2,
	.arg1name = "gidsetsize",
	.arg2type = ARG_ADDRESS,
	.arg2name = "grouplist",
},
