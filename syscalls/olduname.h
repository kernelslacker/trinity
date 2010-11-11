/*
 * SYSCALL_DEFINE1(uname, struct old_utsname __user *, name)
 */
{
	.name = "olduname",
	.num_args = 1,
	.arg1name = "name",
	.arg1type = ARG_ADDRESS,
},
