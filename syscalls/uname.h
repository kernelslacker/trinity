/*
 * SYSCALL_DEFINE1(uname, struct old_utsname __user *, name)
 */
{
	.name = "uname",
	.num_args = 1,
	.arg1name = "name",
	.arg1type = ARG_ADDRESS,
},
