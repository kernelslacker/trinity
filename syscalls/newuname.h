/*
 *
 * SYSCALL_DEFINE1(newuname, struct new_utsname __user *, name)
 */
{
	.name = "newuname",
	.num_args = 1,
	.arg1name = "name",
	.arg1type = ARG_ADDRESS,
},
