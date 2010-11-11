/*
 * SYSCALL_DEFINE2(delete_module, const char __user *, name_user, unsigned int, flags
 */
{
	.name = "delete_module",
	.num_args = 2,
	.flags = CAPABILITY_CHECK,
	.arg1name = "name_user",
	.arg1type = ARG_ADDRESS,
	.arg2name = "flags",
},
