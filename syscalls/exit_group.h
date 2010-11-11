/*
 * SYSCALL_DEFINE1(exit_group, int, error_code)
 */
{
	.name = "exit_group",
	.num_args = 1,
	.flags = AVOID_SYSCALL,
	.arg1name = "error_code",
},
