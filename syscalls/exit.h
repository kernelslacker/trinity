/*
 * SYSCALL_DEFINE1(exit, int, error_code)
 */
{
	.name = "exit",
	.num_args = 1,
	.flags = AVOID_SYSCALL,
	.arg1name = "error_code",
},
