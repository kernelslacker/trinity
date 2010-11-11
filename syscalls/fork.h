/*
   int sys_fork(struct pt_regs *regs)
 */
{
	.name = "fork",
	.num_args = 1,
	.flags = AVOID_SYSCALL,
	.arg1name = "regs",
},
