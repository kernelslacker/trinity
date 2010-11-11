/*
   int sys_vfork(struct pt_regs *regs)
 */
{
	.name = "vfork",
	.num_args = 1,
	.flags = AVOID_SYSCALL,
	.arg1name = "regs",
},
