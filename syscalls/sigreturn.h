/*
 * unsigned long sys_sigreturn(struct pt_regs *regs)
 */
{
	.name = "rt_sigreturn",
	.num_args = 1,
	.flags = AVOID_SYSCALL,
	.arg1name = "regs",
	.arg1type = ARG_ADDRESS,
},
