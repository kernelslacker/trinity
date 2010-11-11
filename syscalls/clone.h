/*
   long sys_clone(unsigned long clone_flags, unsigned long newsp,
	void __user *parent_tid, void __user *child_tid, struct pt_regs *regs)
 */
{
	.name = "clone",
	.num_args = 5,
	.flags = AVOID_SYSCALL,
	.arg1name = "clone_flags",
	.arg2name = "newsp",
	.arg2type = ARG_ADDRESS,
	.arg3name = "parent_tid",
	.arg3type = ARG_ADDRESS,
	.arg4name = "child_tid",
	.arg4type = ARG_ADDRESS,
	.arg5name = "regs",
	.arg5type = ARG_ADDRESS,
},
