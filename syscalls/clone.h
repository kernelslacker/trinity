/*
   long sys_clone(unsigned long clone_flags, unsigned long newsp,
	void __user *parent_tid, void __user *child_tid, struct pt_regs *regs)
 */

#include <linux/sched.h>

{
	.name = "clone",
	.num_args = 5,
	.flags = AVOID_SYSCALL,
	.arg1name = "clone_flags",
	.arg1type = ARG_LIST,
	.arg1list = {
		.num = 23,
		.values = { CSIGNAL,
			CLONE_VM, CLONE_FS, CLONE_FILES, CLONE_SIGHAND,
			CLONE_PTRACE, CLONE_VFORK, CLONE_PARENT, CLONE_THREAD,
			CLONE_NEWNS, CLONE_SYSVSEM, CLONE_SETTLS, CLONE_PARENT_SETTID,
			CLONE_CHILD_CLEARTID, CLONE_DETACHED, CLONE_UNTRACED, CLONE_CHILD_SETTID,
			CLONE_NEWUTS, CLONE_NEWIPC, CLONE_NEWUSER, CLONE_NEWPID,
			CLONE_NEWNET, CLONE_IO },
	},
	.arg2name = "newsp",
	.arg2type = ARG_ADDRESS,
	.arg3name = "parent_tid",
	.arg3type = ARG_ADDRESS,
	.arg4name = "child_tid",
	.arg4type = ARG_ADDRESS,
	.arg5name = "regs",
	.arg5type = ARG_ADDRESS,
},


