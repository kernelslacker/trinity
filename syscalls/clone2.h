/*
 * sys_clone2(u64 flags, u64 ustack_base, u64 ustack_size, u64 parent_tidptr, u64 child_tidptr,
              u64 tls)
 */

#include <linux/sched.h>

{
	.name = "clone",
	.num_args = 6,
	.flags = AVOID_SYSCALL,
	.arg1name = "flags",
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
	.arg2name = "ustack_base",
	.arg2type = ARG_ADDRESS,
	.arg3name = "ustack_size",
	.arg4name = "parent_tidptr",
	.arg4type = ARG_ADDRESS,
	.arg5name = "child_tidptr",
	.arg5type = ARG_ADDRESS,
	.arg6name = "tls",
	.arg6type = ARG_ADDRESS,
},
