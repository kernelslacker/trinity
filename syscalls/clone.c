/*
 * long sys_clone(unsigned long clone_flags, unsigned long newsp,
	void __user *parent_tid, void __user *child_tid, struct pt_regs *regs)
 * On success, the thread ID of the child process is returned in the caller's thread of execution.
 * On failure, -1 is returned in the caller's context, no child process will be created, and errno will be set appropriately.
 */

#include <linux/sched.h>
#include "sanitise.h"

#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP                0x02000000      /* New cgroup namespace */
#endif

static unsigned long clone_flags[] = {
	CSIGNAL,
	CLONE_VM, CLONE_FS, CLONE_FILES, CLONE_SIGHAND,
	CLONE_PTRACE, CLONE_VFORK, CLONE_PARENT, CLONE_THREAD,
	CLONE_NEWNS, CLONE_SYSVSEM, CLONE_SETTLS, CLONE_PARENT_SETTID,
	CLONE_CHILD_CLEARTID, CLONE_DETACHED, CLONE_UNTRACED, CLONE_CHILD_SETTID,
	CLONE_NEWCGROUP, CLONE_NEWUTS, CLONE_NEWIPC, CLONE_NEWUSER,
	CLONE_NEWPID, CLONE_NEWNET, CLONE_IO,
};

struct syscallentry syscall_clone = {
	.name = "clone",
	.num_args = 5,
	.flags = AVOID_SYSCALL,
	.arg1name = "clone_flags",
	.arg1type = ARG_LIST,
	.arg1list = ARGLIST(clone_flags),
	.arg2name = "newsp",
	.arg2type = ARG_ADDRESS,
	.arg3name = "parent_tid",
	.arg3type = ARG_ADDRESS,
	.arg4name = "child_tid",
	.arg4type = ARG_ADDRESS,
	.arg5name = "regs",
	.arg5type = ARG_ADDRESS,
	.rettype = RET_PID_T,
};


#ifdef __ia64__
/*
 * sys_clone2(u64 flags, u64 ustack_base, u64 ustack_size, u64 parent_tidptr, u64 child_tidptr, u64 tls)
 *
 * On success, the thread ID of the child process is returned in the caller's thread of execution.
 * On failure, -1 is returned in the caller's context, no child process will be created, and errno will be set appropriately.
 */

struct syscallentry syscall_clone2 = {
	.name = "clone",
	.num_args = 6,
	.flags = AVOID_SYSCALL,
	.arg1name = "flags",
	.arg1type = ARG_LIST,
	.arg1list = ARGLIST(clone_flags),
	.arg2name = "ustack_base",
	.arg2type = ARG_ADDRESS,
	.arg3name = "ustack_size",
	.arg3type = ARG_LEN,
	.arg4name = "parent_tidptr",
	.arg4type = ARG_ADDRESS,
	.arg5name = "child_tidptr",
	.arg5type = ARG_ADDRESS,
	.arg6name = "tls",
	.arg6type = ARG_ADDRESS,
	.rettype = RET_PID_T,
};
#endif
