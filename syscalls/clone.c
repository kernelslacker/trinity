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
	CLONE_PIDFD, CLONE_NEWTIME,
};

/*
 * Enforce mandatory flag dependencies from the kernel:
 *   CLONE_THREAD requires CLONE_SIGHAND
 *   CLONE_SIGHAND requires CLONE_VM
 */
static void sanitise_clone(struct syscallrecord *rec)
{
	if (rec->a1 & CLONE_THREAD)
		rec->a1 |= CLONE_SIGHAND;
	if (rec->a1 & CLONE_SIGHAND)
		rec->a1 |= CLONE_VM;
}

struct syscallentry syscall_clone = {
	.name = "clone",
	.group = GROUP_PROCESS,
	.num_args = 5,
	.flags = AVOID_SYSCALL,
	.argtype = { [0] = ARG_LIST, [1] = ARG_ADDRESS, [2] = ARG_ADDRESS, [3] = ARG_ADDRESS, [4] = ARG_ADDRESS },
	.argname = { [0] = "clone_flags", [1] = "newsp", [2] = "parent_tid", [3] = "child_tid", [4] = "regs" },
	.arg1list = ARGLIST(clone_flags),
	.sanitise = sanitise_clone,
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
	.group = GROUP_PROCESS,
	.num_args = 6,
	.flags = AVOID_SYSCALL,
	.argtype = { [0] = ARG_LIST, [1] = ARG_ADDRESS, [2] = ARG_LEN, [3] = ARG_ADDRESS, [4] = ARG_ADDRESS, [5] = ARG_ADDRESS },
	.argname = { [0] = "flags", [1] = "ustack_base", [2] = "ustack_size", [3] = "parent_tidptr", [4] = "child_tidptr", [5] = "tls" },
	.arg1list = ARGLIST(clone_flags),
	.sanitise = sanitise_clone,
	.rettype = RET_PID_T,
};
#endif
