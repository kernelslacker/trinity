/*
 * long sys_clone(unsigned long clone_flags, unsigned long newsp,
	void __user *parent_tid, void __user *child_tid, struct pt_regs *regs)
 * On success, the thread ID of the child process is returned in the caller's thread of execution.
 * On failure, -1 is returned in the caller's context, no child process will be created, and errno will be set appropriately.
 */

#include <linux/sched.h>
#include "clone.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

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

static void sanitise_clone(struct syscallrecord *rec)
{
	enforce_clone_flag_deps(&rec->a1, true);
}

static void post_clone(struct syscallrecord *rec)
{
	/* Child branch: caller-side differentiation, nothing to validate here. */
	if (rec->retval == 0)
		return;

	/* Error branch: -1UL with errno set, valid failure shape. */
	if (rec->retval == (unsigned long)-1L)
		return;

	/*
	 * Kernel ABI: parent retval is the child pid in [1, PID_MAX_LIMIT=4194304],
	 * or -1UL on failure. Anything else is a corrupted retval (sign-extension
	 * tear or pid_ns translation bug) — reject before any caller routes it
	 * back into pid_alive()/waitpid() bookkeeping.
	 */
	if (rec->retval > 4194304UL) {
		output(0, "post_clone: rejected returned pid 0x%lx outside [1, PID_MAX_LIMIT=4194304] (and not -1)\n",
		       rec->retval);
		post_handler_corrupt_ptr_bump(rec, NULL);
		return;
	}
}

struct syscallentry syscall_clone = {
	.name = "clone",
	.group = GROUP_PROCESS,
	.num_args = 5,
	.flags = AVOID_SYSCALL,
	.argtype = { [0] = ARG_LIST, [1] = ARG_ADDRESS, [2] = ARG_ADDRESS, [3] = ARG_ADDRESS, [4] = ARG_ADDRESS },
	.argname = { [0] = "clone_flags", [1] = "newsp", [2] = "parent_tid", [3] = "child_tid", [4] = "regs" },
	.arg_params[0].list = ARGLIST(clone_flags),
	.sanitise = sanitise_clone,
	.post = post_clone,
	.rettype = RET_PID_T,
};
