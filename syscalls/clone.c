/*
 * long sys_clone(unsigned long clone_flags, unsigned long newsp,
	void __user *parent_tid, void __user *child_tid, struct pt_regs *regs)
 * On success, the thread ID of the child process is returned in the caller's thread of execution.
 * On failure, -1 is returned in the caller's context, no child process will be created, and errno will be set appropriately.
 */

#include <linux/sched.h>
#include "child.h"
#include "clone.h"
#include "sanitise.h"
#include "shm.h"
#include "stats_ring.h"
#include "trinity.h"
#include "utils.h"

#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP                0x02000000      /* New cgroup namespace */
#endif

/*
 * Mirrors the convention in syscalls/unshare.c: when sanitise admits
 * a CLONE_NEWNET clone() it stamps post_state with NEWNET_INFLIGHT_TICKET
 * so post_clone() knows to drop shm->newnet_in_flight.  We do not
 * derive the bookkeeping from rec->a1 at post time -- the wholesale-
 * stomp detector exists precisely because sibling syscalls can
 * scribble the rec, and an unbalanced decrement would permanently
 * unbalance the cap.  The admission / release atomics live in
 * include/shm.h alongside MAX_CONCURRENT_NEWNET.
 */

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

	/*
	 * Throttle CLONE_NEWNET to MAX_CONCURRENT_NEWNET fleet-wide -- the
	 * kernel's netns cleanup workqueue is the slow path and any
	 * grandchild that succeeds with this flag widens the backlog.  See
	 * the comment on MAX_CONCURRENT_NEWNET in include/shm.h for the
	 * full forkbomb story.  Done after enforce_clone_flag_deps() so we
	 * see the final flag set the kernel will receive, not the raw
	 * random bitmask that may still have a CLONE_NEWNET that another
	 * dep rule was about to strip anyway.
	 */
	if ((rec->a1 & CLONE_NEWNET) == 0)
		return;

	if (try_admit_newnet()) {
		rec->post_state = NEWNET_INFLIGHT_TICKET;
		return;
	}

	{
		struct childdata *c = this_child();

		rec->a1 &= ~CLONE_NEWNET;
		if (c != NULL && c->stats_ring != NULL)
			stats_ring_enqueue(c->stats_ring,
					   STATS_FIELD_UNSHARE_NEWNET_THROTTLED,
					   0, 1);
		else
			parent_stats.unshare_newnet_throttled++;
	}
}

static void post_clone(struct syscallrecord *rec)
{
	/*
	 * Release the ticket up front, atomically.  clone() returns in
	 * BOTH the parent and the newly created task; the syscallrecord
	 * lives in shared memory (children[] is alloc_shared), so both
	 * tasks reach this hook against the same rec->post_state.
	 * release_newnet_ticket() test-and-clears the ticket bit in a
	 * single RMW so only one branch's decrement lands -- a plain
	 * check-then-clear-then-fetch_sub would let both decrement and
	 * drift the counter toward negative, permanently disabling the
	 * cap.
	 */
	release_newnet_ticket(rec);

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
	.ret_objtype = OBJ_PID,
};
