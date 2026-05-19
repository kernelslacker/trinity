/*
 * SYSCALL_DEFINE1(unshare, unsigned long, unshare_flags)
 */
#include <linux/sched.h>
#include "child.h"
#include "sanitise.h"
#include "shm.h"
#include "stats_ring.h"

#ifndef UNSHARE_EMPTY_MNTNS
#define UNSHARE_EMPTY_MNTNS	0x00100000
#endif

static unsigned long unshare_flags[] = {
	CLONE_THREAD, CLONE_FS, CLONE_NEWNS, CLONE_SIGHAND,
	CLONE_VM, CLONE_FILES, CLONE_SYSVSEM, CLONE_NEWUTS,
	CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWUSER, CLONE_NEWPID,
	CLONE_NEWCGROUP, CLONE_NEWTIME,
	UNSHARE_EMPTY_MNTNS,
};

/*
 * post_state convention for the throttle: NEWNET_INFLIGHT_TICKET means
 * sanitise_unshare() admitted a CLONE_NEWNET caller and bumped
 * shm->newnet_in_flight, so post_unshare() must drop it.  Zero (the
 * value generic_sanitise() leaves behind) means we did not bump and
 * post must not drop.  We deliberately do not derive this from the
 * post-call value of rec->a1 -- a sibling syscall can scribble the
 * arg slot between BEFORE and AFTER, and an unbalanced decrement would
 * let the in-flight counter underflow into a giant unsigned value and
 * permanently disable the cap.  The admission / release atomics live
 * in include/shm.h alongside MAX_CONCURRENT_NEWNET.
 */

static void sanitise_unshare(struct syscallrecord *rec)
{
	if ((rec->a1 & CLONE_NEWNET) == 0)
		return;

	if (try_admit_newnet()) {
		rec->post_state = NEWNET_INFLIGHT_TICKET;
		return;
	}

	/*
	 * Cap reached -- strip CLONE_NEWNET.  The remaining bits in
	 * unshare_flags[] are still a valid unshare bitmask (the kernel
	 * takes any subset, including zero), so the syscall still
	 * exercises the unshare path; we only avoid feeding another
	 * in-flight netns clone into copy_net_ns().
	 */
	rec->a1 &= ~CLONE_NEWNET;
	{
		struct childdata *c = this_child();

		if (c != NULL && c->stats_ring != NULL)
			stats_ring_enqueue(c->stats_ring,
					   STATS_FIELD_UNSHARE_NEWNET_THROTTLED,
					   0, 1);
		else
			parent_stats.unshare_newnet_throttled++;
	}
}

static void post_unshare(struct syscallrecord *rec)
{
	release_newnet_ticket(rec);
}

struct syscallentry syscall_unshare = {
	.name = "unshare",
	.group = GROUP_PROCESS,
	.num_args = 1,
	.argtype = { [0] = ARG_LIST },
	.argname = { [0] = "unshare_flags" },
	.arg_params[0].list = ARGLIST(unshare_flags),
	.flags = KCOV_REMOTE_HEAVY,
	.sanitise = sanitise_unshare,
	.post = post_unshare,
	.rettype = RET_ZERO_SUCCESS,
};
