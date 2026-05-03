/*
 * SYSCALL_DEFINE2(sched_rr_get_interval, pid_t, pid, struct timespec __user *, interval)
 */
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static void sanitise_sched_rr_get_interval(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a2, sizeof(struct timespec));
}

/*
 * Oracle: sched_rr_get_interval(pid, &interval) reads the SCHED_RR round-robin
 * quantum the scheduler will give the target task on its next slice and copies
 * the {tv_sec, tv_nsec} pair out to the user buffer.  When pid == 0 the kernel
 * resolves the target to the calling task, so re-issuing the same query for
 * self gives a second read of the same field through the same code path — the
 * two copies must agree unless something in between either (a) had
 * copy_to_user write past or before the live timespec slot, (b) the 32-bit-on-
 * 64-bit compat copy_to_user truncated tv_sec, (c) struct-layout mismatch on
 * 32-on-64 emulation landed tv_nsec in the tv_sec slot, or (d) a stale rcu
 * read of the RR sched class quantum after a parallel sysctl write to
 * /proc/sys/kernel/sched_rt_runtime_us or sched_rt_period_us.
 *
 * Restrict to self (pid == 0 or pid == gettid()): the kernel returns the RR
 * quantum that depends on the target task's policy/cgroup, so cross-target
 * sampling races migration / policy changes and tells us nothing.  Snapshot
 * the user buffer into a stack-local copy first to defeat TOCTOU on the user
 * side — once it's on our stack a sibling thread cannot scribble it
 * underneath the comparison.  If the re-call returns -1 (the original syscall
 * succeeded but the re-call hit a transient failure), give up rather than
 * report a false divergence.  Compare tv_sec and tv_nsec individually with no
 * early-return so a multi-field corruption shows up in a single sample, but
 * bump the anomaly counter only once per sample.  Sample one in a hundred to
 * stay in line with the rest of the oracle family.
 *
 * Known benign sources of divergence (acceptable at the 1/100 sample rate):
 * sysctl writes to sched_rt_runtime_us / sched_rt_period_us between the two
 * reads, and a caller policy change from SCHED_RR to SCHED_OTHER between the
 * two reads (the kernel returns 0/0 for SCHED_OTHER while live SCHED_RR
 * returns a nonzero quantum).
 */
static void post_sched_rr_get_interval(struct syscallrecord *rec)
{
	struct timespec user_ts, kernel_ts;
	int rc;

	if (!ONE_IN(100))
		return;

	if ((long) rec->retval != 0)
		return;

	if (rec->a2 == 0)
		return;

	if ((pid_t) rec->a1 != 0 && (pid_t) rec->a1 != gettid())
		return;

	{
		void *interval = (void *)(unsigned long) rec->a2;

		/* Cluster-1/2/3 guard: reject pid-scribbled rec->a2. */
		if (looks_like_corrupted_ptr(interval)) {
			outputerr("post_sched_rr_get_interval: rejected suspicious interval=%p (pid-scribbled?)\n",
				  interval);
			shm->stats.post_handler_corrupt_ptr++;
			return;
		}
	}

	memcpy(&user_ts, (struct timespec *)(unsigned long) rec->a2,
	       sizeof(user_ts));

	rc = syscall(SYS_sched_rr_get_interval, 0, &kernel_ts);
	if (rc != 0)
		return;

	if (user_ts.tv_sec != kernel_ts.tv_sec ||
	    user_ts.tv_nsec != kernel_ts.tv_nsec) {
		output(0,
		       "[oracle:sched_rr_get_interval] tv_sec %ld vs %ld tv_nsec %ld vs %ld\n",
		       (long) user_ts.tv_sec, (long) kernel_ts.tv_sec,
		       (long) user_ts.tv_nsec, (long) kernel_ts.tv_nsec);
		__atomic_add_fetch(&shm->stats.sched_rr_get_interval_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_sched_rr_get_interval = {
	.name = "sched_rr_get_interval",
	.group = GROUP_SCHED,
	.num_args = 2,
	.argtype = { [0] = ARG_PID, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "pid", [1] = "interval" },
	.sanitise = sanitise_sched_rr_get_interval,
	.post = post_sched_rr_get_interval,
};
