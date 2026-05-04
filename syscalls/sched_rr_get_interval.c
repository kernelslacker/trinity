/*
 * SYSCALL_DEFINE2(sched_rr_get_interval, pid_t, pid, struct timespec __user *, interval)
 */
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "deferred-free.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * Snapshot of the two sched_rr_get_interval input args read by the post
 * oracle, captured at sanitise time and consumed by the post handler.
 * Lives in rec->post_state, a slot the syscall ABI does not expose, so a
 * sibling syscall scribbling rec->aN between the syscall returning and
 * the post handler running cannot retarget the pid self-filter or
 * redirect the source memcpy at a foreign user buffer.
 */
struct sched_rr_get_interval_post_state {
	unsigned long pid;
	unsigned long tp;
};

static void sanitise_sched_rr_get_interval(struct syscallrecord *rec)
{
	struct sched_rr_get_interval_post_state *snap;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	avoid_shared_buffer(&rec->a2, sizeof(struct timespec));

	/*
	 * Snapshot both input args for the post oracle.  Without this the
	 * post handler reads rec->aN at post-time, when a sibling syscall
	 * may have scribbled the slots: looks_like_corrupted_ptr() cannot
	 * tell a real-but-wrong heap address from the original interval
	 * pointer, so the source memcpy would touch a foreign allocation,
	 * and the pid self-filter would resolve against a scribbled value.
	 * post_state is private to the post handler.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->pid = rec->a1;
	snap->tp  = rec->a2;
	rec->post_state = (unsigned long) snap;
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
 * sampling races migration / policy changes and tells us nothing.
 *
 * TOCTOU defeat: the two input args (pid, tp) are snapshotted at sanitise
 * time into a heap struct in rec->post_state, so a sibling that scribbles
 * rec->aN between syscall return and post entry cannot retarget the pid
 * self-filter or redirect the source memcpy at a foreign user buffer.  The
 * user buffer payload is then snapshotted into a stack-local copy before
 * re-issuing — once it's on our stack a sibling thread cannot scribble it
 * underneath the comparison.  The re-call uses a fresh private stack buffer
 * (do NOT pass snap->tp -- a sibling could mutate the user buffer itself
 * mid-syscall and forge a clean compare).
 *
 * If the re-call returns -1 (the original syscall succeeded but the re-call
 * hit a transient failure), give up rather than report a false divergence.
 * Compare tv_sec and tv_nsec individually with no early-return so a
 * multi-field corruption shows up in a single sample, but bump the anomaly
 * counter only once per sample.  Sample one in a hundred to stay in line
 * with the rest of the oracle family.
 *
 * Known benign sources of divergence (acceptable at the 1/100 sample rate):
 * sysctl writes to sched_rt_runtime_us / sched_rt_period_us between the two
 * reads, and a caller policy change from SCHED_RR to SCHED_OTHER between the
 * two reads (the kernel returns 0/0 for SCHED_OTHER while live SCHED_RR
 * returns a nonzero quantum).
 */
static void post_sched_rr_get_interval(struct syscallrecord *rec)
{
	struct sched_rr_get_interval_post_state *snap =
		(struct sched_rr_get_interval_post_state *) rec->post_state;
	struct timespec user_ts, kernel_ts;
	int rc;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_sched_rr_get_interval: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		rec->post_state = 0;
		return;
	}

	if (!ONE_IN(100))
		goto out_free;

	if ((long) rec->retval != 0)
		goto out_free;

	if (snap->tp == 0)
		goto out_free;

	if ((pid_t) snap->pid != 0 && (pid_t) snap->pid != gettid())
		goto out_free;

	{
		void *interval = (void *)(unsigned long) snap->tp;

		/*
		 * Defense in depth: even with the post_state snapshot, a
		 * wholesale stomp could rewrite the snapshot's inner pointer
		 * field.  Reject pid-scribbled tp before deref.
		 */
		if (looks_like_corrupted_ptr(rec, interval)) {
			outputerr("post_sched_rr_get_interval: rejected suspicious interval=%p (post_state-scribbled?)\n",
				  interval);
			goto out_free;
		}
	}

	memcpy(&user_ts, (struct timespec *)(unsigned long) snap->tp,
	       sizeof(user_ts));

	rc = syscall(SYS_sched_rr_get_interval, 0, &kernel_ts);
	if (rc != 0)
		goto out_free;

	if (user_ts.tv_sec != kernel_ts.tv_sec ||
	    user_ts.tv_nsec != kernel_ts.tv_nsec) {
		output(0,
		       "[oracle:sched_rr_get_interval] tv_sec %ld vs %ld tv_nsec %ld vs %ld\n",
		       (long) user_ts.tv_sec, (long) kernel_ts.tv_sec,
		       (long) user_ts.tv_nsec, (long) kernel_ts.tv_nsec);
		__atomic_add_fetch(&shm->stats.sched_rr_get_interval_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}

out_free:
	deferred_freeptr(&rec->post_state);
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
