/*
 * SYSCALL_DEFINE2(sched_rr_get_interval, pid_t, pid, struct timespec __user *, interval)
 */
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/types.h>
#include <time.h>
#include "deferred-free.h"
#include "output-poison.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/sched.h"
/*
 * Snapshot of the two sched_rr_get_interval input args read by the post
 * oracle, captured at sanitise time and consumed by the post handler.
 * Lives in rec->post_state, a slot the syscall ABI does not expose, so a
 * sibling syscall scribbling rec->aN between the syscall returning and
 * the post handler running cannot retarget the pid self-filter or
 * redirect the source memcpy at a foreign user buffer.  The poison seed
 * travels with the pointer so a stomp cannot smear the seed against a
 * heap page that happens to still carry a residual pattern from an
 * earlier call.
 */
#define SCHED_RR_GET_INTERVAL_POST_STATE_MAGIC	0x53525249UL	/* "SRRI" */
struct sched_rr_get_interval_post_state {
	unsigned long magic;
	unsigned long pid;
	unsigned long tp;
	uint64_t poison_seed;
};

static void sanitise_sched_rr_get_interval(struct syscallrecord *rec)
{
	struct sched_rr_get_interval_post_state *snap;
	void *buf;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	avoid_shared_buffer_out(&rec->a2, sizeof(struct timespec));

	/*
	 * ARG_NON_NULL_ADDRESS draws from get_writable_address(), which
	 * returns NULL when the writable pool cannot back the requested
	 * mapping_sizes[] pick.  Skip the poison + snap install on those
	 * calls -- writing a poison pattern to a NULL or otherwise not-
	 * provably-writable user pointer would SIGSEGV inside the
	 * sanitiser and mask the syscall path we are trying to fuzz.
	 * range_readable_user() also filters raw fuzz addresses that fell
	 * outside the tracked shared / libc-heap snapshots; those
	 * addresses may not be writable and the poison stamp would fault
	 * the same way.  On skip, rec->post_state stays 0 --
	 * post_state_claim_owned() returns NULL and the post handler
	 * no-ops without ever touching the pointer.
	 */
	buf = (void *)(unsigned long) rec->a2;
	if (!range_readable_user(buf, sizeof(struct timespec)))
		return;

	/*
	 * Snapshot both input args plus the output-buffer poison seed for
	 * the post oracle.  Without the pid/tp snap the post handler reads
	 * rec->aN at post-time, when a sibling syscall may have scribbled
	 * the slots: looks_like_corrupted_ptr() cannot tell a real-but-
	 * wrong heap address from the original interval pointer, so the
	 * source memcpy would touch a foreign allocation, and the pid
	 * self-filter would resolve against a scribbled value.  The poison
	 * seed travels with the pointer so a stomp cannot smear the seed
	 * against a heap page that happens to still carry a residual
	 * pattern from an earlier call.  Stamp the poison after
	 * avoid_shared_buffer_out() so it lands on the final buffer the
	 * kernel will see; the returned seed is fed back into
	 * check_output_struct() in the post handler.  post_state is private
	 * to the post handler.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic       = SCHED_RR_GET_INTERVAL_POST_STATE_MAGIC;
	snap->pid         = rec->a1;
	snap->tp          = rec->a2;
	snap->poison_seed = poison_output_struct(buf, sizeof(struct timespec), 0);
	post_state_install(rec, snap);
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
	struct sched_rr_get_interval_post_state *snap;
	struct timespec user_ts, kernel_ts;
	int rc;

	/*
	 * Canonical ownership bracket: shape -> ownership -> magic, in that
	 * order.  post_state_claim_owned() has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption counter
	 * on failure -- just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, SCHED_RR_GET_INTERVAL_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	/*
	 * Untouched-buffer check: sched_rr_get_interval returned 0 (success)
	 * but the user buffer still byte-for-byte matches the poison pattern
	 * we stamped at sanitise time -- the kernel never called
	 * copy_to_user() at all, or short-copied and left an uninitialised-
	 * field tail readable in user memory (a kernel->user infoleak).  The
	 * non-RR-task path is not a false positive: the kernel still writes
	 * {0, 0} into the full timespec, which overwrites the 8-byte poison
	 * repeats.  Runs on every retval==0 sample, not gated by ONE_IN(100),
	 * because the check is cheap (a snapshot memcpy and a byte-walk
	 * against a repeating 8-byte pattern -- no re-issue syscall).
	 * Snapshot the buffer via post_snapshot_or_skip so a sibling munmap
	 * of the writable-pool page between syscall return and the poison
	 * compare degrades to a skipped sample instead of a SIGSEGV in
	 * check_output_struct's byte-walk.  Counts against the shared
	 * post_handler_untouched_out_buf slot.
	 */
	if ((long) rec->retval == 0 && snap->tp != 0) {
		unsigned char poison_snap[sizeof(struct timespec)];

		if (post_snapshot_or_skip(poison_snap,
					  (const void *)(unsigned long) snap->tp,
					  sizeof(poison_snap)) &&
		    check_output_struct(poison_snap, sizeof(poison_snap),
					snap->poison_seed))
			__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
					   1, __ATOMIC_RELAXED);
	}

	if (!ONE_IN(100))
		goto out_free;

	if ((long) rec->retval != 0)
		goto out_free;

	if (snap->tp == 0)
		goto out_free;

	if ((pid_t) snap->pid != 0 && (pid_t) snap->pid != gettid())
		goto out_free;

	if (!post_snapshot_or_skip(&user_ts,
				   (const void *)(unsigned long) snap->tp,
				   sizeof(user_ts)))
		goto out_free;

	rc = syscall(SYS_sched_rr_get_interval, 0, &kernel_ts);
	if (rc != 0)
		goto out_free;

	if (user_ts.tv_sec != kernel_ts.tv_sec ||
	    user_ts.tv_nsec != kernel_ts.tv_nsec) {
		output(0,
		       "[oracle:sched_rr_get_interval] tv_sec %ld vs %ld tv_nsec %ld vs %ld\n",
		       (long) user_ts.tv_sec, (long) kernel_ts.tv_sec,
		       (long) user_ts.tv_nsec, (long) kernel_ts.tv_nsec);
		__atomic_add_fetch(&shm->stats.oracle.sched_rr_get_interval_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}

out_free:
	post_state_release(rec, snap);
}

struct syscallentry syscall_sched_rr_get_interval = {
	.name = "sched_rr_get_interval",
	.group = GROUP_SCHED,
	.num_args = 2,
	.argtype = { [0] = ARG_PID, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "pid", [1] = "interval" },
	.sanitise = sanitise_sched_rr_get_interval,
	.post = post_sched_rr_get_interval,
	.rettype = RET_ZERO_SUCCESS,
	.flags = REEXEC_SANITISE_OK,
};
