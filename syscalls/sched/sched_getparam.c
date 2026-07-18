/*
 * SYSCALL_DEFINE2(sched_getparam, pid_t, pid, struct sched_param __user *, param)
 */
#include <sched.h>
#include <unistd.h>
#include <string.h>
#include "deferred-free.h"
#include "output-poison.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/sched.h"
/*
 * Snapshot of the two sched_getparam input args read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot retarget the pid self-filter or redirect the
 * source memcpy at a foreign user buffer.  The poison seed travels
 * with the pointer so a stomp cannot smear the seed against a heap
 * page that happens to still carry a residual pattern from an earlier
 * call.
 */
#define SCHED_GETPARAM_POST_STATE_MAGIC	0x53475052UL	/* "SGPR" */
struct sched_getparam_post_state {
	unsigned long magic;
	unsigned long pid;
	unsigned long param;
	uint64_t poison_seed;
};

static void sanitise_sched_getparam(struct syscallrecord *rec)
{
	struct sched_getparam_post_state *snap;
	void *buf;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	avoid_shared_buffer_out(&rec->a2, sizeof(struct sched_param));

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
	if (!range_readable_user(buf, sizeof(struct sched_param)))
		return;

	/*
	 * Snapshot both input args plus the output-buffer poison seed for
	 * the post oracle.  Without the pid/param snap the post handler
	 * reads rec->aN at post-time, when a sibling syscall may have
	 * scribbled the slots: looks_like_corrupted_ptr() cannot tell a
	 * real-but-wrong heap address from the original param pointer, so
	 * the source memcpy would touch a foreign allocation, and the pid
	 * self-filter would resolve against a scribbled value.  The
	 * poison seed travels with the pointer so a stomp cannot smear
	 * the seed against a heap page that happens to still carry a
	 * residual pattern from an earlier call.  Stamp the poison after
	 * avoid_shared_buffer_out() so it lands on the final buffer the
	 * kernel will see; the returned seed is fed back into
	 * check_output_struct() in the post handler.  post_state is
	 * private to the post handler.  post_state_install pairs the
	 * rec->post_state assign with the ownership-table register so the
	 * observable window between the two is closed;
	 * post_sched_getparam() will then gate the snap through
	 * post_state_claim_owned() and prove ownership before dereferencing
	 * any field.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic       = SCHED_GETPARAM_POST_STATE_MAGIC;
	snap->pid         = rec->a1;
	snap->param       = rec->a2;
	snap->poison_seed = poison_output_struct(buf, sizeof(struct sched_param), 0);
	post_state_install(rec, snap);
}

/*
 * Oracle: sched_getparam(pid, &param) copies task->rt_priority (the int
 * scheduling priority maintained by the scheduler core, guarded by
 * task->pi_lock for the RT classes) out to userspace.  When pid == 0 the
 * kernel resolves the target to the calling task, so re-issuing the same
 * query for self gives a second read of the same field through the same
 * code path — the two copies must agree unless something in between
 * either (a) had copy_to_user write past or before the live ->rt_priority
 * field, (b) tore a write from a parallel sched_setparam to current's
 * own param (vanishingly rare for the self-target case), or (c) the
 * userspace receive buffer was clobbered after the kernel returned.
 *
 * Restrict to self (pid == 0 or pid == gettid()): re-calling for some
 * other pid races against that task's own sched_setparam and tells us
 * nothing.  Skip if the param pointer is NULL — the kernel rejects that
 * with -EFAULT and there is no buffer to compare.
 *
 * TOCTOU defeat: the two input args (pid, param) are snapshotted at
 * sanitise time into a heap struct in rec->post_state, so a sibling
 * that scribbles rec->aN between syscall return and post entry cannot
 * retarget the pid self-filter or redirect the source memcpy at a
 * foreign user buffer.  The re-call is issued against a fresh private
 * stack buffer (do NOT pass the snapshot's param -- a sibling could
 * mutate the user buffer itself mid-syscall and forge a clean compare).
 *
 * If the re-call itself returns -1 (the original syscall succeeded but
 * the re-call lost a race or the task's sched class changed underneath),
 * give up rather than report a false divergence.  Sample one in a
 * hundred to stay in line with the rest of the oracle family.
 */
static void post_sched_getparam(struct syscallrecord *rec)
{
	struct sched_getparam_post_state *snap;
	struct sched_param local, syscall_buf;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, SCHED_GETPARAM_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	/*
	 * Untouched-buffer check: sched_getparam returned 0 (success) but
	 * the user buffer still byte-for-byte matches the poison pattern
	 * we stamped at sanitise time -- the kernel never called
	 * copy_to_user() at all, or short-copied and left an
	 * uninitialised-field tail readable in user memory (a kernel->
	 * user infoleak).  Runs on every retval==0 sample, not gated by
	 * ONE_IN(100), because the check is cheap (a snapshot memcpy and
	 * a byte-walk against a repeating 8-byte pattern -- no re-issue
	 * syscall).  Snapshot the buffer via post_snapshot_or_skip so a
	 * sibling munmap of the writable-pool page between syscall return
	 * and the poison compare degrades to a skipped sample instead of
	 * a SIGSEGV in check_output_struct's byte-walk.  Counts against
	 * the shared post_handler_untouched_out_buf slot.
	 */
	if ((long) rec->retval == 0 && snap->param != 0) {
		unsigned char poison_snap[sizeof(struct sched_param)];

		if (post_snapshot_or_skip(poison_snap,
					  (const void *)(unsigned long) snap->param,
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

	if (snap->pid != 0 && snap->pid != (unsigned long) gettid())
		goto out_free;

	if (snap->param == 0)
		goto out_free;

	memset(&local, 0, sizeof(local));
	if (sched_getparam(0, &local) == -1)
		goto out_free;

	if (!post_snapshot_or_skip(&syscall_buf,
				   (const void *)(unsigned long) snap->param,
				   sizeof(syscall_buf)))
		goto out_free;

	if (local.sched_priority != syscall_buf.sched_priority) {
		output(0, "sched_getparam oracle: syscall=%d but recheck=%d\n",
		       syscall_buf.sched_priority, local.sched_priority);
		__atomic_add_fetch(&shm->stats.oracle.sched_getparam_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

out_free:
	post_state_release(rec, snap);
}

struct syscallentry syscall_sched_getparam = {
	.name = "sched_getparam",
	.group = GROUP_SCHED,
	.num_args = 2,
	.argtype = { [0] = ARG_PID, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "pid", [1] = "param" },
	.sanitise = sanitise_sched_getparam,
	.rettype = RET_ZERO_SUCCESS,
	.post = post_sched_getparam,
	.flags = REEXEC_SANITISE_OK,
};
