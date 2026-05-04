/*
 * SYSCALL_DEFINE2(sched_getparam, pid_t, pid, struct sched_param __user *, param)
 */
#include <sched.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "deferred-free.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * Snapshot of the two sched_getparam input args read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot retarget the pid self-filter or redirect the
 * source memcpy at a foreign user buffer.
 */
struct sched_getparam_post_state {
	unsigned long pid;
	unsigned long param;
};

static void sanitise_sched_getparam(struct syscallrecord *rec)
{
	struct sched_getparam_post_state *snap;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	avoid_shared_buffer(&rec->a2, sizeof(struct sched_param));

	/*
	 * Snapshot both input args for the post oracle.  Without this the
	 * post handler reads rec->aN at post-time, when a sibling syscall
	 * may have scribbled the slots: looks_like_corrupted_ptr() cannot
	 * tell a real-but-wrong heap address from the original param
	 * pointer, so the source memcpy would touch a foreign allocation,
	 * and the pid self-filter would resolve against a scribbled value.
	 * post_state is private to the post handler.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->pid   = rec->a1;
	snap->param = rec->a2;
	rec->post_state = (unsigned long) snap;
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
	struct sched_getparam_post_state *snap =
		(struct sched_getparam_post_state *) rec->post_state;
	struct sched_param local, syscall_buf;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(snap)) {
		outputerr("post_sched_getparam: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
		rec->post_state = 0;
		return;
	}

	if (!ONE_IN(100))
		goto out_free;

	if ((long) rec->retval != 0)
		goto out_free;

	if (snap->pid != 0 && snap->pid != (unsigned long) gettid())
		goto out_free;

	if (snap->param == 0)
		goto out_free;

	{
		void *param = (void *)(unsigned long) snap->param;

		/*
		 * Defense in depth: even with the post_state snapshot, a
		 * wholesale stomp could rewrite the snapshot's inner pointer
		 * field.  Reject pid-scribbled param before deref.
		 */
		if (looks_like_corrupted_ptr(param)) {
			outputerr("post_sched_getparam: rejected suspicious param=%p (post_state-scribbled?)\n",
				  param);
			__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
			goto out_free;
		}
	}

	memset(&local, 0, sizeof(local));
	if (sched_getparam(0, &local) == -1)
		goto out_free;

	memcpy(&syscall_buf, (struct sched_param *)(unsigned long) snap->param,
	       sizeof(syscall_buf));

	if (local.sched_priority != syscall_buf.sched_priority) {
		output(0, "sched_getparam oracle: syscall=%d but recheck=%d\n",
		       syscall_buf.sched_priority, local.sched_priority);
		__atomic_add_fetch(&shm->stats.sched_getparam_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

out_free:
	deferred_freeptr(&rec->post_state);
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
};
