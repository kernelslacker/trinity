/*
 * SYSCALL_DEFINE2(rt_sigpending, sigset_t __user *, set, size_t, sigsetsize)
 */
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "deferred-free.h"
#include "output-poison.h"
#include "proc-status.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/* Kernel sigset_t is a fixed 64-bit mask; sizeof matches on every arch. */
#define KERNEL_SIGSET_SIZE	8

/*
 * Snapshot of the two rt_sigpending input args plus the output-buffer
 * poison seed read by the post oracle, captured at sanitise time and
 * consumed by the post handler.  Lives in rec->post_state, a slot the
 * syscall ABI does not expose, so a sibling syscall scribbling rec->aN
 * between the syscall returning and the post handler running cannot
 * redirect the oracle at a foreign set user buffer or alias the
 * sigsetsize length check.  The poison seed travels with the pointer so
 * a stomp cannot smear the seed against a heap page that happens to
 * still carry a residual pattern from an earlier call.
 */
#define RT_SIGPENDING_POST_STATE_MAGIC	0x52545350UL	/* "RTSP" */
struct rt_sigpending_post_state {
	unsigned long magic;
	unsigned long set;
	unsigned long sigsetsize;
	uint64_t poison_seed;
};

static void sanitise_rt_sigpending(struct syscallrecord *rec)
{
	struct rt_sigpending_post_state *snap;
	void *buf;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	/*
	 * Bias sigsetsize to the kernel-ABI value (8 bytes = _NSIG/8);
	 * keep a small wrong-size arm to hit the EINVAL branch.  glibc's
	 * sizeof(sigset_t) is 128, and the kernel unconditionally rejects
	 * any sigsetsize != 8 before touching the buffer -- so leaving a2
	 * to ARG_LEN wastes nearly every call on an EINVAL that never
	 * reaches the copy_to_user() the oracle is meant to police.
	 */
	if (!ONE_IN(8))
		rec->a2 = KERNEL_SIGSET_SIZE;

	avoid_shared_buffer_out(&rec->a1, rec->a2);

	/*
	 * Snapshot the two input args plus the output-buffer poison seed
	 * for the post oracle.  Without the set/sigsetsize snap the post
	 * handler reads rec->a1/a2 at post-time, when a sibling syscall
	 * may have scribbled the slots: looks_like_corrupted_ptr() cannot
	 * tell a real-but-wrong heap address from the original set user
	 * buffer pointer, so the source memcpy would touch a foreign
	 * allocation that the guard never inspected, and the sigsetsize
	 * gate would resolve against a scribbled value.  post_state is
	 * private to the post handler.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic       = RT_SIGPENDING_POST_STATE_MAGIC;
	snap->set         = rec->a1;
	snap->sigsetsize  = rec->a2;
	snap->poison_seed = 0;

	/*
	 * Stamp a per-call poison pattern across the KERNEL_SIGSET_SIZE
	 * window when the caller asked for exactly that length AND the
	 * buffer is provably writable.  The kernel only performs a FULL
	 * write when sigsetsize == KERNEL_SIGSET_SIZE (8 bytes) -- a short
	 * request copies only sigsetsize bytes and would leave the tail of
	 * any larger poison window legitimately intact (a guaranteed false
	 * positive); a mismatched request returns -EINVAL before any copy
	 * so the buffer stays byte-for-byte poison and would also false-
	 * positive if we armed the check.  range_readable_user() filters
	 * raw fuzz addresses outside the tracked shared / libc-heap
	 * snapshots that a poison byte-walk would SIGSEGV on.  On skip,
	 * poison_seed stays 0 and the post handler no-ops the poison
	 * check while the field-diff oracle still runs.  Stamped after
	 * avoid_shared_buffer_out() so the poison lands on the final
	 * buffer the kernel will see; the returned seed is fed back into
	 * check_output_struct() from the post handler.
	 */
	buf = (void *)(unsigned long) rec->a1;
	if (rec->a2 == KERNEL_SIGSET_SIZE &&
	    range_readable_user(buf, KERNEL_SIGSET_SIZE))
		snap->poison_seed = poison_output_struct(buf,
							 KERNEL_SIGSET_SIZE,
							 0);

	/*
	 * post_state_install pairs the rec->post_state assign with the
	 * ownership-table register so the observable window between the
	 * two is closed; post_rt_sigpending() will then gate the snap
	 * through post_state_claim_owned() and prove ownership before
	 * dereferencing any field.
	 */
	post_state_install(rec, snap);
}

/*
 * Oracle: rt_sigpending() copies the union of the calling thread's
 * per-thread pending mask and the per-process shared pending mask out
 * to userspace.  Two independent post checks run against the same
 * success return:
 *
 *   1. Untouched-buffer poison check.  Sanitise stamped a per-call
 *      poison pattern across the KERNEL_SIGSET_SIZE window; a byte-
 *      identical pattern after a 0-retval means the kernel skipped
 *      copy_to_user() entirely or short-copied and left an
 *      uninitialised tail readable in user memory (a kernel->user
 *      infoleak).  Runs on every success sample -- the check is a
 *      KERNEL_SIGSET_SIZE byte-walk with no re-issue -- and bumps the
 *      shared post_handler_untouched_out_buf slot.  Gated on
 *      sigsetsize == KERNEL_SIGSET_SIZE because a short user request
 *      only guarantees the kernel copies sigsetsize bytes and the
 *      tail of the poison window would legitimately still carry
 *      poison; a mismatched request returns -EINVAL and never reaches
 *      the retval==0 arm.
 *
 *   2. Procfs field-divergence oracle.  The procfs view of the same
 *      fact is /proc/self/status, which exposes the two halves
 *      separately as "SigPnd:" (per-thread, task->pending.signal) and
 *      "ShdPnd:" (shared, task->signal->shared_pending.signal).  Both
 *      views read the same sigpending bitmaps but through different
 *      code paths -- the syscall takes siglock once and copies
 *      sigorsets(thread, shared), procfs walks proc_pid_status() which
 *      formats each half via %016lx after taking siglock per render --
 *      so a divergence between the syscall's union and
 *      (SigPnd | ShdPnd) for the same task is its own corruption
 *      shape: a torn write to signal->shared_pending, a stale rcu
 *      pointer to the signal_struct, or a sigset_t copy_to_user that
 *      wrote past/before the live mask.  Mirror of the getppid procfs
 *      oracle pattern.  Sample one in a hundred.
 *
 * TOCTOU defeat: the two input args and the poison seed are
 * snapshotted at sanitise time into a heap struct in rec->post_state,
 * so a sibling that scribbles rec->a1/a2 between syscall return and
 * post entry cannot redirect the source memcpy at a foreign user
 * buffer, alias the sigsetsize gate, or smear the poison check
 * against an unrelated heap page that happens to still carry a
 * residual pattern.  The user-buffer payload at set is then
 * snapshotted into a stack-local via post_snapshot_or_skip before
 * both the poison check and the procfs compare, so a sibling munmap
 * of the writable-pool page between syscall return and our reads
 * degrades to a skipped sample instead of a SIGSEGV.
 */
static void post_rt_sigpending(struct syscallrecord *rec)
{
	struct rt_sigpending_post_state *snap;
	uint64_t syscall_pending, proc_pending;
	uint64_t sigpnd = 0, shdpnd = 0;
	sigset_t sset;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, RT_SIGPENDING_POST_STATE_MAGIC, __func__);
	if (snap == NULL)
		return;

	if (rec->retval != 0)
		goto out_free;
	if (snap->set == 0)
		goto out_free;
	if (snap->sigsetsize != KERNEL_SIGSET_SIZE)
		goto out_free;

	if (!post_snapshot_or_skip(&sset,
				   (const void *) snap->set,
				   sizeof(sset)))
		goto out_free;

	/*
	 * Untouched-buffer poison check on every success sample the buffer
	 * snapshot succeeded on.  poison_seed of 0 means sanitise chose
	 * not to stamp poison (unwritable pointer or short-length request)
	 * -- skip the check so "we couldn't poison" is not confused with
	 * "kernel didn't write".  On a match, bump the shared counter; the
	 * procfs arm below will also diverge (a poison-shaped sigset is
	 * not what /proc/self/status reports), but the shared slot is the
	 * cheaper, no-re-issue signal.
	 */
	if (snap->poison_seed != 0 &&
	    check_output_struct(&sset, sizeof(sset), snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

	if (!ONE_IN(100))
		goto out_free;

	memcpy(&syscall_pending, &sset, sizeof(syscall_pending));

	/*
	 * Pair-read both halves from a single /proc/self/status snapshot.
	 * Two back-to-back single-mask reads can straddle a signal moving
	 * shared->thread-pending and yield a union that no single
	 * proc_pid_status() render ever produced -- a spurious anomaly.
	 */
	if (!proc_status_read_sigmask_pair(&sigpnd, &shdpnd))
		goto out_free;

	proc_pending = sigpnd | shdpnd;

	if (syscall_pending != proc_pending) {
		output(0, "rt_sigpending oracle: syscall=0x%016lx but "
		       "/proc/self/status SigPnd|ShdPnd=0x%016lx "
		       "(SigPnd=0x%016lx ShdPnd=0x%016lx)\n",
		       (unsigned long)syscall_pending,
		       (unsigned long)proc_pending,
		       (unsigned long)sigpnd, (unsigned long)shdpnd);
		__atomic_add_fetch(&shm->stats.oracle.rt_sigpending_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

out_free:
	post_state_release(rec, snap);
}

struct syscallentry syscall_rt_sigpending = {
	.name = "rt_sigpending",
	.group = GROUP_SIGNAL,
	.num_args = 2,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_LEN },
	.argname = { [0] = "set", [1] = "sigsetsize" },
	.sanitise = sanitise_rt_sigpending,
	.post = post_rt_sigpending,
	.rettype = RET_ZERO_SUCCESS,
	.flags = REEXEC_SANITISE_OK,
};
