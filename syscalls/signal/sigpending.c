/*
 * SYSCALL_DEFINE1(sigpending, old_sigset_t __user *, set)
 */
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/syscall.h>
#include "deferred-free.h"
#include "output-poison.h"
#include "proc-status.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#if defined(SYS_sigpending) || defined(__NR_sigpending)
#ifndef SYS_sigpending
#define SYS_sigpending __NR_sigpending
#endif
#define HAVE_SYS_SIGPENDING 1
#endif

#ifdef HAVE_SYS_SIGPENDING
/*
 * Snapshot of the sigpending input arg read by the post oracle, captured
 * at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->a1 between the syscall returning and the post
 * handler running cannot redirect the oracle at a foreign set user
 * buffer.
 */
#define SIGPENDING_POST_STATE_MAGIC	0x5347504EUL	/* "SGPN" */
struct sigpending_post_state {
	unsigned long magic;
	unsigned long set;
	/*
	 * Seed for the poison pattern stamped into the old_sigset_t
	 * buffer at sanitise time.  Returned by
	 * poison_output_struct() and fed back into check_output_struct()
	 * in the post handler.  A stomp of rec->a1 between syscall return
	 * and post entry cannot redirect the poison check at an unrelated
	 * heap page whose residual bytes happen to still match some
	 * earlier call's seed.  0 means sanitise chose not to stamp
	 * (unwritable pointer) -- the post handler no-ops the poison arm
	 * on 0 rather than confuse "we could not poison" with "kernel did
	 * not write".
	 */
	uint64_t poison_seed;
};
#endif

static void sanitise_sigpending(struct syscallrecord *rec)
{
#ifdef HAVE_SYS_SIGPENDING
	struct sigpending_post_state *snap;
	void *buf;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;
#endif

	/*
	 * Legacy sigpending takes a single old_sigset_t (one word) writeback
	 * target.  rt_sigpending was scrubbed in the prior batch using its
	 * caller-supplied a2 length; sigpending has no length arg, so use
	 * sigset_t as the conservative upper bound.
	 */
	avoid_shared_buffer_out(&rec->a1, sizeof(sigset_t));

#ifdef HAVE_SYS_SIGPENDING
	/*
	 * Snapshot the input arg read by the post oracle.  Without this the
	 * post handler reads rec->a1 at post-time, when a sibling syscall
	 * may have scribbled the slot: looks_like_corrupted_ptr() cannot
	 * tell a real-but-wrong heap address from the original set user
	 * buffer pointer, so the source memcpy would touch a foreign
	 * allocation that the guard never inspected.  post_state is private
	 * to the post handler.  Gated on HAVE_SYS_SIGPENDING to mirror the
	 * .post registration -- on systems without SYS_sigpending the post
	 * handler is not registered and a snapshot only the post handler
	 * can free would leak.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic       = SIGPENDING_POST_STATE_MAGIC;
	snap->set         = rec->a1;
	snap->poison_seed = 0;

	/*
	 * Stamp a per-call poison pattern into the output buffer the
	 * kernel is about to fill.  CRITICAL: the poison window is
	 * exactly sizeof(unsigned long) == old_sigset_t, NOT
	 * sizeof(sigset_t).  avoid_shared_buffer_out above
	 * bounds the writable draw at the larger sigset_t width, but the
	 * kernel only writes the leading old_sigset_t word -- a wider
	 * poison window would leave the unwritten tail intact and false-
	 * positive on every success return.  Gate on range_readable_user()
	 * so a writable-pool draw that landed at an address no longer
	 * provably mapped does not SIGSEGV the sanitiser inside
	 * poison_output_struct's byte-walk.  On skip, poison_seed stays 0
	 * and the post handler no-ops the poison arm while the existing
	 * procfs SigPnd oracle keeps running against snap->set.  Done
	 * after avoid_shared_buffer_out() so the poison lands on the
	 * final buffer the kernel will see.
	 */
	buf = (void *)(unsigned long) rec->a1;
	if (range_readable_user(buf, sizeof(unsigned long)))
		snap->poison_seed = poison_output_struct(buf,
							 sizeof(unsigned long),
							 0);

	/*
	 * post_state_install pairs the rec->post_state assign with the
	 * ownership-table register so the observable window between the
	 * two is closed; post_sigpending() will then gate the snap through
	 * post_state_claim_owned() and prove ownership before
	 * dereferencing any field.
	 */
	post_state_install(rec, snap);
#endif
}

#ifdef HAVE_SYS_SIGPENDING
/*
 * Oracle: sigpending(2) writes do_sigpending()'s set, the signals pending
 * for the thread or the process that the thread blocks, cut to one
 * old_sigset_t, an unsigned long: signals 1 to 32 on a 32-bit build.  The
 * procfs view of the same fact is /proc/self/status, whose SigPnd and
 * ShdPnd render the two pending sets and SigBlk the blocked one through
 * proc_pid_status() rather than a siglock-guarded copy_to_user, so a
 * divergence for the same task is its own corruption shape: a torn write
 * into the user buffer, a stale signal_struct rcu pointer, or a
 * copy_to_user that overwrote past/before the live mask.  Mirror of the
 * rt_sigpending procfs oracle, whose set the kernel writes whole.
 *
 * False-positive source at ONE_IN(100): a signal queued between syscall
 * return and our procfs read legitimately advances SigPnd or ShdPnd.
 * Acceptable at this sample rate.
 *
 * Only an ABI with __NR_sigpending builds it: i386 has it (slot 73),
 * x86_64 does not.
 */
static void post_sigpending(struct syscallrecord *rec)
{
	struct sigpending_post_state *snap;
	unsigned long user_snap;	/* old_sigset_t */
	uint64_t syscall_pending, proc_pending;
	uint64_t sigpnd = 0, shdpnd = 0, sigblk = 0;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, SIGPENDING_POST_STATE_MAGIC, __func__);
	if (snap == NULL)
		return;

	if ((long)rec->retval != 0)
		goto out_free;
	if (snap->set == 0)
		goto out_free;

	/*
	 * Snapshot the user buffer BEFORE the proc read so a sibling-thread
	 * scribble of the buffer between syscall return and our procfs read
	 * can't alias the comparison.
	 */
	if (!post_snapshot_or_skip(&user_snap,
				   (const void *) snap->set,
				   sizeof(user_snap)))
		goto out_free;
	syscall_pending = (uint64_t)user_snap;

	/*
	 * Untouched-buffer poison check: sigpending returned 0 (success)
	 * but the leading old_sigset_t word still matches the poison
	 * pattern we stamped at sanitise time -- the kernel never called
	 * copy_to_user() at all and never landed the pending mask.  Window
	 * is exactly sizeof(unsigned long) == old_sigset_t,
	 * matching what the kernel actually writes; the sigset_t upper
	 * bound used by avoid_shared_buffer_out() is deliberately NOT
	 * reused here or the unwritten tail would false-positive on every
	 * success.  (No short-copy tail arm as in wider-struct oracles --
	 * a single-word writeback either lands whole or not at all.)
	 * Cheap (single-word compare, no re-issue), so runs on every
	 * success sample the buffer snapshot succeeded on -- unlike the
	 * procfs divergence arm below, which stays rate-limited.
	 * Counts against the shared post_handler_untouched_out_buf slot.
	 * poison_seed of 0 means sanitise skipped the stamp -- skip the
	 * check too so "we could not poison" is not confused with "kernel
	 * did not write".
	 */
	if (snap->poison_seed != 0 &&
	    check_output_struct(&user_snap, sizeof(user_snap),
				snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

	if (!ONE_IN(100))
		goto out_free;

	/*
	 * Both pending halves from one /proc/self/status snapshot, as
	 * rt_sigpending reads them; SigBlk changes only by this thread's own
	 * call, so a read of its own cannot straddle a change.
	 */
	if (!proc_status_read_sigmask_pair(&sigpnd, &shdpnd) ||
	    !proc_status_read_sigmask("SigBlk", &sigblk))
		goto out_free;

	proc_pending = (sigpnd | shdpnd) & sigblk & (uint64_t) ~0UL;

	if (syscall_pending != proc_pending) {
		output(0, "sigpending oracle: syscall=0x%016lx but "
		       "/proc/self/status (SigPnd|ShdPnd)&SigBlk=0x%016lx "
		       "(SigPnd=0x%016llx ShdPnd=0x%016llx SigBlk=0x%016llx)\n",
		       (unsigned long)syscall_pending,
		       (unsigned long)proc_pending,
		       (unsigned long long)sigpnd, (unsigned long long)shdpnd,
		       (unsigned long long)sigblk);
		__atomic_add_fetch(&shm->stats.oracle.sigpending_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

out_free:
	post_state_release(rec, snap);
}
#endif

struct syscallentry syscall_sigpending = {
	.name = "sigpending",
	.group = GROUP_SIGNAL,
	.num_args = 1,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "set" },
	.sanitise = sanitise_sigpending,
#ifdef HAVE_SYS_SIGPENDING
	.post = post_sigpending,
#endif
	.rettype = RET_ZERO_SUCCESS,
	.flags = REEXEC_SANITISE_OK,
};
