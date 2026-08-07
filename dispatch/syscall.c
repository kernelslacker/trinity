/*
 * Top-level dispatch coordinator.  The raw execution path lives in
 * dispatch/syscall-exec.c and the return-side phases in
 * dispatch/syscall-return.c; this file keeps only the do_syscall()
 * entry point that picks between the common in-child path and the
 * EXTRA_FORK throwaway-grandchild wrapper.
 */

#include "child.h"
#include "deferred-free.h"
#include "kcov.h"
#include "shm.h"
#include "signals.h"
#include "syscall.h"
#include "syscall-internal.h"
#include "syscall_record.h"
#include "tables.h"

void do_syscall(struct syscallrecord *rec, struct syscallentry *entry,
		struct kcov_child *kc, struct childdata *child)
{
	/* Kernel-entry seal barrier: with --deferred-free-batch ON any
	 * X_unlock left rw_open by pre-dispatch bookkeeping (sanitiser
	 * zmalloc_tracked, cleanup_release_post_state on the previous
	 * iteration's return path) is mprotected back to steady state
	 * BEFORE the syscall enters the kernel.  A fuzzed value-result
	 * syscall that aliases the deferred-free metadata pages then
	 * SIGSEGVs on the PROT_READ/PROT_NONE tripwire instead of silently
	 * scribbling.  No-op with the flag OFF; the pre-batch behaviour
	 * (per-mutation X_unlock/X_lock round-trips) is byte-identical. */
	if (!deferred_free_seal_all()) {
		static unsigned long seal_fail_n;
		if ((++seal_fail_n % 1000) == 1)
			outputerr("deferred_free: seal failed at syscall "
				  "dispatch chokepoint; suppressing kernel "
				  "entry\n");
		/* Mark as kernel-never-entered so kcov_collect() skips
		 * total_calls / per_syscall_calls[nr] and the arg-drain
		 * in handle_syscall_ret() still runs on return.
		 *
		 * Deliberately softer than the two child/child.c chokepoints
		 * (loop-top :299 and childop-dispatch :736) which abort the
		 * child on any seal failure.  A mprotect failure at this site
		 * lets the iteration complete so handle_syscall_ret() drains
		 * the arg state cleanly; the loop-top seal at the next
		 * iteration will catch a persistent failure and abort then.
		 * This bounds the impact to at most one miscounted op per
		 * child cycle while avoiding a mid-iteration teardown that
		 * would leak post_state.  The softer behaviour is intentional
		 * -- do not silently harden to abort without updating the
		 * loop-top comments and the rationale in the commit log. */
		clear_stale_kcov_state(kc, rec);
		rec->validator_rejected = true;
		__atomic_add_fetch(
			&shm->stats.syscall_dispatch.seal_fail_ops,
			1, __ATOMIC_RELAXED);
		return;
	}
	deferred_free_debug_assert_sealed();

	/* Arm the self-fuzzed-fatal-signal gate in child_fault_handler.
	 * While set, an own-pid SI_USER/SI_TKILL/SI_QUEUE delivery of
	 * SIGSEGV/SIGBUS/SIGILL/SIGABRT is treated as fuzzer noise (the
	 * child just executed kill/tkill/tgkill/rt_sigqueueinfo/
	 * pidfd_send_signal at itself) and the child exits silently
	 * instead of pouring a bug log into /tmp/.  See signals.c. */
	in_do_syscall = 1;

	if (entry->flags & EXTRA_FORK)
		do_extrafork(rec, entry, child);
	else
		 /* common-case, do the syscall in this child process. */
		__do_syscall(rec, entry, BEFORE, kc, child);

	in_do_syscall = 0;

	/* Reuse the iteration-start timestamp child->tp captured at the top
	 * of random_syscall_step() rather than calling clock_gettime() again.
	 * rec->tp's consumers (taint timestamp ordering in post-mortem, and
	 * pre_crash_ring entry timestamps) only need second-level granularity
	 * for crash attribution — paying for a second clock read per syscall
	 * was pure overhead in the hot path. */
	rec->tp = child->tp;
}
