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
	deferred_free_seal_all();
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
