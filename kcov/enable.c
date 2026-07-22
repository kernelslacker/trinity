/*
 * KCOV enable / disable ioctls, PC + CMP childop brackets, and the
 * kcov_note_extrafork accounting that sits alongside them.  Carved
 * out of kcov.c so every KCOV_ENABLE / KCOV_DISABLE / KCOV_REMOTE_
 * ENABLE issuing site lives in one translation unit; kcov_recover_fd,
 * kcov_diag_record, and kcov_latch_first_ebadf come in through the
 * externs in kcov-internal.h.
 */

#include <errno.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#ifdef CONFIG_GUARD_SHARED
#include "signals.h"		/* kcov_protect_recover / kcov_protect_active */
#endif

#include "child.h"
#include "cmp_hints.h"
#include "kcov-internal.h"
#include "params.h"		/* kcov_trace_size */
#include "pids.h"		/* this_child */
#include "shm.h"
#include "trinity.h"		/* output, outputerr */
#include "utils.h"		/* untrack_shared_region, kcov_audit_ring_dump */

#ifdef CONFIG_GUARD_SHARED
/*
 * Run the on-fault diagnostic dump for a kcov_enable_trace() reset
 * fault.  The reset store at the head of kcov_enable_trace runs under
 * sigsetjmp(kcov_protect_recover); when child_fault_handler catches a
 * SIGSEGV/SIGBUS with kcov_protect_active set it siglongjmp's back
 * and we end up here.  The dump itemises everything the spec asked
 * for so the post-hoc analysis can pin which actor stripped the
 * buffer:
 *
 *   1. Buffer addr + size, both branches (PC vs CMP fallback).
 *   2. Live VMA prot from /proc/self/maps -- the smoking-gun for any
 *      caller (sanitiser miss, internal mprotect, external syscall)
 *      that ended up actually flipping the page.
 *   3. Registration-still-present check -- catches the path where an
 *      untrack_shared_region() fired but the matching protection
 *      restore did not.
 *   4. The per-child audit ring's last ~16 disagreements -- the
 *      accelerator desync history that immediately preceded the
 *      fault, so the offending mm-sanitiser call site is named in
 *      the same log block as the fault itself.
 *
 * Bumps a counter on the shared kcov diag and _exit()s with
 * KCOV_PROT_FAULT_EXIT_CODE so the parent reaper distinguishes a
 * protection-strip fault from a clean exit / recovery-exhausted
 * bail.  Does NOT attempt silent recovery -- masking the fault is
 * the exact behaviour the audit is here to expose.
 */
static void kcov_enable_trace_dump_fault(struct kcov_child *kc, bool is_cmp)
{
	unsigned long buf_addr = (unsigned long)
		(is_cmp ? kc->cmp_trace_buf : kc->trace_buf);
	unsigned long buf_bytes = is_cmp
		? KCOV_CMP_BUFFER_SIZE * sizeof(unsigned long)
		: (size_t)kcov_trace_size * sizeof(unsigned long);
	const char *origin = is_cmp ? "kcov-cmp" : "kcov-pc";

	outputerr("kcov_enable_trace: protection-strip fault on %s buffer "
		  "addr=0x%lx size=0x%lx\n", origin, buf_addr, buf_bytes);
	log_buffer_prot_from_proc_maps("kcov_enable_trace:on-fault",
				       buf_addr, buf_bytes);
	if (kcov_registration_still_present(buf_addr, buf_bytes, origin))
		outputerr("kcov_enable_trace: %s registration STILL present "
			  "in shared_regions[]\n", origin);
	else
		outputerr("kcov_enable_trace: %s registration MISSING from "
			  "shared_regions[] -- untrack/munmap path took it\n",
			  origin);
	kcov_audit_ring_dump("kcov_enable_trace:on-fault");

	if (kcov_shm != NULL)
		__atomic_fetch_add(&kcov_shm->pc_diag.pc_enable_count, 1,
				   __ATOMIC_RELAXED);

	kc->active = false;
	_exit(KCOV_PROT_FAULT_EXIT_CODE);
}
#endif	/* CONFIG_GUARD_SHARED */

void kcov_enable_trace(struct kcov_child *kc)
{
	/*
	 * volatile under CONFIG_GUARD_SHARED because the sigsetjmp/
	 * longjmp pair inserted below crosses this scope; ISO C 7.13.2.1
	 * only guarantees post-longjmp values for objects of volatile-
	 * qualified type, and gcc -Wclobbered would otherwise flag it.
	 * Cost is one stack reload per ioctl loop iteration, well below
	 * the cost of the ioctl itself.  Plain unsigned int in the no-
	 * guard build keeps the byte image unchanged.
	 */
#ifdef CONFIG_GUARD_SHARED
	volatile unsigned int retries = 0;
#else
	unsigned int retries = 0;
#endif

	if (kc == NULL || !kc->active)
		return;

#ifdef CONFIG_GUARD_SHARED
	/*
	 * On-fault diagnostic.  The trace_buf[0]=0 reset below is
	 * supposed to be safe: the buffer is registered with origin
	 * "kcov-pc" in shared_regions[] and the mm-sanitiser overlap
	 * gates are supposed to refuse fuzzed addresses that touch it.
	 * Yet runs reproducibly take SEGV_ACCERR/SIGBUS on the store,
	 * so some path is silently stripping PROT_WRITE between
	 * registration and use.  Install a sigsetjmp before each store
	 * attempt so child_fault_handler siglongjmp's back here on a
	 * real (si_code > 0) SIGSEGV/SIGBUS while kcov_protect_active
	 * is set -- the dump helper then logs everything the spec asks
	 * for and _exit()s with KCOV_PROT_FAULT_EXIT_CODE.  No silent
	 * recovery; masking the fault is the bug the audit is here to
	 * find.
	 */
	if (sigsetjmp(kcov_protect_recover, 1) != 0) {
		kcov_protect_active = 0;
		kcov_enable_trace_dump_fault(kc, false);
		/* not reached */
	}
	kcov_protect_active = 1;
	__atomic_store_n(&kc->trace_buf[0], 0, __ATOMIC_RELAXED);
	kcov_protect_active = 0;
#else
	__atomic_store_n(&kc->trace_buf[0], 0, __ATOMIC_RELAXED);
#endif

	while (ioctl(kc->fd, KCOV_ENABLE, KCOV_TRACE_PC) < 0) {
		if (errno == EINTR && retries < KCOV_ENABLE_EINTR_MAX) {
			retries++;
			__atomic_fetch_add(
				&kcov_shm->pc_diag.pc_enable_eintr_retries,
				1, __ATOMIC_RELAXED);
			continue;
		}
		kcov_diag_record(
			&kcov_shm->pc_diag.pc_enable_errno,
			&kcov_shm->pc_diag.pc_enable_count, errno);
		if (errno == EBADF) {
			kcov_latch_first_ebadf(kc, this_child());

			/* Try to rebuild the vanished fd up to KCOV_-
			 * RECOVERY_MAX times across this slot's lifetime.
			 * The counter resets in kcov_collect() only after a
			 * syscall actually harvests coverage, so a "recover
			 * then immediately re-EBADF" loop consumes the
			 * budget instead of papering it over.  On successful
			 * recovery, re-zero trace_buf[0] (the new mapping
			 * starts uninitialised) and retry the ioctl on the
			 * fresh fd.  On cap exhaustion or failed recovery,
			 * mark the slot dead and _exit() with
			 * KCOV_RECOVERY_EXHAUSTED_EXIT_CODE so the parent's
			 * reaper hands us a clean init_child slot rather
			 * than leaving this child silently degraded.  The
			 * non-zero status is what makes the reap visible to
			 * reap_entry_is_fast_die(); a bare _exit(0) here
			 * would leave the fork-storm circuit breaker inert
			 * for kcov-recovery loops. */
			kc->recovery_attempts++;
			if (kc->recovery_attempts <= KCOV_RECOVERY_MAX &&
			    kcov_recover_fd(kc, false)) {
				__atomic_store_n(&kc->trace_buf[0], 0,
					__ATOMIC_RELAXED);
				continue;
			}
			kc->active = false;
			_exit(KCOV_RECOVERY_EXHAUSTED_EXIT_CODE);
		}
		kc->active = false;
		break;
	}
}

void kcov_enable_cmp(struct kcov_child *kc)
{
	unsigned int retries = 0;

	if (kc == NULL || !kc->cmp_capable)
		return;

	__atomic_store_n(&kc->cmp_trace_buf[0], 0, __ATOMIC_RELAXED);
	while (ioctl(kc->cmp_fd, KCOV_ENABLE, KCOV_TRACE_CMP) < 0) {
		/* Ride out signal storms the same way the PC and remote
		 * paths do -- a single EINTR is not a reason to demote a
		 * previously-probed-good cmp fd and lose CMP coverage for
		 * the rest of this child's lifetime. */
		if (errno == EINTR && retries < KCOV_ENABLE_EINTR_MAX) {
			retries++;
			continue;
		}
		/* Runtime failure on a previously-probed-good fd.  Record
		 * the symptom into cmp_diag for every observation -- with
		 * the recovery loop below the count is no longer one-per-
		 * child, it tracks the true rate of close-race incidents
		 * hitting cmp_fd.  An EBADF means the slot was aliased by
		 * a fuzzed close/dup/close_range; try to rebuild the cmp
		 * fd up to KCOV_RECOVERY_MAX times before giving up.
		 * Mirrors the PC-side recovery in kcov_enable_trace() --
		 * same _exit(KCOV_RECOVERY_EXHAUSTED_EXIT_CODE) bail so
		 * the reaper's fast-die circuit breaker treats CMP-side
		 * exhaustion identically to PC-side.  Non-EBADF errors
		 * retain the pre-existing demote-and-continue semantics:
		 * the cmp-not-supported / cmp-broken-by-the-kernel case
		 * is not a slot-replacement symptom, PC tracing on the
		 * other fd remains valid, so just stop attempting CMP. */
		kcov_diag_record(&kcov_shm->cmp_diag.runtime_enable_errno,
			&kcov_shm->cmp_diag.runtime_enable_count, errno);
		if (errno == EBADF) {
			kc->cmp_recovery_attempts++;
			if (kc->cmp_recovery_attempts <= KCOV_RECOVERY_MAX &&
			    kcov_recover_fd(kc, true)) {
				__atomic_store_n(&kc->cmp_trace_buf[0], 0,
					__ATOMIC_RELAXED);
				continue;
			}
			kc->active = false;
			_exit(KCOV_RECOVERY_EXHAUSTED_EXIT_CODE);
		}
		kc->cmp_capable = false;
		return;
	}
	kc->cmp_enabled_this_call = true;
}

void kcov_enable_remote(struct kcov_child *kc, unsigned int child_id, unsigned int nr)
{
	struct kcov_remote_arg arg = {0};
	unsigned int retries = 0;
	bool remote_failed = false;

	if (kc == NULL || !kc->active || !kc->remote_capable)
		return;

	__atomic_store_n(&kc->trace_buf[0], 0, __ATOMIC_RELAXED);

	arg.trace_mode = KCOV_TRACE_PC;
	arg.area_size = kcov_trace_size;
	arg.num_handles = 0;
	arg.common_handle = KCOV_SUBSYSTEM_COMMON | (child_id + 1);

	if (nr < MAX_NR_SYSCALL)
		__atomic_fetch_add(&kcov_shm->remote_enable.remote_enable_requested[nr], 1,
				   __ATOMIC_RELAXED);

	while (ioctl(kc->fd, KCOV_REMOTE_ENABLE, &arg) < 0) {
		if (errno == EINTR && retries < KCOV_ENABLE_EINTR_MAX) {
			retries++;
			__atomic_fetch_add(
				&kcov_shm->pc_diag.remote_enable_eintr_retries,
				1, __ATOMIC_RELAXED);
			continue;
		}
		kcov_diag_record(
			&kcov_shm->pc_diag.remote_enable_errno,
			&kcov_shm->pc_diag.remote_enable_count, errno);
		kc->remote_capable = false;
		remote_failed = true;
		break;
	}

	if (!remote_failed) {
		if (nr < MAX_NR_SYSCALL)
			__atomic_fetch_add(&kcov_shm->remote_enable.remote_enable_succeeded[nr],
					   1, __ATOMIC_RELAXED);
		return;
	}

	if (nr < MAX_NR_SYSCALL)
		__atomic_fetch_add(&kcov_shm->remote_enable.remote_enable_failed[nr], 1,
				   __ATOMIC_RELAXED);

	/* Fall back to per-thread mode if remote failed at runtime. */
	retries = 0;
	while (ioctl(kc->fd, KCOV_ENABLE, KCOV_TRACE_PC) < 0) {
		if (errno == EINTR && retries < KCOV_ENABLE_EINTR_MAX) {
			retries++;
			__atomic_fetch_add(
				&kcov_shm->pc_diag.remote_fallback_pc_enable_eintr_retries,
				1, __ATOMIC_RELAXED);
			continue;
		}
		kcov_diag_record(
			&kcov_shm->pc_diag.pc_enable_errno,
			&kcov_shm->pc_diag.pc_enable_count, errno);
		/* Same recover-or-die logic as kcov_enable_trace: an EBADF
		 * on this branch means the close-race chain killed the PC
		 * fd between the initial remote enable and this fallback.
		 * The remote-enable arm above does not trigger recovery --
		 * its failure flips remote_capable=false and demotes the
		 * child to PC-only, and the PC-only retries (which land
		 * here when EBADF strikes them too) own the fd-rebuild
		 * budget. */
		if (errno == EBADF) {
			kcov_latch_first_ebadf(kc, this_child());

			kc->recovery_attempts++;
			if (kc->recovery_attempts <= KCOV_RECOVERY_MAX &&
			    kcov_recover_fd(kc, false)) {
				__atomic_store_n(&kc->trace_buf[0], 0,
					__ATOMIC_RELAXED);
				continue;
			}
			kc->active = false;
			_exit(KCOV_RECOVERY_EXHAUSTED_EXIT_CODE);
		}
		kc->active = false;
		return;
	}
	__atomic_fetch_add(&kcov_shm->pc_diag.remote_fallback_to_pc,
			   1, __ATOMIC_RELAXED);
	if (nr < MAX_NR_SYSCALL)
		__atomic_fetch_add(&kcov_shm->remote_enable.remote_fallback_to_local[nr], 1,
				   __ATOMIC_RELAXED);
	kc->remote_mode = false;
}

void kcov_disable(struct kcov_child *kc)
{
	if (kc == NULL || !kc->active)
		return;

	/* Mode is fixed per child at init (see kcov_init_child), so only
	 * one of the two fds is ever enabled per syscall.  Branching here
	 * keeps a CMP-mode child from spamming KCOV_DISABLE -EINVAL on the
	 * PC fd every call (and a PC-mode child from spamming it on the cmp
	 * fd).  The kernel's one-`t->kcov`-per-task rule makes this
	 * exclusive: simultaneously enabling both fds returns -EBUSY on
	 * the second enable, so a child only ever has one fd active. */
	if (kc->mode == KCOV_MODE_PC) {
		if (kc->fd >= 0 && kc->trace_buf != NULL) {
			if (ioctl(kc->fd, KCOV_DISABLE, 0) < 0)
				kcov_diag_record(
					&kcov_shm->pc_diag.pc_disable_errno,
					&kcov_shm->pc_diag.pc_disable_count,
					errno);
		}
	} else if (kc->cmp_fd >= 0 && kc->cmp_trace_buf != NULL &&
		   kc->cmp_enabled_this_call) {
		/* cmp_enabled_this_call gate preserves the pre-existing
		 * defence against a runtime KCOV_TRACE_CMP enable failure
		 * mid-run flipping cmp_capable=false — the disable then
		 * knows not to fire on an fd the kernel never enabled. */
		if (ioctl(kc->cmp_fd, KCOV_DISABLE, 0) < 0)
			kcov_diag_record(
				&kcov_shm->cmp_diag.runtime_disable_errno,
				&kcov_shm->cmp_diag.runtime_disable_count,
				errno);
		kc->cmp_enabled_this_call = false;
	}
}

void kcov_note_extrafork(struct kcov_child *kc, unsigned int nr)
{
	/* Denominator bump runs even when the child has no kcov (kc==NULL
	 * or !kc->active): per_syscall_extrafork_calls[] is a count of
	 * EXTRA_FORK dispatches through do_extrafork(), independent of
	 * whether the worker itself is a kcov producer.  kcov_shm is
	 * allocated by kcov_init_global() on every trinity startup, so
	 * the NULL guard is defensive against startup ordering / no-kcov
	 * builds only.  MAX_NR_SYSCALL upper-bound matches every other
	 * per_syscall_*[] writer in this file. */
	if (kcov_shm != NULL && nr < MAX_NR_SYSCALL)
		__atomic_fetch_add(&kcov_shm->per_syscall.per_syscall_extrafork_calls[nr],
				   1, __ATOMIC_RELAXED);

	if (kc == NULL || !kc->active)
		return;

	if (kc->mode == KCOV_MODE_PC) {
		if (kc->trace_buf != NULL)
			__atomic_store_n(&kc->trace_buf[0], 0,
					 __ATOMIC_RELAXED);
	} else if (kc->mode == KCOV_MODE_CMP) {
		if (kc->cmp_trace_buf != NULL)
			__atomic_store_n(&kc->cmp_trace_buf[0], 0,
					 __ATOMIC_RELAXED);
	}
}

/*
 * Open a per-call KCOV bracket around a childop invocation.
 *
 * Returns true if the bracket took ownership of the trace (caller
 * must pair with kcov_bracket_end); false if the bracket was
 * declined and no enable was issued.  Declined cases:
 *
 *   - kc inactive, or shared state not yet allocated.  Defensive in
 *     addition to the call-site have_kcov gate.
 *   - CMP-mode child.  The kernel rejects holding both KCOV_TRACE_PC
 *     and KCOV_TRACE_CMP on the same task with -EBUSY, so the
 *     existing per-syscall CMP enable on this fd is left undisturbed.
 *   - Nested call.  bracket_owned already set means an outer bracket
 *     is in flight; the inner call must skip its own enable/disable
 *     so the outer collect can still observe a full trace.  Refcount-
 *     style nesting would have the inner kcov_collect drain
 *     trace_buf, leaving the outer bracket to harvest an empty buffer
 *     and return zero edges.
 */
bool kcov_bracket_begin(struct kcov_child *kc)
{
	if (kc == NULL || !kc->active || kcov_shm == NULL) {
		/* kcov_shm == NULL on this defensive arm means the per-call
		 * attempt counter at the child.c gate also could not bump,
		 * so skipping the skipped_inactive bump here keeps the
		 * attempts == bracketed + sum(skipped) invariant intact. */
		if (kcov_shm != NULL)
			__atomic_fetch_add(
				&kcov_shm->childop_kcov.childop_kcov_skipped_inactive,
				1, __ATOMIC_RELAXED);
		return false;
	}
	if (kc->mode == KCOV_MODE_CMP) {
		__atomic_fetch_add(&kcov_shm->childop_kcov.childop_kcov_skipped_cmp,
			1, __ATOMIC_RELAXED);
		return false;
	}
	if (kc->bracket_owned) {
		__atomic_fetch_add(&kcov_shm->childop_kcov.childop_kcov_skipped_nested,
			1, __ATOMIC_RELAXED);
		return false;
	}

	kcov_enable_trace(kc);
	if (!kc->active) {
		/* kcov_enable_trace flipped active=false on ioctl failure;
		 * no enable is live, so don't claim ownership.  Counted as
		 * skipped_inactive so the attempt still balances out against
		 * the begin-side counter. */
		__atomic_fetch_add(&kcov_shm->childop_kcov.childop_kcov_skipped_inactive,
			1, __ATOMIC_RELAXED);
		return false;
	}
	kc->bracket_owned = true;
	__atomic_fetch_add(&kcov_shm->childop_kcov.childop_kcov_bracketed,
		1, __ATOMIC_RELAXED);
	return true;
}

/*
 * Close the bracket opened by kcov_bracket_begin and harvest the
 * per-call new-edge count via kcov_collect().  op_nr is the synthetic
 * childop identifier (CHILDOP_KCOV_NR_BASE + child_op_type) used to
 * bypass the per_syscall_*[] arrays inside kcov_collect.
 *
 * Returns 0 when this child did not own the bracket (the matching
 * begin returned false), otherwise the number of bucket bits this
 * call freshly set in kcov_shm->bucket_seen.
 */
unsigned long kcov_bracket_end(struct kcov_child *kc,
				unsigned long op_nr)
{
	unsigned long edges_this_call = 0;

	if (kc == NULL || !kc->bracket_owned)
		return 0;

	kcov_disable(kc);
	/* Childops are PC-mode only (kcov_bracket_begin rejects KCOV_MODE_CMP)
	 * and op_nr >= CHILDOP_KCOV_NR_BASE bypasses the per-syscall arrays
	 * inside kcov_collect, so the do32 dimension is unused on this path;
	 * pass false as the conservative default. */
	kcov_collect(kc, (unsigned int)op_nr, false, &edges_this_call, NULL);
	kc->bracket_owned = false;
	return edges_this_call;
}

/*
 * Per-bracket record / insert tallies for the §3.2 anti-domination
 * caps.  File-scope statics, single-writer per child process
 * (trinity children are separate processes; each has its own copy),
 * reset to zero at every kcov_cmp_bracket_begin() and consulted by
 * childop_cmp_collect().  Not stashed on struct kcov_child to keep
 * its 48-byte hot-cacheline budget intact.
 */
static unsigned int childop_cmp_bracket_records_this;
static unsigned int childop_cmp_bracket_inserts_this;

/* KCOV CMP trace-buffer record format -- mirrors the constants in
 * cmp_hints.c so this file is self-contained and the harvest path
 * does not pull the cmp_hints.c hot-loop machinery into a wrapped
 * syscall's critical section. */
#define KCOV_CMP_REC_CONST		(1U << 0)
#define KCOV_CMP_REC_SIZE_SHIFT		1
#define KCOV_CMP_REC_SIZE_MASK		3U
#define KCOV_CMP_REC_WORDS		4

bool kcov_cmp_bracket_begin(struct kcov_child *kc)
{
	if (kc == NULL || !kc->active || kcov_shm == NULL) {
		/* kcov_shm == NULL also gates the bump itself so a defensive
		 * call before shm setup is a quiet no-op rather than a NULL
		 * deref.  Mirrors the PC-bracket gate. */
		if (kcov_shm != NULL)
			__atomic_fetch_add(
				&kcov_shm->childop_cmp.childop_cmp_brackets_skipped_inactive,
				1, __ATOMIC_RELAXED);
		return false;
	}
	if (kc->mode != KCOV_MODE_CMP) {
		__atomic_fetch_add(
			&kcov_shm->childop_cmp.childop_cmp_brackets_skipped_pc_mode,
			1, __ATOMIC_RELAXED);
		return false;
	}
	if (!kc->cmp_capable || kc->cmp_trace_buf == NULL) {
		__atomic_fetch_add(
			&kcov_shm->childop_cmp.childop_cmp_brackets_skipped_incapable,
			1, __ATOMIC_RELAXED);
		return false;
	}
	if (kc->bracket_owned) {
		__atomic_fetch_add(
			&kcov_shm->childop_cmp.childop_cmp_brackets_skipped_nested,
			1, __ATOMIC_RELAXED);
		return false;
	}

	kcov_enable_cmp(kc);
	if (!kc->cmp_enabled_this_call) {
		/* kcov_enable_cmp gave up (runtime EBADF / unsupported);
		 * cmp_capable is now false.  Treat as the incapable reject
		 * arm so the attempts == opened + sum(skipped) invariant
		 * holds. */
		__atomic_fetch_add(
			&kcov_shm->childop_cmp.childop_cmp_brackets_skipped_incapable,
			1, __ATOMIC_RELAXED);
		return false;
	}

	kc->bracket_owned = true;
	childop_cmp_bracket_records_this = 0;
	childop_cmp_bracket_inserts_this = 0;
	__atomic_fetch_add(&kcov_shm->childop_cmp.childop_cmp_brackets_opened, 1,
			   __ATOMIC_RELAXED);
	return true;
}

void kcov_cmp_bracket_end(struct kcov_child *kc)
{
	if (kc == NULL || !kc->bracket_owned)
		return;
	/* kcov_disable already gates on kc->mode and cmp_enabled_this_call,
	 * so calling it on a CMP-mode child here issues exactly one
	 * KCOV_DISABLE on cmp_fd and clears cmp_enabled_this_call. */
	kcov_disable(kc);
	kc->bracket_owned = false;
}

void childop_cmp_reset(struct kcov_child *kc)
{
	if (kc == NULL || !kc->bracket_owned)
		return;
	if (kc->mode != KCOV_MODE_CMP || kc->cmp_trace_buf == NULL)
		return;
	/* Reset the count word so the wrapped syscall's CMP records start
	 * at slot 0 of cmp_trace_buf -- the kernel appends from the count
	 * the same way KCOV_ENABLE does at bracket entry. */
	__atomic_store_n(&kc->cmp_trace_buf[0], 0, __ATOMIC_RELAXED);
}

void childop_cmp_collect(struct kcov_child *kc, unsigned int nr)
{
	unsigned long count;
	unsigned long i;
	unsigned int kept = 0;
	unsigned int truncated = 0;
	unsigned long *trace_buf;

	if (kc == NULL || !kc->bracket_owned)
		return;
	if (kc->mode != KCOV_MODE_CMP || kc->cmp_trace_buf == NULL)
		return;
	if (kcov_shm == NULL || nr >= MAX_NR_SYSCALL)
		return;

	trace_buf = kc->cmp_trace_buf;
	count = __atomic_load_n(&trace_buf[0], __ATOMIC_RELAXED);

	/* Clamp to KCOV_CMP_RECORDS_MAX and account the truncation
	 * against the per-nr trace_truncated counter -- mirrors the
	 * random-syscall path's cmp_trace_truncated row. */
	if (count >= KCOV_CMP_RECORDS_MAX) {
		count = KCOV_CMP_RECORDS_MAX;
		truncated = 1;
	}

	__atomic_fetch_add(&kcov_shm->childop_cmp.childop_cmp_syscalls_sampled[nr], 1UL,
			   __ATOMIC_RELAXED);
	if (truncated)
		__atomic_fetch_add(&kcov_shm->childop_cmp.childop_cmp_trace_truncated[nr],
				   1UL, __ATOMIC_RELAXED);

	if (count == 0)
		return;

	__atomic_fetch_add(&kcov_shm->childop_cmp.childop_cmp_records_collected[nr],
			   count, __ATOMIC_RELAXED);

	for (i = 0; i < count; i++) {
		unsigned long *rec;
		unsigned long type, arg1, ip;
		unsigned int size;

		/* §3.2 anti-domination cap: drop further records on this
		 * bracket once the cap is hit so one chatty childop cannot
		 * dominate the lane (or burn cycles in this loop). */
		if (childop_cmp_bracket_records_this >=
		    CHILDOP_CMP_BRACKET_RECORDS_CAP) {
			__atomic_fetch_add(
				&kcov_shm->childop_cmp.childop_cmp_record_cap_hits, 1UL,
				__ATOMIC_RELAXED);
			break;
		}
		childop_cmp_bracket_records_this++;

		rec = &trace_buf[1 + i * KCOV_CMP_REC_WORDS];
		type = rec[0];
		arg1 = rec[1];
		/* rec[2] is the runtime operand; feeding it back would
		 * recycle trinity's own inputs.  rec[3] is the comparison
		 * site PC. */
		ip   = kcov_canon_cmp_ip(rec[3]);
		size = 1U << ((type >> KCOV_CMP_REC_SIZE_SHIFT) &
			      KCOV_CMP_REC_SIZE_MASK);

		/* Only KCOV_CMP_CONST records expose a kernel-side
		 * compile-time constant; both-runtime records would just
		 * mirror values trinity already generated. */
		if (!(type & KCOV_CMP_REC_CONST))
			continue;

		/* Mirror cmp_hints_collect()'s boring-constant filter (the
		 * narrower ~3UL arm) so the quarantine lane is not flooded
		 * with 0/1/2/3 and (unsigned long)-1 sentinels.  The
		 * wider ~7UL arm is per-child A/B telemetry on the
		 * random-syscall path and is intentionally not replicated
		 * here -- this lane has no A/B yet. */
		if ((arg1 & ~3UL) == 0)
			continue;
		if (arg1 == (unsigned long)-1)
			continue;

		if (childop_cmp_bracket_inserts_this >=
		    CHILDOP_CMP_BRACKET_INSERTS_CAP) {
			__atomic_fetch_add(
				&kcov_shm->childop_cmp.childop_cmp_insert_cap_hits, 1UL,
				__ATOMIC_RELAXED);
			break;
		}
		childop_cmp_bracket_inserts_this++;
		kept++;

		/* do32 = false: childops issue native 64-bit syscalls only. */
		cmp_hints_childop_insert(nr, false, ip, arg1, size);
	}

	if (kept > 0) {
		struct childdata *cc = this_child();

		if (cc != NULL) {
			unsigned int op = (unsigned int)cc->op_type;

			if (op < KCOV_CHILDOP_NR_MAX)
				__atomic_fetch_add(
				    &kcov_shm->childop_cmp.childop_cmp_syscalls_sampled_per_op[op],
				    1UL, __ATOMIC_RELAXED);
		}
	}
}
