/*
 * health/signals-fault-handler.c — child and main fault handlers.
 *
 * ⚠ ASYNC-SIGNAL-SAFE CRASH PATH — the M6 sigsetjmp recovery site.
 *
 * This file owns the sigsetjmp recovery buffers and the SA_SIGINFO
 * crash handlers that read them.  child_fault_handler() is the hot
 * path: it runs inside a signal handler delivered to a fuzzing child
 * that has just taken a real fault.  ALL code paths reachable from
 * the point where the siglongjmp gates are checked must be either:
 *   - on the POSIX 2024 §2.4.3 async-signal-safe list (write(2),
 *     open(2), close(2), dup2(2), lseek(2), read(2), _exit(2),
 *     umask(2), sigaction(2)), or
 *   - one of the hand-rolled sigsafe_{putc,...}/fault_beacon_extract_{ip,sp} helpers
 *     from signals-internal.h / signals-async-safe.c.
 *
 * Do NOT add libc stdio, malloc, dladdr, fopen, or locale-touching
 * calls to the post-gate paths without careful review of the deadlock
 * class documented in signals-async-safe.c::write_backtrace_raw_pcs().
 *
 * SERIALIZE with 365·M6 — the signal() → sigaction() migrations at
 * the three escalation/default-restore sites in sighandler(),
 * escalate_fault(), and main_fault_handler() are that task's
 * territory; do not touch them here.
 *
 * See Documentation/signals.md for the full contract.
 */
#include <setjmp.h>	/* sigjmp_buf, siglongjmp */
#include <stdlib.h>	/* EXIT_SUCCESS */
#include <sys/stat.h>	/* umask() */
#include <signal.h>	/* siginfo_t, SA_SIGINFO */
#include <sys/syscall.h>	/* SYS_write (raw syscall, bypassing libc stdio) */
#include <unistd.h>	/* _exit, write, dup2, close, open */

#include "trinity.h"	/* __unused__ */
#include "signals.h"
#include "signals-internal.h"

#include "shm.h"	/* shm->debug (escalate_fault) */
#include "pids.h"	/* mypid() */
#include "child.h"	/* this_child(), struct childdata, alt_op_name() */
#include "utils.h"	/* range_in_tracked_shared, guard_pages_classify */

/*
 * Recovery point for asb_relocate()'s best-effort source copy.  See
 * include/signals.h and rand/random-address.c::asb_relocate() for the
 * full contract.  Definition lives here so the storage for the jmp_buf
 * is colocated with the handler that reads asb_copy_active.
 *
 * Inherited COW-private into every forked child; never touched by the
 * parent.  Plain file-scope storage rather than __thread because
 * trinity children are single-threaded processes -- no two threads in
 * the same address space race on the slot.
 */
sigjmp_buf asb_copy_recover;
volatile sig_atomic_t asb_copy_active;

/*
 * Recovery point for cmp_hints_collect()'s field-scoped ARG_TIMESPEC
 * deref.  See include/signals.h and cmp_hints.c::cmp_hints_collect()
 * for the full contract.  Definition lives here so the storage for
 * the jmp_buf is colocated with the handler that reads
 * cmp_field_read_active.
 *
 * Inherited COW-private into every forked child; never touched by the
 * parent.  Plain file-scope storage rather than __thread because
 * trinity children are single-threaded processes -- no two threads in
 * the same address space race on the slot.
 */
sigjmp_buf cmp_field_recover;
volatile sig_atomic_t cmp_field_read_active;

/*
 * Recovery point for vma_split_storm's touch_random_page() one-byte
 * store.  See include/signals.h and childops/mm/vma-split-storm.c::
 * touch_random_page() for the full contract.  Definition lives here
 * so the storage for the jmp_buf is colocated with the handler that
 * reads vma_split_storm_touch_active.
 *
 * Inherited COW-private into every forked child; never touched by the
 * parent.  Plain file-scope storage rather than __thread because
 * trinity children are single-threaded processes -- no two threads in
 * the same address space race on the slot.
 */
sigjmp_buf vma_split_storm_touch_recover;
volatile sig_atomic_t vma_split_storm_touch_active;

#ifdef CONFIG_GUARD_SHARED
/*
 * Recovery point for the kcov_enable_trace() trace_buf[0]=0 reset.
 * See include/signals.h and kcov.c::kcov_enable_trace() for the full
 * contract.  Definition lives here so the storage for the jmp_buf is
 * colocated with the handler that reads kcov_protect_active.
 *
 * COW-inherited into every forked child; never touched by the parent.
 * Plain file-scope storage rather than __thread because trinity
 * children are single-threaded.
 */
sigjmp_buf kcov_protect_recover;
volatile sig_atomic_t kcov_protect_active;
#endif

/*
 * Set while a child is inside do_syscall().  Lets the child fault
 * handler distinguish a SIGSEGV/SIGBUS/SIGILL the child fuzzed at
 * itself via kill(getpid(), SIGFOO) / tkill / tgkill /
 * rt_sigqueueinfo (SI_USER, si_pid == own pid, flag set) from a
 * real fault that just happened to fire at a moment when the child
 * was somewhere else (flag clear -- treat as a real bug, log it).
 */
volatile sig_atomic_t in_do_syscall;
volatile sig_atomic_t in_extrafork_grandchild;

/*
 * Stamp the per-child fault beacon (see include/bug_backtrace.h::
 * child_fault_beacon for the field contract and the release-store /
 * acquire-load handoff that orders the stamp into the parent's view).
 *
 * Carries the same no_sanitize attribute as child_fault_handler because
 * the first plain load of me->syscall.state intentionally bypasses
 * ASAN's shadow check -- a torn-down shm childdata mapping must not
 * escalate to SIGKILL inside this very handler.
 */
static __attribute__((no_sanitize("address")))
void stamp_fault_beacon(int sig, siginfo_t *info, void *ctx)
{
	struct childdata *me = this_child();

	/*
	 * Gate the first me-deref on me belonging to a tracked
	 * shared region.  this_child() can return a non-NULL but
	 * unmapped pointer (torn-down or corrupt shm childdata
	 * mapping); the NULL check alone lets the first plain load
	 * re-fault inside this very handler and the kernel escalates
	 * to SIGKILL, erasing the original crash class.
	 * See Documentation/signals.md.
	 *
	 * range_in_tracked_shared() is a linear walk of
	 * shared_regions[] with no allocator / stdio / lock /
	 * this_child() / stats_ring enqueue / global mutation --
	 * async-signal-safe.  range_overlaps_shared() is
	 * deliberately NOT used here: its confirmed-overlap path
	 * calls this_child(), enqueues stats, and writes
	 * last_reject_* globals -- exactly the re-entrant class
	 * this gate exists to keep out.  On a miss the stamp is
	 * skipped (dropped-beacon, surfaced by the parent's
	 * existing written==0 path).
	 */
	if (me != NULL &&
	    range_in_tracked_shared((unsigned long)me,
				    sizeof(struct childdata))) {
		struct child_fault_beacon *beacon = &me->fault_beacon;
		struct child_fault_beacon local;
		enum syscallstate st = me->syscall.state;
		int32_t snr;

		if (st == PREP || st == BEFORE || st == GOING_AWAY)
			snr = (int32_t)me->syscall.nr;
		else
			snr = -1;
		/*
		 * Build the stamp on the stack, then publish via a
		 * single struct assignment.  fault_sa installs this
		 * handler with sa_mask=empty and no SA_NODEFER on
		 * SIGABRT/SIGBUS/SIGILL, so an inner handler can run
		 * to completion mid-stamp; field-by-field stores into
		 * the shared slot would yield a torn record (signo
		 * from one fault, ip/sp from another) for the
		 * parent's acquire-load.  See Documentation/signals.md.
		 *
		 * .written is left zero in the local so the struct
		 * assignment transiently clears the published bit;
		 * the release-store below is the real publish edge.
		 */
		local.written = 0;
		local.signo = (int32_t)sig;
		local.sig_code = (int32_t)info->si_code;
		local.fault_addr = info->si_addr;
		local.fault_ip = fault_beacon_extract_ip(ctx);
		local.fault_sp = fault_beacon_extract_sp(ctx);
		local.op_nr = me->op_nr;
		local.last_syscall_nr = snr;
		*beacon = local;
		/* Release-store seals every preceding plain store
		 * into view of any parent that acquire-loads
		 * .written and sees 1. */
		__atomic_store_n(&beacon->written, 1U,
				 __ATOMIC_RELEASE);
	}
}

#ifdef CONFIG_GUARD_SHARED
/*
 * Decode a CONFIG_GUARD_SHARED guard-page trip and emit a one-line
 * attribution naming the overflowed region, direction (leading vs
 * trailing), distance past the edge, and writer PC.  Gated on
 * SIGSEGV at function entry so a SIGBUS/SIGABRT/SIGILL still reaches
 * the in-handler diagnostic path below but is not decoded as a
 * guard trip (it isn't, by construction).
 */
static __attribute__((no_sanitize("address")))
void emit_guard_page_attribution(int sig, siginfo_t *info, void *ctx)
{
	if (sig == SIGSEGV) {
		uintptr_t region_addr;
		size_t region_size;
		bool trailing;
		unsigned long delta;

		if (guard_pages_classify((uintptr_t)info->si_addr,
					 &region_addr, &region_size,
					 &trailing, &delta)) {
			char buf[256];
			struct sigsafe_buf b = { buf, sizeof(buf) };
			size_t used;
			ssize_t w;

			sigsafe_puts(&b, "GUARD TRAP: region=");
			sigsafe_putp(&b, (void *)region_addr);
			sigsafe_puts(&b, " size=");
			sigsafe_putu(&b, (unsigned long)region_size);
			sigsafe_puts(&b, trailing ? " trailing" : " leading");
			sigsafe_puts(&b, " overflow delta=");
			sigsafe_putu(&b, delta);
			sigsafe_puts(&b, " writer=");
			sigsafe_putp(&b, fault_beacon_extract_ip(ctx));
			sigsafe_puts(&b, " si_addr=");
			sigsafe_putp(&b, info->si_addr);
			sigsafe_putc(&b, '\n');

			used = sizeof(buf) - b.left;
			w = write(STDERR_FILENO, buf, used);
			(void)w;	/* dying anyway; short write irrelevant */
		}
	}
}
#endif

/*
 * Format and emit the currently-running childop's identity
 * ("childop=<name> op_nr=<n> last_syscall_nr=<n>\n") to the
 * inherited stderr (the per-pid bug log after the dup2 above).
 *
 * Mirrors write_siginfo_safely's hand-rolled formatter: byte stores
 * into a stack buffer via the sigsafe_* helpers, single write(),
 * no stdio, no allocator, no lock.  Gates on me->syscall.state so a
 * signal that hit between syscalls emits -1 rather than the stale
 * previous-call number.
 */
static __attribute__((no_sanitize("address")))
void stamp_childop_identity(void)
{
	struct childdata *me = this_child();
	const char *opname;
	unsigned long opnr;
	int last_syscall_nr;
	char buf[160];

	if (me != NULL) {
		enum syscallstate st = me->syscall.state;

		opname = alt_op_name(me->op_type);
		opnr = me->op_nr;
		if (opname == NULL)
			opname = "unknown";
		if (st == PREP || st == BEFORE || st == GOING_AWAY)
			last_syscall_nr = (int)me->syscall.nr;
		else
			last_syscall_nr = -1;
	} else {
		opname = "unknown";
		opnr = 0;
		last_syscall_nr = -1;
	}
	{
		struct sigsafe_buf b = { buf, sizeof(buf) };
		size_t used;
		ssize_t w;

		sigsafe_puts(&b, "childop=");
		sigsafe_puts(&b, opname);
		sigsafe_puts(&b, " op_nr=");
		sigsafe_putu(&b, opnr);
		sigsafe_puts(&b, " last_syscall_nr=");
		sigsafe_puti(&b, (long)last_syscall_nr);
		sigsafe_putc(&b, '\n');

		used = sizeof(buf) - b.left;
		w = write(STDERR_FILENO, buf, used);
		(void)w;	/* dying anyway; nothing to do on short write */
	}
}

/*
 * SIGTRAP handler for the Stage-2 writer-pinning canary (perf HW
 * breakpoint armed by writer-watch.c with perf_event_attr.sigtrap=1).
 * The kernel delivers SIGTRAP synchronously in the writing thread with
 * si_code=TRAP_PERF; ucontext RIP is the writer's PC.  Dumps writer
 * identity and _exit()s so the trap does not re-fire when the kernel
 * resumes the interrupted thread.  See Documentation/signals.md.
 *
 * STRICTLY ASYNC-SIGNAL-SAFE: only write(2), sigsafe_* helpers, and
 * pure inline ucontext reads.  No libc malloc / stdio / locale / lock,
 * no symbolization (dladdr is unsafe; emit RAW PC and resolve offline
 * against the [load-bases] line log_load_bases() prints at startup).
 * The this_child() deref is gated by range_in_tracked_shared exactly
 * like stamp_fault_beacon.
 *
 * Carries no_sanitize("address") like child_fault_handler: the gated
 * me->syscall.state load intentionally bypasses ASAN's shadow check.
 */
__attribute__((no_sanitize("address")))
void writer_trap_handler(int sig, siginfo_t *info, void *ctx)
{
	char buf[256];
	struct sigsafe_buf b = { buf, sizeof(buf) };
	struct childdata *me;
	const char *opname = "unknown";
	unsigned long opnr = 0;
	int last_syscall_nr = -1;
	size_t used;
	ssize_t w;

	me = this_child();
	if (me != NULL &&
	    range_in_tracked_shared((unsigned long)me,
				    sizeof(struct childdata))) {
		enum syscallstate st = me->syscall.state;

		opname = alt_op_name(me->op_type);
		if (opname == NULL)
			opname = "unknown";
		opnr = me->op_nr;
		if (st == PREP || st == BEFORE || st == GOING_AWAY)
			last_syscall_nr = (int)me->syscall.nr;
	}

	sigsafe_puts(&b, "WRITER-PINNED: hardware write breakpoint fired");
	sigsafe_puts(&b, " addr=");
	sigsafe_putp(&b, info != NULL ? info->si_addr : NULL);
	sigsafe_puts(&b, " writer_pc=");
	sigsafe_putp(&b, fault_beacon_extract_ip(ctx));
	sigsafe_puts(&b, " (RAW, resolve offline against [load-bases])");
	sigsafe_puts(&b, " syscall_nr=");
	sigsafe_puti(&b, (long)last_syscall_nr);
	sigsafe_puts(&b, " childop=");
	sigsafe_puts(&b, opname);
	sigsafe_puts(&b, " op_nr=");
	sigsafe_putu(&b, opnr);
	sigsafe_puts(&b, " pid=");
	sigsafe_puti(&b, (long)getpid());
	sigsafe_putc(&b, '\n');

	used = sizeof(buf) - b.left;
	w = write(STDERR_FILENO, buf, used);
	(void)w;	/* dying anyway; short write irrelevant */
	(void)sig;

	/*
	 * _exit(), not return / raise.  The watched address has just been
	 * scribbled and the instruction has NOT advanced; returning would
	 * re-execute the write and re-fire SIGTRAP in a tight loop.  The
	 * parent's reaper sees a normal exit and respawns the slot.
	 */
	_exit(EXIT_SUCCESS);
}

/*
 * Final escalation step.  In debug mode restore the default
 * disposition and re-raise so the kernel emits a core file (the
 * RLIMIT_CORE bump in child.c::disable_coredumps was -D-only).
 * In non-debug, _exit(EXIT_SUCCESS) so the parent's reaper sees a
 * normal exit and respawns without crash-loop noise.
 */
static __attribute__((no_sanitize("address")))
void escalate_fault(int sig)
{
	if (shm->debug == true) {
		(void)signal(sig, SIG_DFL);
		raise(sig);
	} else {
		_exit(EXIT_SUCCESS);
	}
}

/*
 * Child-side fault handler.  Mirrors main_fault_handler in spirit but
 * preserves the existing non-debug clean-exit behaviour:
 *
 *   - Real fault (kernel-generated, si_code > 0) or self-sent (abort,
 *     stack-smash from libc):
 *       * stamp child->fault_beacon BEFORE any libc-touching call so
 *         the parent can surface the death class even when the
 *         open / dup2 / backtrace() chain below re-faults walking a
 *         corrupted ld.so writable segment (see
 *         include/bug_backtrace.h::child_fault_beacon)
 *       * dump backtrace + signal info to stderr so we have ANY signal
 *         in the log even when the core is unwindable (fault from
 *         stack-corruption disturbs the unwind chain — gdb on the
 *         core often gets nothing)
 *       * in debug mode: signal(SIG_DFL) + raise(sig) so the kernel
 *         dumps a core (RLIMIT_CORE was bumped to unlimited in
 *         child.c::disable_coredumps for -D)
 *       * in non-debug: _exit(EXIT_SUCCESS) — matches the legacy
 *         sighandler so the parent's reaper sees a normal exit and
 *         respawns without crash-loop noise
 *
 *   - Sibling-spoofed (process-sent, kill/tkill/tgkill/rt_sigqueueinfo
 *     fuzzing aimed at us): ignore — fuzzer noise.
 */
__attribute__((no_sanitize("address")))
void child_fault_handler(int sig, siginfo_t *info, void *ctx)
{
	/*
	 * asb_relocate() copy-fault recovery.  Runs first so the
	 * siglongjmp aborts the handler outright with no publish-side
	 * side effects (beacon stamp, buglog open) on a fault we're
	 * retry-as-skipping in the sanitiser.
	 * See Documentation/signals.md.
	 *
	 * Gated on SIGSEGV/SIGBUS only (the faults the kernel raises
	 * for an unmapped source), si_code > 0 (real kernel fault --
	 * a sibling kill would resume the memcpy on return anyway),
	 * and asb_copy_active (set only across the memcpy itself).
	 * sigsetjmp was installed with savemask=1 so a subsequent
	 * SEGV in this child still reaches this handler.
	 */
	if (asb_copy_active && info->si_code > 0 &&
	    (sig == SIGSEGV || sig == SIGBUS)) {
		siglongjmp(asb_copy_recover, 1);
	}

	/*
	 * cmp_hints_collect() field-scoped ARG_TIMESPEC deref
	 * recovery.  Cached VMA state can stale between the
	 * range_readable_user() gate and the tv_sec/tv_nsec loads
	 * if a sibling raw munmap/mremap intervenes.  Same three-way
	 * gate as asb_copy above.  See Documentation/signals.md.
	 */
	if (cmp_field_read_active && info->si_code > 0 &&
	    (sig == SIGSEGV || sig == SIGBUS)) {
		siglongjmp(cmp_field_recover, 1);
	}

	/*
	 * vma_split_storm touch_random_page() one-byte-store
	 * recovery.  The pte-priming write can hit a sub-VMA whose
	 * most recent mprotect was PROT_READ, faulting with
	 * SIGSEGV/SEGV_ACCERR (op-bookkeeping fault, not a kernel
	 * bug).  Same three-way gate as asb_copy above.  Outside
	 * CONFIG_GUARD_SHARED so it applies to all builds.
	 * See Documentation/signals.md.
	 */
	if (vma_split_storm_touch_active && info->si_code > 0 &&
	    (sig == SIGSEGV || sig == SIGBUS)) {
		siglongjmp(vma_split_storm_touch_recover, 1);
	}

#ifdef CONFIG_GUARD_SHARED
	/*
	 * kcov_enable_trace() trace_buf[0]=0 reset-fault recovery.
	 * The store is guarded at registration and by mm-sanitiser
	 * overlap gates, yet some path intermittently strips
	 * PROT_WRITE.  Same three-way gate as asb_copy above.  On
	 * longjmp the caller logs the full diagnostic and _exit()s
	 * with a distinct code so the fault is visible in reap
	 * statistics without crash-looping the worker.
	 * See Documentation/signals.md.
	 */
	if (kcov_protect_active && info->si_code > 0 &&
	    (sig == SIGSEGV || sig == SIGBUS)) {
		siglongjmp(kcov_protect_recover, 1);
	}
#endif

	if (info->si_code <= 0 && info->si_pid != mypid()) {
		/* Sibling spoof — ignore. */
		return;
	}
	/*
	 * Self-fuzzed delivery: a child running random_syscall picked
	 * kill / tkill / tgkill / rt_sigqueueinfo / pidfd_send_signal
	 * with target == own pid and signo ∈ {SIGSEGV, SIGBUS, SIGILL,
	 * SIGABRT}.  The kernel obediently delivers it and we land here
	 * with si_code == SI_USER (0) / SI_TKILL (-6) / SI_QUEUE (-1)
	 * and si_pid == getpid().  Drop silently — same _exit path the
	 * non-debug real-fault arm uses below — so the parent's reaper
	 * sees a normal exit and respawns without /tmp/trinity-bug-<pid>.log
	 * polluting the run with fuzzer-generated noise.  Without this
	 * gate, ~25-50% of bug logs in a typical run are own-pid
	 * SIGBUS/SIGILL/SIGSEGV from this exact path.
	 *
	 * Skipped if we're not currently inside do_syscall() — a
	 * self-sent fatal from outside the syscall hot path (e.g. glibc
	 * abort() from a heap-corruption assertion, or an explicit
	 * raise() from trinity itself) is a real bug that must still be
	 * logged.
	 */
	if (info->si_code <= 0 && info->si_pid == mypid() && in_do_syscall) {
		_exit(EXIT_SUCCESS);
	}
	/*
	 * do_extrafork() throwaway grand-child gate.  Hoisted to cover
	 * the beacon stamp AND the per-pid buglog open / shared stderr-
	 * memfd drain below: this_child() returns the parent worker's
	 * childdata (cached_pid is COW-inherited and never updated
	 * across the throwaway fork), so a beacon stamp would publish a
	 * fault attributed to the wrong worker, and the buglog open +
	 * memfd lseek+drain would corrupt the worker's on-disk forensic
	 * record for an unrelated fault and race with the worker's own
	 * memfd offset.  Skip straight to the in-handler stderr writes
	 * below; the grand-child has no childdata of its own to stamp
	 * into and the kernel-side crash artefacts still surface the
	 * death.
	 */
	if (in_extrafork_grandchild) {
		/*
		 * Redirect this grandchild's STDERR_FILENO to /dev/null
		 * before the shared post-skip_buglog diagnostics
		 * (write_backtrace_raw_pcs + write_siginfo_safely) run.
		 * Without this, a fault in a throwaway extra-fork
		 * grandchild skips the per-pid buglog block above but
		 * still appends backtrace + siginfo text to the
		 * fork-inherited stderr memfd, polluting the worker's
		 * diagnostic record for an unrelated fault.  open / dup2
		 * / close are on the POSIX 2024 §2.4.3 async-signal-safe
		 * list; the kernel-side oops still prints regardless.
		 */
		int devnull = open("/dev/null", O_WRONLY | O_CLOEXEC);
		if (devnull >= 0) {
			dup2(devnull, STDERR_FILENO);
			if (devnull != STDERR_FILENO)
				close(devnull);
		}
		goto skip_buglog;
	}
	/*
	 * Stamp the fault beacon FIRST -- before umask, open, dup2,
	 * backtrace(), write_siginfo_safely, or anything else libc-
	 * touchy.  When the underlying root cause is a corrupted ld.so
	 * writable segment (NULL'd link_map slot, stomped GOT), a
	 * subsequent unwinder call can re-fault walking that state and
	 * the process dies before any forensic line lands on disk.  (The
	 * historical worst offender here was backtrace_symbols_fd's
	 * dladdr link_map walk -- now removed; backtrace_symbols_fd is
	 * only reachable under the off-by-default USE_BACKTRACE_UNSAFE
	 * knob.)  The beacon captures the death class into shared
	 * memory using only kernel-supplied siginfo + ucontext fields and
	 * a local-then-publish struct copy -- no allocator, no stdio, no
	 * lock -- so the parent's dump_child_fault_beacon() can surface
	 * the silenced class even in the re-fault case.  See
	 * include/bug_backtrace.h::child_fault_beacon for the field
	 * contract and the release-store / acquire-load handoff that
	 * orders the stamp into the parent's view.
	 */
	stamp_fault_beacon(sig, info, ctx);
	/*
	 * Reset the umask before creating any files.  The umask syscall is
	 * itself fuzzed, so a child that drew umask(0777) and then crashed
	 * would otherwise have its /tmp/trinity-bug-<pid>.log redirect file
	 * created with mode 0644 & ~0777 == 0, and the kernel/userspace
	 * coredump helper would create the core file with the same 0000
	 * mode and abort with "cannot preserve file permissions".  umask()
	 * is async-signal-safe (POSIX 2024 §2.4.3) so this is safe to call
	 * from a signal handler.  Returning the old mask is intentionally
	 * ignored — this child is about to die.
	 */
	(void)umask(0);
	/*
	 * Open the per-pid bug log and drain the buffered pre-crash
	 * stderr text into it BEFORE redirecting STDERR_FILENO --
	 * otherwise the in-handler write_siginfo_safely() /
	 * write_backtrace_raw_pcs() output below would land before the
	 * glibc malloc_printerr text that explains why we're here.
	 * See Documentation/signals.md.
	 *
	 * buglog_path[] was pre-formatted in init_stderr_memfd() to
	 * keep snprintf() out of this handler.  open / lseek / read /
	 * write / dup2 / close are all on the POSIX 2024 §2.4.3
	 * async-signal-safe list.  Silent no-op on stderr_memfd == -1
	 * (memfd_create() failed); open() failure emits a BUGLOG-FAIL
	 * marker to the stderr memfd for parent-side accounting.
	 */
	open_buglog_and_drain_stderr(sig);
skip_buglog:
	/*
	 * Phase sentinel: written to STDERR_FILENO (the per-pid buglog
	 * after open_buglog_and_drain_stderr, /dev/null for extrafork
	 * grandchildren, or the stderr memfd when buglog open failed).
	 * A partial log that ends mid-phase identifies which write stage
	 * re-faulted.  write() is on the POSIX 2024 §2.4.3 safe list.
	 */
	{
		static const char bt_phase[] = "BUGLOG-PHASE: backtrace\n";
		(void)syscall(SYS_write, STDERR_FILENO,
			      bt_phase, sizeof(bt_phase) - 1);
	}
#if defined(USE_BACKTRACE) && !defined(__SANITIZE_ADDRESS__)
	/*
	 * RAW PCs only -- backtrace_symbols_fd() is async-unsafe and
	 * deadlocks against the arena lock on a malloc-raised abort.
	 * See write_backtrace_raw_pcs() for the full rationale.
	 */
	write_backtrace_raw_pcs("trinity child");
#endif
#ifdef CONFIG_GUARD_SHARED
	/*
	 * Guard-page attribution.  Under --guard-shared, a fuzzer
	 * write past a PROT_NONE-wrapped region traps SIGSEGV with
	 * si_addr inside the guard; emit one line naming the
	 * overflowed region, direction, distance, and writer PC.
	 * Skipped for non-SIGSEGV faults (not a guard trip by
	 * construction).  Writer PC is emitted raw (dladdr is not on
	 * the POSIX 2024 §2.4.3 safe list); the bugs.txt post-parser
	 * resolves PIE-relative offsets offline against the load base.
	 * See Documentation/signals.md.
	 */
	emit_guard_page_attribution(sig, info, ctx);
#endif
	write_siginfo_safely(sig, info, "trinity child");

	/*
	 * Stamp the currently-running childop's identity so the
	 * canary queue can attribute the crash to a specific op
	 * rather than bottoming out at child_process+offset.  Emits
	 * the syscall NUMBER, not the name (name-map is a pointer-
	 * chasing table walk not on the POSIX safe list); bugs.txt
	 * post-parser resolves names offline.  Gated on
	 * me->syscall.state so we emit -1 instead of a stale number
	 * from the previous call when the signal hit between
	 * syscalls.  See Documentation/signals.md.
	 */
	stamp_childop_identity();

	/*
	 * Completion sentinel: present only when all in-handler write
	 * stages finished without re-faulting or async kill.  A log
	 * that lacks this line was truncated; the last BUGLOG-PHASE
	 * line names the stage that was in flight at truncation time.
	 */
	{
		static const char done[] = "BUGLOG-COMPLETE\n";
		(void)syscall(SYS_write, STDERR_FILENO,
			      done, sizeof(done) - 1);
	}

	escalate_fault(sig);
}

/*
 * Handler for signals that should only be fatal if they come from the
 * kernel (real fault), not from a child process sending us garbage via
 * kill/tkill/tgkill.
 *
 * si_code > 0:  kernel generated (e.g. SEGV_MAPERR) — always fatal
 * si_code <= 0: sent by a process (SI_USER, SI_TKILL, SI_QUEUE)
 *   - from ourselves (abort(), raise()): fatal — it's a real crash
 *   - from a child process: ignore — it's fuzzer noise
 */
__attribute__((no_sanitize("address")))
void main_fault_handler(int sig, siginfo_t *info, __unused__ void *ctx)
{
	if (info->si_code > 0 || info->si_pid == mypid()) {
		/* Real fault or self-sent (e.g. glibc abort) — dump a
		 * backtrace and siginfo to stderr first so we have a handle
		 * on the crash even when no coredump lands (ulimit -c 0 or a
		 * restrictive core_pattern), then die properly. */
#if defined(USE_BACKTRACE) && !defined(__SANITIZE_ADDRESS__)
		/* RAW PCs only; see write_backtrace_raw_pcs(). */
		write_backtrace_raw_pcs("trinity main");
#endif
		write_siginfo_safely(sig, info, "trinity main");
		signal(sig, SIG_DFL);
		raise(sig);
	}
	/* Sent by a child process — ignore */
}
