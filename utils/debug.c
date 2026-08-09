/*
 * Various routines useful for debugging.
 */


#ifdef USE_BACKTRACE
#include <execinfo.h>
#endif
#include <errno.h>		// errno for open() failure reporting in classify_child_buglog
#include <signal.h>		// SIGSEGV / SIGABRT / SIGBUS / SIGILL for fault_beacon dump
#include <stdbool.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>		// memmem for BUGLOG-COMPLETE tail scan
#include <syslog.h>
#include <stdio.h>
#include <limits.h>
#include <fcntl.h>		// O_RDONLY / O_CLOEXEC for partial-log tail check
#include <unistd.h>
#include "child.h"
#include "debug.h"
#include "fd-event.h"
#include "list.h"
#include "params.h"
#include "pids.h"
#include "pre_crash_ring.h"
#include "shm.h"
#include "stats_ring.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"
#include "version.h"

#define BACKTRACE_SIZE 100

static void __show_backtrace(void)
{
#ifdef USE_BACKTRACE
	unsigned int j, nptrs;
	void *buffer[BACKTRACE_SIZE];
	char **strings;

	nptrs = backtrace(buffer, BACKTRACE_SIZE);

	strings = backtrace_symbols(buffer, nptrs);
	if (strings == NULL) {
		perror("backtrace_symbols");
		return;
	}

	for (j = 0; j < nptrs; j++)
		output(0, "%s\n", strings[j]);

	free(strings);
#endif
}

static void show_child_backtrace(void)
{
	struct childdata *child = this_child();

	set_dontkillme(child, true);
	__show_backtrace();
	set_dontkillme(child, false);
}

void show_backtrace(void)
{
	pid_t pid = mypid();

	if (pid == mainpid) {
		__show_backtrace();
		return;
	}

	show_child_backtrace();
}

void __attribute__((noreturn)) __BUG(const char *bugtxt, const char *filename, const char *funcname, unsigned int lineno)
{
	struct childdata *child = this_child();

#ifdef USE_BACKTRACE
	/* Stamp raw backtrace frames into shared memory BEFORE the
	 * hit_bug flip below.  init_child redirects child stderr to
	 * /dev/null, so the backtrace_symbols output show_backtrace()
	 * emits from this context is lost.  The parent re-symbolises
	 * these frames from its own real-stderr context via
	 * dump_child_bug().  The release-store on .count happens in
	 * program order before the release-store on hit_bug, so the
	 * parent's acquire-load on hit_bug also makes the populated
	 * frame array visible. */
	if (child != NULL) {
		int n = backtrace(child->bug_backtrace.frames,
				  BUG_BACKTRACE_MAX_FRAMES);
		__atomic_store_n(&child->bug_backtrace.count,
				 (uint32_t) (n > 0 ? n : 0),
				 __ATOMIC_RELEASE);
	}
#endif

	outputerr("BUG!: %s\n", bugtxt);
	outputerr("BUG!: %s\n", VERSION);
	outputerr("BUG!: [%d] %s:%s:%u\n", mypid(), filename, funcname, lineno);

	show_backtrace();

	/* Drain the pre-crash syscall ring(s).
	 *
	 * Child-side BUG: skip the ring dump from this context entirely.
	 * The child's stderr is /dev/null, so dump_one_ring()'s output
	 * would be lost; the parent's main_loop per-tick poll picks the
	 * event up via hit_bug and dump_child_bug() re-runs
	 * pre_crash_ring_dump() against the same shared ring from real
	 * parent stderr.
	 *
	 * Parent-side BUG (this_child() returns NULL): iterate every
	 * child.  Parent crashes are typically downstream fallout from a
	 * child's recent wild write, so the offending syscall is sitting
	 * in some child's ring even though the parent has no obvious
	 * pointer to which one. */
	if (child == NULL) {
		pre_crash_ring_dump_all(outputerr);
		/* Parent-side BUG: main_loop has stopped ticking by the
		 * time we reach this branch, so any slots still pending in
		 * a child's fd_event / stats ring would never be consumed.
		 * Flush them now so the post-mortem sees the same per-child
		 * fd/stats context the running loop would have aggregated.
		 * Drain order matches the per-tick order in main_loop
		 * (fd_event -> stats).  These helpers are single-consumer
		 * parent-only; calling them from a child-side BUG would race
		 * the still-running parent, which is why this lives only in
		 * the parent branch.  Mirrors the kmsg-monitor pre-crash
		 * drain wired up for WARN/OOPS banners; this is the
		 * __BUG() counterpart for the other rings. */
		fd_event_drain_all();
		stats_ring_drain_all();
	}

	/*
	 * Stamp the bug into the per-child shm record so the parent's
	 * reap path can attribute the dying child to a self-inflicted
	 * assertion.  Strings are literals at the __BUG() call site so
	 * stashing the pointer is safe (they live in .rodata which all
	 * processes share).
	 */
	if (child != NULL) {
		child->bug_text = bugtxt;
		child->bug_func = funcname;
		child->bug_lineno = lineno;
		__atomic_store_n(&child->hit_bug, true, __ATOMIC_RELEASE);
	}

	/*
	 * Halt fleet-wide spawning on first BUG.  Existing children keep
	 * running until they exit naturally; the BUG'd child stays alive
	 * (spinning below) so gdb can attach to it directly to inspect
	 * the corruption that tripped the assertion.  Other slots drain
	 * to empty as their children exit; replace_child skips them
	 * because of this flag.  Parent stays alive in main_loop (we
	 * deliberately do NOT set exit_reason) so it's also gdb-able.
	 *
	 * The whole fuzz fleet gets quarantined on a single BUG.  This
	 * is by design: every BUG firing represents a bug Trinity itself
	 * found and that we want to investigate, not silently respawn
	 * past.  If the noise of catching every duplicate becomes a
	 * problem, change replace_child's bug-quarantine behaviour
	 * before changing this — never silence the BUG itself.
	 */
	__atomic_store_n(&shm->spawn_no_more, true, __ATOMIC_RELEASE);

	outputerr("BUG!: fleet halted — fuzzing stopped, attach gdb to pid %d (or any other live process) to inspect\n",
		mypid());

	/* Now spin indefinitely (but allow ctrl-c).  set_dontkillme keeps
	 * the parent's progress watchdog from SIGKILL'ing us, so the
	 * spinning child stays alive and ptrace-attachable. */

	if (child != NULL)
		set_dontkillme(child, true);

	while (1) {
		if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) == EXIT_SIGINT) {
			if (child != NULL)
				set_dontkillme(child, false);
			exit(EXIT_FAILURE);
		}
		sleep(1);
	}
}

void dump_child_bug(struct childdata *child)
{
	if (child == NULL)
		return;

	/* Idempotent once-only: bug_dumped cmpxchg gates the print so the
	 * per-tick poll and the zombie watchdog (or any future caller)
	 * surface the forensic exactly once.  hit_bug stays set so the
	 * zombie watchdog's "kernel finishing teardown" attribution still
	 * sees this child was a BUG, not a kernel SIGKILL. */
	bool expected = false;
	if (!__atomic_compare_exchange_n(&child->bug_dumped, &expected,
					  true, 0,
					  __ATOMIC_ACQ_REL,
					  __ATOMIC_RELAXED))
		return;

	outputerr("BUG!: (child %u pid %d) %s\n",
		  child->num, pids[child->num],
		  child->bug_text ? child->bug_text : "?");
	outputerr("BUG!: %s\n", VERSION);
	outputerr("BUG!: %s:%u\n",
		  child->bug_func ? child->bug_func : "?",
		  child->bug_lineno);

#ifdef USE_BACKTRACE
	/* Acquire-load on .count pairs with the child's release-store in
	 * __BUG so the frames[] reads observe the populated array.
	 * backtrace_symbols allocates internally; this is parent context
	 * (the caller is main_loop's per-tick poll), so the libc/malloc-
	 * touchy call is safe. */
	uint32_t n = __atomic_load_n(&child->bug_backtrace.count,
				     __ATOMIC_ACQUIRE);
	if (n > 0 && n <= BUG_BACKTRACE_MAX_FRAMES) {
		char **strs = backtrace_symbols(child->bug_backtrace.frames,
						(int) n);
		if (strs != NULL) {
			uint32_t i;

			for (i = 0; i < n; i++)
				outputerr("  %s\n", strs[i]);
			free(strs);
		} else {
			outputerr("  (backtrace_symbols failed; %u raw frames in shared mem)\n",
				  n);
		}
	} else {
		outputerr("  (no backtrace captured — child died before stamping)\n");
	}
#else
	outputerr("  (backtrace unavailable: built without USE_BACKTRACE)\n");
#endif

	/* pre_crash_ring entries live in shared childdata; dump_one_ring
	 * needs only the childdata pointer and an anchor timestamp, both
	 * available here. */
	pre_crash_ring_dump(child, outputerr);

	outputerr("BUG!: fleet halted — fuzzing stopped, attach gdb to pid %d (or any other live process) to inspect\n",
		  pids[child->num]);
}

/*
 * Beacon-capture accounting.  Written only from dump_child_fault_beacon()
 * and classify_child_buglog() (parent main-loop / reap context, no
 * concurrent writers), read from print_stats() and finalize_and_exit()
 * via beacon_loss_get_counts().
 *
 * total_beacon_dumps      -- incremented once per FAULT! beacon surfaced.
 * no_buglog_beacons       -- beacon fired but no per-pid bug log file
 *                            present (open() failed in child or child died
 *                            before reaching open_buglog_and_drain_stderr).
 * partial_buglog_beacons  -- log file present but BUGLOG-COMPLETE sentinel
 *                            absent; child re-faulted mid-handler.
 *                            Classified only after the child is reaped so
 *                            the per-tick poll path cannot produce false
 *                            positives (child publishes the beacon before
 *                            writing the log, so a mid-write check yields
 *                            a spurious partial for an otherwise-complete
 *                            log).  Partial counts are therefore a strict
 *                            lower bound: false negatives are possible
 *                            (unlikely; would require the child to finish
 *                            writing between reap and classify_child_buglog),
 *                            false positives are not.
 * unreadable_buglog_beacons -- log file present but open() or read() on
 *                              the parent side failed, or read returned 0
 *                              bytes (zero-byte log, e.g. child SIGKILLed
 *                              between open() and first write()).  Tracked
 *                              separately from partial to keep the
 *                              re-faulted-mid-write signal clean.
 * complete_buglog_beacons   -- log file present, readable, and
 *                              BUGLOG-COMPLETE sentinel found in the tail.
 *                              Counted directly so that
 *                              total - (no_log + partial + unreadable +
 *                              complete + skipped_timed_out) surfaces a
 *                              visible 'pending/lost' residual for beacons
 *                              that never reached classify_child_buglog().
 * skipped_timed_out_beacons -- beacon written but classify deliberately
 *                              skipped because the child was not confirmed
 *                              dead on the timed-out reap arm; the child
 *                              may still be writing its bug log.
 */
static unsigned int total_beacon_dumps;
static unsigned int no_buglog_beacons;
static unsigned int partial_buglog_beacons;
static unsigned int unreadable_buglog_beacons;
static unsigned int complete_buglog_beacons;
static unsigned int skipped_timed_out_beacons;

/*
 * Return the five beacon-capture counters accumulated across the run.
 * Called from print_stats() and finalize_and_exit() to surface numbers in
 * the run summary.  Safe to call from any parent context.
 *
 * total - (no_log + partial + unreadable + complete + skipped_timed_out)
 * gives the 'pending/lost' residual: beacons surfaced but never classified
 * because the owning child was killed (e.g. via kill_all_kids()) before
 * reap_child() ran classify_child_buglog().
 */
void beacon_loss_get_counts(unsigned int *out_total,
			    unsigned int *out_no_log,
			    unsigned int *out_partial,
			    unsigned int *out_unreadable,
			    unsigned int *out_complete,
			    unsigned int *out_skipped_timed_out)
{
	if (out_total)
		*out_total             = total_beacon_dumps;
	if (out_no_log)
		*out_no_log            = no_buglog_beacons;
	if (out_partial)
		*out_partial           = partial_buglog_beacons;
	if (out_unreadable)
		*out_unreadable        = unreadable_buglog_beacons;
	if (out_complete)
		*out_complete          = complete_buglog_beacons;
	if (out_skipped_timed_out)
		*out_skipped_timed_out = skipped_timed_out_beacons;
}

/*
 * Record one beacon that was skipped on the timed-out reap arm.  Written
 * only from process_zombie_pending() (parent main-loop context, no concurrent
 * writers); plain increment matches the other beacon-loss counters above.
 */
void beacon_loss_count_skipped_timed_out(void)
{
	skipped_timed_out_beacons++;
}

void dump_child_fault_beacon(struct childdata *child)
{
	struct child_fault_beacon *beacon;
	uint32_t written;
	const char *signame;
	int sig;

	if (child == NULL)
		return;

	beacon = &child->fault_beacon;

	/* Acquire-load on .written pairs with the child's release-store
	 * in child_fault_handler so the other beacon fields read here are
	 * the post-stamp values, not a torn snapshot the writer was
	 * mid-way through. */
	written = __atomic_load_n(&beacon->written, __ATOMIC_ACQUIRE);
	if (written == 0U)
		return;

	/* Idempotent once-only: fault_beacon_dumped cmpxchg gates the
	 * print so the per-tick poll and any future caller (zombie
	 * watchdog, reap path) surface the forensic exactly once.
	 * beacon->written stays set so post-reap diagnostics can still
	 * see this child died with a stamped beacon. */
	bool expected = false;
	if (!__atomic_compare_exchange_n(&child->fault_beacon_dumped,
					  &expected, true, 0,
					  __ATOMIC_ACQ_REL,
					  __ATOMIC_RELAXED))
		return;

	sig = (int)beacon->signo;
	switch (sig) {
	case SIGSEGV: signame = "SIGSEGV"; break;
	case SIGABRT: signame = "SIGABRT"; break;
	case SIGBUS:  signame = "SIGBUS";  break;
	case SIGILL:  signame = "SIGILL";  break;
	default:      signame = "?";       break;
	}

	outputerr("FAULT!: (child %u pid %d) %s (si_code=%d, si_addr=%p)\n",
		  child->num, pids[child->num], signame,
		  (int)beacon->sig_code, beacon->fault_addr);
	if (beacon->fault_ip != NULL || beacon->fault_sp != NULL) {
		outputerr("FAULT!:  ip=%p sp=%p\n",
			  beacon->fault_ip, beacon->fault_sp);
	} else {
		outputerr("FAULT!:  ip=? sp=? (no ucontext extractor on this arch)\n");
	}
	outputerr("FAULT!:  op_nr=%lu last_syscall_nr=%d\n",
		  beacon->op_nr, (int)beacon->last_syscall_nr);
	outputerr("FAULT!:  (signal-time beacon -- pre-libc capture; the in-handler backtrace may have re-faulted)\n");

	/*
	 * Structured aggregation key.  Stable one-line format parsed by the
	 * bugs.txt post-processor to produce distinct summary rows per crash
	 * class.  Key components:
	 *
	 *   <signame>/<si_code>/<fault_ip_class>/<breadcrumb_hash>
	 *
	 * fault_ip_class buckets the instruction pointer at signal delivery:
	 *   nil     -- NULL (extractor returned NULL or no ucontext)
	 *   nearnil -- tiny user address (< 4096; near-null deref)
	 *   kernel  -- kernel-space VA (bit 63 set on x86-64/arm64)
	 *   user    -- normal user-space address
	 *
	 * breadcrumb_hash is a 32-bit rotate-mix fold over the last <=8
	 * ring entries of any kind.  Every entry contributes its kind byte
	 * so that its existence and position are always visible in the hash.
	 * For PRE_CRASH_KIND_SYSCALL entries the syscall_nr (with bit 31 set
	 * when do32bit is true) is additionally mixed so that the same
	 * syscall on different ABIs hashes differently.
	 * PRE_CRASH_KIND_TAINT and PRE_CRASH_KIND_CANARY entries contribute
	 * only their kind: CANARY's syscall_nr fields are untrustworthy
	 * (copied from a stomped syscallrecord), and TAINT's syscall_nr is
	 * zero-initialised, so neither is mixed into the key.
	 * Each step rotates the accumulator left by 5 bits then XORs in the
	 * contribution: crumb = (crumb<<5 | crumb>>27) ^ value.  This is
	 * position-sensitive (order matters) and non-cancelling (a repeated
	 * value changes the accumulator rather than zeroing it), so crashes
	 * sharing the same {signal, si_code, fault_ip_class} bucket but
	 * arriving from distinct call sequences remain distinguishable.
	 *
	 * The key is appended to the FAULT! stream (outerr.log) so a simple
	 * grep/awk over the existing log format is sufficient to aggregate
	 * crashes; no binary format or separate file is needed.
	 */
	{
		const char *ip_class;
		uintptr_t fip = (uintptr_t)beacon->fault_ip;
		uint32_t crumb = 0;

		if (beacon->fault_ip == NULL)
			ip_class = "nil";
		else if (fip < 4096U)
			ip_class = "nearnil";
		else if (fip >= (uintptr_t)0x8000000000000000UL)
			ip_class = "kernel";
		else
			ip_class = "user";

		/* Rotate-mix fold over the last <=8 ring entries (any kind). */
		{
			struct pre_crash_ring *ring = &child->pre_crash;
			uint32_t head = __atomic_load_n(&ring->base.head,
							__ATOMIC_ACQUIRE);
			uint32_t look = head < 8U ? head : 8U;
			uint32_t i;

			for (i = 0; i < look; i++) {
				uint32_t slot = (head - look + i) &
						(PRE_CRASH_RING_SIZE - 1U);
				uint8_t kind = ring->entries[slot].kind;
				crumb = (crumb << 5 | crumb >> 27) ^ (uint32_t)kind;
				if (kind == PRE_CRASH_KIND_SYSCALL) {
					uint32_t nr = (uint32_t)ring->entries[slot].syscall_nr |
						      (ring->entries[slot].do32bit ? 0x80000000U : 0);
					crumb = (crumb << 5 | crumb >> 27) ^ nr;
				}
			}
		}

		outputerr("FAULT!:  key=%s/%d/%s/%08x\n",
			  signame, (int)beacon->sig_code, ip_class, crumb);
	}

	/*
	 * Count this beacon.  Log-file classification (no_log / partial /
	 * unreadable) is deferred to classify_child_buglog(), called from
	 * the reap path after the child has fully exited.  Deferring
	 * avoids false positives on this per-tick poll path: the child
	 * publishes the beacon *before* opening or writing the log
	 * (health/signals.c stamp_fault_beacon precedes
	 * open_buglog_and_drain_stderr), so a mid-write check here would
	 * spuriously charge partial for an otherwise-complete log.
	 */
	total_beacon_dumps++;
}

/*
 * Classify the on-disk bug log for a child whose beacon was surfaced by
 * dump_child_fault_beacon().  Must be called after the child has exited so
 * that the classification sees the final state of the log file rather than
 * a snapshot mid-write.  The pid is passed explicitly so zombie-deferred
 * callers in process_zombie_pending() can supply the original pid after
 * pids[child->num] has already been set to EMPTY_PIDSLOT (b5bfac7d77d9
 * moved the bug-log path build from dump_child_fault_beacon into here).
 *
 * Four outcomes, tracked as distinct counters:
 *
 *  no_log:      access() shows no trinity-bug-<pid>.log -- child's
 *               open_buglog_and_drain_stderr open() failed, or the child
 *               died before reaching the buglog open call.
 *
 *  unreadable:  log file is present but parent open() or read() failed,
 *               or read() returned 0 bytes (zero-byte log, e.g. child
 *               SIGKILLed between open() and first write()).  Worst-case
 *               truncation is the most dangerous outcome; tracked
 *               separately from partial to keep the re-faulted-mid-write
 *               signal clean.
 *
 *  partial:     log file is present and readable, but the BUGLOG-COMPLETE
 *               sentinel is absent from its tail.  Child re-faulted inside
 *               the in-handler write stages before writing the sentinel.
 *
 *  complete:    log file present, readable, BUGLOG-COMPLETE sentinel found.
 *               Counted directly via complete_buglog_beacons++ in the
 *               memmem()-found branch so that the residual
 *               total - (no_log + partial + unreadable + complete)
 *               surfaces beacons from children lost before reap_child()
 *               ran classify_child_buglog() (e.g. SIGKILL via
 *               kill_all_kids()).  Prior to b5bfac7d77d9 this gap was
 *               silently absorbed into the subtraction-derived complete.
 *
 * access() and open()/read() are safe here (parent context).
 */
void classify_child_buglog(struct childdata *child, pid_t pid)
{
	char logpath[PATH_MAX + 64];
	int pn;

	if (child == NULL)
		return;
	if (__atomic_load_n(&child->fault_beacon.written, __ATOMIC_ACQUIRE) == 0U)
		return;

	pn = snprintf(logpath, sizeof(logpath), "%s/trinity-bug-%d.log",
		      trinity_tmpdir_abs(), (int)pid);
	if (pn <= 0 || (size_t)pn >= sizeof(logpath))
		return;

	if (access(logpath, F_OK) != 0) {
		/* No log file at all. */
		no_buglog_beacons++;
		outputerr("FAULT!:  (no bug log at %s -- open() failed in child "
			  "or pre-stamp death; "
			  "no_log: %u/%u)\n",
			  logpath,
			  no_buglog_beacons,
			  total_beacon_dumps);
		return;
	}

	/* Log file present: open and read the tail for the sentinel. */
	{
		int tfd = open(logpath, O_RDONLY | O_CLOEXEC);

		if (tfd < 0) {
			/* Parent-side open() failure. */
			unreadable_buglog_beacons++;
			outputerr("FAULT!:  (unreadable bug log at %s -- "
				  "parent open() failed (errno %d); "
				  "unreadable: %u/%u)\n",
				  logpath, errno,
				  unreadable_buglog_beacons,
				  total_beacon_dumps);
		} else {
			enum { TAIL_BYTES = 64 };
			char tail[TAIL_BYTES];
			ssize_t nr;

			if (lseek(tfd, -(off_t)TAIL_BYTES, SEEK_END) < 0)
				(void)lseek(tfd, 0, SEEK_SET);
			nr = read(tfd, tail, sizeof(tail));
			close(tfd);

			if (nr <= 0) {
				/*
				 * Zero-byte log (nr == 0): child was killed
				 * between open() and first write() -- the
				 * worst truncation class, not a complete log.
				 * Read error (nr < 0): treat identically.
				 */
				unreadable_buglog_beacons++;
				outputerr("FAULT!:  (unreadable bug log at %s -- "
					  "%s; "
					  "unreadable: %u/%u)\n",
					  logpath,
					  (nr == 0) ? "zero-byte log (killed before first write)"
						    : "read() error",
					  unreadable_buglog_beacons,
					  total_beacon_dumps);
			} else if (memmem(tail, (size_t)nr,
					  "BUGLOG-COMPLETE", 15) == NULL) {
				partial_buglog_beacons++;
				outputerr("FAULT!:  (partial bug log -- "
					  "BUGLOG-COMPLETE absent; "
					  "handler likely re-faulted; "
					  "partial: %u/%u)\n",
					  partial_buglog_beacons,
					  total_beacon_dumps);
			} else {
				/* BUGLOG-COMPLETE sentinel present: full log captured. */
				complete_buglog_beacons++;
			}
		}
	}
}

void dump_syscallrec(struct syscallrecord *rec)
{
	struct syscallentry *entry = get_syscall_entry(rec->nr, rec->do32bit);
	const char *name = entry ? entry->name : "?";

	output(0, " nr:%d (%s) a1:%lx a2:%lx a3:%lx a4:%lx a5:%lx a6:%lx retval:%ld errno_post:%d\n",
		rec->nr, name, rec->a1, rec->a2, rec->a3, rec->a4, rec->a5, rec->a6, rec->retval, rec->errno_post);
	output(0, " do32bit:%d\n", rec->do32bit);
	output(0, " state:%d\n",
		__atomic_load_n(&rec->state, __ATOMIC_RELAXED));
	output(0, " prebuffer : %p (len:%zu)\n", rec->prebuffer, strnlen(rec->prebuffer, PREBUFFER_LEN));
	output(0, " -> %.*s\n", PREBUFFER_LEN, rec->prebuffer);
	output(0, " postbuffer : %p (len:%zu)\n", rec->postbuffer, strnlen(rec->postbuffer, POSTBUFFER_LEN));
	output(0, " -> %.*s\n", POSTBUFFER_LEN, rec->postbuffer);
}

void dump_childdata(struct childdata *child)
{
	output(0, "child struct @%p\n", child);

	output(0, " op_nr:%lx\n", child->op_nr);

	output(0, "syscall: %p\n", &child->syscall);
	dump_syscallrec(&child->syscall);

	/*
	 * dump_childdata runs in the parent against another process's
	 * childdata.  The objects pointer lives in shared childdata but
	 * addresses the owning child's private heap, so neither the
	 * pointer nor anything it points at is safe to deref from this
	 * process.  Print the address and stop.
	 */
	output(0, "objects: %p (private to owning child)\n", child->objects);

	output(0, " tp.tv_sec=%ld tp.tv_nsec=%ld\n", child->tp.tv_sec, child->tp.tv_nsec);

	output(0, "seed: %u\n", child->seed);
	output(0, "childnum: %d\n", child->num);

	output(0, "killcount: %d\n",
		__atomic_load_n(&child->kill_count, __ATOMIC_RELAXED));
	output(0, "dontkillme: %d\n", child->dontkillme);
	output(0, "\n");
};

/*
 * Mirror of the Linux kernel's CONFIG_DEBUG_LIST validators.
 *
 * On any failure we log the specific corruption class observed (NULL
 * pointer, poison, or broken back-link) along with the call site, then
 * route to __BUG so the existing backtrace+spin path lets gdb attach
 * before the process is reaped.
 */
void __list_add_valid_or_die(struct list_head *new,
                             struct list_head *prev,
                             struct list_head *next,
                             const char *file,
                             const char *func,
                             unsigned int line)
{
	if (prev == NULL || next == NULL) {
		outputerr("list_add corruption at %s:%s:%u: prev=%p next=%p new=%p (NULL insertion point — caller passed in a torn list head)\n",
			file, func, line, prev, next, new);
		__BUG("list_add: NULL prev or next", file, func, line);
	}
	if (new == prev || new == next) {
		outputerr("list_add corruption at %s:%s:%u: new=%p coincides with prev=%p or next=%p (double-add or self-insertion)\n",
			file, func, line, new, prev, next);
		__BUG("list_add: self-insertion", file, func, line);
	}
	if (next->prev != prev) {
		outputerr("list_add corruption at %s:%s:%u: next->prev should be prev (%p) but is %p (next=%p new=%p) — surrounding link trampled\n",
			file, func, line, prev, next->prev, next, new);
		__BUG("list_add: next->prev != prev", file, func, line);
	}
	if (prev->next != next) {
		outputerr("list_add corruption at %s:%s:%u: prev->next should be next (%p) but is %p (prev=%p new=%p) — surrounding link trampled\n",
			file, func, line, next, prev->next, prev, new);
		__BUG("list_add: prev->next != next", file, func, line);
	}
}

void __list_del_entry_valid_or_die(struct list_head *entry,
                                   const char *file,
                                   const char *func,
                                   unsigned int line)
{
	struct list_head *prev, *next;

	if (entry == NULL) {
		outputerr("list_del corruption at %s:%s:%u: entry pointer itself is NULL\n",
			file, func, line);
		__BUG("list_del: entry == NULL", file, func, line);
	}
	if (entry->next == NULL || entry->prev == NULL) {
		outputerr("list_del corruption at %s:%s:%u: entry=%p has NULL link (next=%p prev=%p) — entry was zeroed by a stray write or never INIT_LIST_HEAD'd\n",
			file, func, line, entry, entry->next, entry->prev);
		__BUG("list_del: entry next/prev is NULL", file, func, line);
	}
	if (entry->next == LIST_POISON1) {
		outputerr("list_del corruption at %s:%s:%u: entry=%p next is LIST_POISON1 — double list_del or use-after-list_del\n",
			file, func, line, entry);
		__BUG("list_del: entry->next == LIST_POISON1", file, func, line);
	}
	if (entry->prev == LIST_POISON2) {
		outputerr("list_del corruption at %s:%s:%u: entry=%p prev is LIST_POISON2 — double list_del or use-after-list_del\n",
			file, func, line, entry);
		__BUG("list_del: entry->prev == LIST_POISON2", file, func, line);
	}

	prev = entry->prev;
	next = entry->next;
	if (prev->next != entry) {
		outputerr("list_del corruption at %s:%s:%u: entry=%p prev=%p but prev->next=%p (expected entry) — back-link broken\n",
			file, func, line, entry, prev, prev->next);
		outputerr(" entry contents: list.next=%p list.prev=%p\n", entry->next, entry->prev);
		outputerr(" prev contents:  list.next=%p list.prev=%p\n", prev->next, prev->prev);
		__BUG("list_del: prev->next != entry", file, func, line);
	}
	if (next->prev != entry) {
		outputerr("list_del corruption at %s:%s:%u: entry=%p next=%p but next->prev=%p (expected entry) — back-link broken\n",
			file, func, line, entry, next, next->prev);
		outputerr(" entry contents: list.next=%p list.prev=%p\n", entry->next, entry->prev);
		outputerr(" next contents:  list.next=%p list.prev=%p\n", next->next, next->prev);
		/*
		 * Distinguish the three forensic states with a one-line summary:
		 *   - both next->next and next->prev are NULL  -> next is a
		 *     zeroed freed object chunk (release_obj zeroes the struct
		 *     before deferred_free_enqueue, or a memset that hit it).
		 *   - next->prev is NULL and next->next looks like a heap-range
		 *     pointer                                   -> next is a
		 *     deferred-free or stale object chunk still carrying a live-
		 *     looking forward link.
		 *   - next->prev is NULL and next->next looks like a valid list
		 *     pointer                                   -> stray 8-byte
		 *     write to next->prev only.
		 */
		if (next->prev == NULL && next->next == NULL)
			outputerr(" forensic: next is fully zeroed (freelist-push leftover or wholesale memset)\n");
		else if (next->prev == NULL)
			outputerr(" forensic: only next->prev is zero; next->next=%p (single 8-byte clobber, or freelist-linked)\n", next->next);
		__BUG("list_del: next->prev != entry", file, func, line);
	}
}

/*
 * debugging output.
 * This is just a convenience helper to avoid littering the code
 * with dozens of 'if debug == true' comparisons causing unnecessary nesting.
 */
#define BUFSIZE 1024

void debugf(const char *fmt, ...)
{
	char debugbuf[BUFSIZE];
	va_list args;

	if (shm->debug == false)
		return;

	va_start(args, fmt);
	vsnprintf(debugbuf, BUFSIZE, fmt, args);
	va_end(args);
	output(0, "%s", debugbuf);
}

/* This is a bit crappy, wrapping a varargs fn with another,
 * but this saves us having to do the openlog/closelog for every
 * case where we want to write a message.
 */
void syslogf(const char *fmt, ...)
{
	char debugbuf[BUFSIZE];
	va_list args;

	va_start(args, fmt);
	vsnprintf(debugbuf, BUFSIZE, fmt, args);
	va_end(args);

	openlog("trinity", LOG_CONS|LOG_PERROR, LOG_USER);
	syslog(LOG_CRIT, "%s", debugbuf);
	closelog();
}
