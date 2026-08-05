#pragma once

#include "child-api.h"
#include "syscall.h"
#include "utils.h"

void show_backtrace(void);

extern void __BUG(const char *bugtxt, const char *filename, const char *funcname, unsigned int lineno)
	__attribute__((noreturn));

#define BUG(bugtxt)	do { \
	__BUG(bugtxt, __FILE__, __func__, __LINE__); \
	unreachable(); \
} while (0)

#define BUG_ON(condition)	do { if ((condition)) BUG(__stringify(condition)); } while (0)

void dump_childdata(struct childdata *child);
void dump_syscallrec(struct syscallrecord *rec);

/*
 * Surface a child-context __BUG() event to the real (parent) stderr.
 * Idempotent via the child->bug_dumped cmpxchg gate: simultaneous
 * pollers print exactly one copy.  Re-symbolises child->bug_backtrace
 * in parent context (libc-touchy, fine here -- not async-signal-safe
 * but never called from a signal handler) and drains
 * child->pre_crash_ring.  Called from the main_loop per-tick poll.
 */
void dump_child_bug(struct childdata *child);

/*
 * Surface a signal-time fault beacon stamped by child_fault_handler
 * (SIGSEGV / SIGBUS / SIGILL / SIGABRT) to the real (parent) stderr.
 * Idempotent via the child->fault_beacon_dumped cmpxchg gate.  The
 * beacon is the only forensic that survives when the in-handler
 * backtrace_symbols_fd path re-faults walking a corrupted ld.so
 * writable segment.  Called from the main_loop per-tick poll, same
 * shape as dump_child_bug().
 */
void dump_child_fault_beacon(struct childdata *child);

/*
 * Classify the on-disk bug log for a reaped child that had a fault beacon.
 * Must be called after the child has exited to avoid false-positive partial
 * counts that the per-tick poll path would produce by reading the log
 * mid-write.  The pid is passed explicitly so zombie-deferred callers can
 * supply the original pid after pids[child->num] is already EMPTY_PIDSLOT.
 * Updates no_buglog_beacons, partial_buglog_beacons, and
 * unreadable_buglog_beacons.  No-op when child is NULL or no beacon fired.
 */
void classify_child_buglog(struct childdata *child, pid_t pid);

/*
 * Return the four beacon-capture loss counters accumulated by
 * dump_child_fault_beacon() / classify_child_buglog() across the run.
 * Any out-pointer may be NULL.
 *   *out_total       -- total beacons surfaced (cmpxchg-gated)
 *   *out_no_log      -- no per-pid bug log file on disk
 *   *out_partial     -- log present but BUGLOG-COMPLETE sentinel absent
 *   *out_unreadable  -- log present but zero-byte, read error, or open error
 *   *out_complete    -- log present, readable, BUGLOG-COMPLETE sentinel found
 *
 * total - (no_log + partial + unreadable + complete + skipped_timed_out)
 * is the 'pending/lost' residual: beacons surfaced but never classified
 * (child killed before reap_child() ran classify_child_buglog()).
 */
void beacon_loss_get_counts(unsigned int *out_total,
			    unsigned int *out_no_log,
			    unsigned int *out_partial,
			    unsigned int *out_unreadable,
			    unsigned int *out_complete,
			    unsigned int *out_skipped_timed_out);

/*
 * Increment the skipped-timed-out beacon counter.  Call from the reap
 * path when fault_beacon.written is set but classify is skipped because
 * the child was not confirmed dead on the timed-out arm.
 */
void beacon_loss_count_skipped_timed_out(void);

void syslogf(const char *fmt, ...);
