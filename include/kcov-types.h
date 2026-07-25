#pragma once

/* KCOV constants, enum modes, and non-shared child/diagnostic structs.
 * Split out of include/kcov.h.  Do not add fields to struct kcov_shared
 * here -- that lives in kcov-shared.h.
 *
 * The bulk of the type definitions have been carved into per-topic
 * sub-headers under include/kcov-groups/; this file now hosts the
 * "big two" diagnostic structs (kcov_cmp_diag and kcov_pc_diag) that
 * predate the group refactor, and their format helper decls.  Every
 * carved sub-header is #included below so consumers still get the full
 * kcov-types.h symbol set from a single include. */

#include <time.h>

#include "exit.h"	/* NUM_EXIT_REASONS */
#include "prop_ring.h"	/* enum scalar_kind, SCALAR_NR_KINDS */
#include "types.h"
#include "syscall.h"	/* MAX_NR_SYSCALL */
#include "cmp_hints.h"	/* CMP_HYP_STATE_NR */

#include "kernel/fcntl.h"

#include "kcov-groups/modes.h"
#include "kcov-groups/constants.h"
#include "kcov-groups/child_structs.h"
#include "kcov-groups/diag_types.h"

/* Per-failure-site diagnostic slots for the KCOV_TRACE_CMP setup and
 * runtime paths.  Written from child context (post-dup2-to-/dev/null,
 * so output() to stdout is silently swallowed) but read by the parent
 * via shared memory, which is how the data survives back out.  First
 * failure wins for *_errno (CAS-from-zero); *_count tallies every
 * failure at that site across all children. */
struct kcov_cmp_diag {
	int init_open_errno;
	int init_init_trace_errno;
	int init_mmap_errno;
	int init_enable_errno;
	int init_disable_errno;
	int runtime_enable_errno;
	int runtime_disable_errno;
	unsigned int init_open_count;
	unsigned int init_init_trace_count;
	unsigned int init_mmap_count;
	unsigned int init_enable_count;
	unsigned int init_disable_count;
	unsigned int runtime_enable_count;
	unsigned int runtime_disable_count;
};

/* Bound for the /proc/self/fd snapshot captured into struct
 * kcov_pc_diag::first_ebadf_proc_fds[].  Sized small enough that the
 * snapshot fits comfortably inside the 256-byte buffer the periodic
 * stats.c and main/loop.c summary callers hand to kcov_pc_diag_format(),
 * even with the rest of the diag line in front of it -- a snapshot of
 * the immediate fd neighbourhood of the protected slot is what the
 * operator needs to root-cause the closer; an exhaustive dump is the
 * unbounded-copy DoS shape this cap prevents.
 * Children that hold more than this number of fds get the snapshot
 * truncated; first_ebadf_proc_fd_count == this define on the wire
 * is the signal that truncation happened. */
#define KCOV_FIRST_EBADF_PROC_FD_MAX 16U

/* Per-failure-site diagnostic slots for the PC and remote KCOV enable/
 * disable paths.  Same shape as struct kcov_cmp_diag: first failure
 * wins for *_errno (CAS-from-zero), *_count tallies every failure at
 * that site across all children. */
struct kcov_pc_diag {
	int pc_enable_errno;
	int pc_disable_errno;
	int remote_enable_errno;
	unsigned int pc_enable_count;
	unsigned int pc_disable_count;
	unsigned int remote_enable_count;
	unsigned int remote_fallback_to_pc;
	unsigned int pc_enable_eintr_retries;
	unsigned int remote_enable_eintr_retries;
	unsigned int remote_fallback_pc_enable_eintr_retries;
	/* First-failure-wins capture of which fuzzed syscall was in
	 * flight (or had just retired) when kcov_enable_trace observed
	 * its first EBADF in this run.  CAS-from-zero on
	 * first_ebadf_op_nr selects the winner so the four fields below
	 * are consistent w.r.t. each other.  Used to pin down the
	 * close-race source: the syscall_nr field should resolve via
	 * the syscall table to close / close_range if the chain-
	 * substitution hypothesis holds; anything else points at an
	 * unaudited closer.  fd_value preserves the slot number at
	 * failure for cross-reference with KCOV_FD_HIGH_BASE. */
	unsigned long first_ebadf_op_nr;	/* CAS-elected winner, 0 == empty */
	unsigned long first_ebadf_pid;
	unsigned int  first_ebadf_syscall_nr;
	int           first_ebadf_fd_value;
	/* Richer context for the first-EBADF capture above.  All five
	 * fields below are written by the CAS winner after the four
	 * fields above land, so they share the same one-shot gate and
	 * stay consistent w.r.t. the winning child.  Readers must still
	 * gate on first_ebadf_valid (ACQUIRE) before consulting these.
	 *
	 *   generation              -- kcov_child::current_generation at
	 *                              latch time, so a winner's slot
	 *                              ties the snapshot to a per-child
	 *                              kcov-collect epoch.
	 *   last_fd_mut_syscall_nr  -- most recent close / dup / dup2 /
	 *                              dup3 / close_range / fcntl(F_DUPFD*)
	 *                              found in this child's
	 *                              child_syscall_ring; 0 if the ring
	 *                              held none.  Broad fd-mutator set
	 *                              (allocators included), retained for
	 *                              backward log compatibility -- prefer
	 *                              last_closer_syscall_nr below for
	 *                              EBADF root-cause work.
	 *   protected_touched       -- 1 if the captured fd-mut syscall
	 *                              targeted a protected fd (kcov PC /
	 *                              cmp fd, stderr, the stderr capture
	 *                              memfd).  0 means the closer was
	 *                              the unaudited path the registry
	 *                              cannot see.
	 *   last_closer_syscall_nr  -- most recent close / close_range /
	 *                              dup2 / dup3 found in this child's
	 *                              child_syscall_ring; 0 if the ring
	 *                              held none.  Strictly fd CLOSERS
	 *                              (dup and fcntl F_DUPFD* are fd
	 *                              ALLOCATORS and are excluded -- they
	 *                              never close kc->fd, but they can
	 *                              mask a real closer further back in
	 *                              the ring when last_fd_mut_syscall_nr
	 *                              walks the broad set).  Compare to
	 *                              last_fd_mut_syscall_nr: if they
	 *                              differ, a benign allocator was
	 *                              masking the real closer.
	 *   closer_protected_touched -- 1 if the captured closer's args
	 *                              targeted a protected fd via the
	 *                              fd_is_protected / lowest_protected_-
	 *                              fd_in_range registry (close: a1;
	 *                              close_range: [a1, a2]; dup2/dup3:
	 *                              a1 || a2).  0 means the captured
	 *                              closer did not name kc->fd at all
	 *                              -- either it was a benign close on
	 *                              an unrelated slot or the real
	 *                              closer scrolled off the 16-slot
	 *                              ring.
	 *   proc_fd_count           -- entries populated in proc_fds[].
	 *                              Capped at KCOV_FIRST_EBADF_PROC_FD_MAX
	 *                              so a fleet running with thousands
	 *                              of fds cannot blow the diag-line
	 *                              budget.
	 *   proc_fds[]              -- numeric /proc/self/fd snapshot of
	 *                              the winning child, truncated to
	 *                              proc_fd_count entries.
	 */
	uint64_t      first_ebadf_generation;
	unsigned int  first_ebadf_last_fd_mut_syscall_nr;
	unsigned char first_ebadf_protected_touched;
	unsigned char first_ebadf_proc_fd_count;
	/* Release/acquire beacon paired with the CAS on first_ebadf_op_nr
	 * above.  The CAS elects the winner but does NOT order the payload
	 * stores that follow it, so a naive reader that only checks
	 * first_ebadf_op_nr can observe the winner mark with the payload
	 * fields still stale.  The winner therefore performs every payload
	 * store above with RELAXED ordering and finally publishes
	 * first_ebadf_valid = 1 with __ATOMIC_RELEASE.  Payload consumers
	 * (kcov_diag_record / kcov_first_ebadf_trap_drain) must gate on an
	 * __ATOMIC_ACQUIRE load of this field before reading any payload
	 * field.  Slotted here (next to proc_fd_count) so the byte lands
	 * inside the existing 4-align padding before first_ebadf_proc_fds[]
	 * -- keeps sizeof(struct kcov_pc_diag) unchanged and preserves the
	 * shm-layout _Static_asserts in include/kcov-shared.h.  Mirrors the
	 * breadcrumb_ring.c and include/bug_backtrace.h valid-flag idiom. */
	unsigned char first_ebadf_valid;
	int           first_ebadf_proc_fds[KCOV_FIRST_EBADF_PROC_FD_MAX];
	unsigned int  first_ebadf_last_closer_syscall_nr;
	unsigned char first_ebadf_closer_protected_touched;
	/* Tally of sanitise_close_range() truncations: bumped each time
	 * the lowest_protected_fd_in_range() guard fires and rewrites
	 * rec->a2 to keep the kernel-side range below a protected fd
	 * (kcov PC/cmp, stderr, the stderr capture memfd).  Gives the
	 * /prot=absent diag-line readings a denominator -- if the
	 * counter is non-zero we know the guard is actively firing
	 * (close_range picker really did target a protected fd; the
	 * sanitizer caught it).  If first_ebadf=...:closer=nr<close_range>
	 * is rare AND this counter is non-zero, the guard is doing its
	 * job and close_range is exonerated as the EBADF source. */
	unsigned long close_range_protect_truncate_count;

	/* First-EBADF trap: full per-child diagnostic snapshot taken in
	 * kcov_latch_first_ebadf() so the operator can name the real
	 * closer even when it scrolled off the 16-slot child_syscall_-
	 * ring summarized by first_ebadf_last_closer_syscall_nr above.
	 * All four fields share the same one-shot CAS gate
	 * (first_ebadf_op_nr) as the existing latch fields -- readers
	 * must gate on first_ebadf_valid (ACQUIRE) before consulting
	 * these so the payload writes are visible.
	 *
	 *   recovery_attempts        -- kcov_child::recovery_attempts at
	 *                               latch time (capped at
	 *                               KCOV_RECOVERY_MAX == 3).  Non-
	 *                               zero means at least one prior
	 *                               kcov_recover_fd() succeeded for
	 *                               this child, so the EBADF being
	 *                               latched is on a REBUILT fd, not
	 *                               the original from kcov_init_-
	 *                               child.  Directly addresses the
	 *                               "kcov_recover_fd race" suspect:
	 *                               zero exonerates it.
	 *   cmp_recovery_attempts    -- companion counter for the cmp fd.
	 *   chronicle_count          -- number of valid slots actually
	 *                               populated in the snapshot below
	 *                               (the producer-side ring may have
	 *                               fewer than KCOV_EBADF_CHRONICLE_MAX
	 *                               valid slots if the child hadn't
	 *                               finished its first 16 syscalls).
	 *   chronicle[]              -- snapshot of the EBADF-observing
	 *                               child's syscall_ring at latch
	 *                               time, captured newest-first
	 *                               (chronicle[0] is the most recent
	 *                               retired syscall).  Lets a parent-
	 *                               side dumper emit the full trail
	 *                               so the operator can see the real
	 *                               closer even when the broad/
	 *                               closer walkers were defeated by
	 *                               ring scroll.
	 */
	unsigned char first_ebadf_recovery_attempts;
	unsigned char first_ebadf_cmp_recovery_attempts;
	unsigned char first_ebadf_chronicle_count;
	struct kcov_ebadf_chronicle_slot
		first_ebadf_chronicle[KCOV_EBADF_CHRONICLE_MAX];
};

/* Build a " name=<errno>/<count>" segment per non-zero cmp_diag site
 * into buf.  Each segment starts with a single space so the caller
 * concatenates straight into a log line.  Returns the number of bytes
 * written (excluding the trailing NUL); zero if no site has any
 * recorded failures, or if kcov_shm is NULL. */
int kcov_cmp_diag_format(char *buf, size_t bufsz, enum kcov_cmp_diag_part part);

/* Build a one-line summary of the PC/remote enable/disable
 * diagnostic counters defined in struct kcov_pc_diag.  Each
 * non-zero error site contributes a `" name=ERRNO_MACRO(errno)/count"`
 * token; each non-zero retry/success counter contributes a
 * `" name=count"` token; absent counters contribute nothing.
 * Same shape as kcov_cmp_diag_format so the two callsites in
 * stats.c periodic dump and main/loop.c summary stay in lockstep.
 * Returns the number of bytes written (excluding the trailing
 * NUL); zero if every counter is zero or kcov_shm is NULL. */
int kcov_pc_diag_format(char *buf, size_t bufsz);

/* Drain the first-EBADF trap dump (recovery counters + full
 * chronicle snapshot) once, the first time the caller observes a
 * non-zero first_ebadf_op_nr.  Returns true and emits one or more
 * output(0, ...) lines if a fresh trap is available, false if the
 * trap is empty or has already been drained in this process.
 * Parent-only call site: stats / main-stats periodic loop.  The
 * one-shot guard is process-local (a static bool inside the helper)
 * so a child that observed first_ebadf cannot accidentally fire the
 * dump from its routed-to-/dev/null output(); only the parent's
 * print loop ever sees the trap surface in the operator log. */
bool kcov_first_ebadf_trap_drain(void);
