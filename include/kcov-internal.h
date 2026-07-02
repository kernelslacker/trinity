#pragma once

/*
 * Internal header for the kcov/ cluster.  Holds cross-cluster helper
 * prototypes and extern decls for formerly-static state that had to
 * cross a TU boundary during the kcov.c carve.
 *
 * The public API for kcov lives in include/kcov.h; anything callers
 * outside kcov/ need continues to be declared there.  This header is
 * private to the kcov/ subdirectory and kcov.c itself.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/ioctl.h>	/* _IO/_IOR/_IOW for the kcov ioctl macros below */

#include "kcov.h"	/* public kcov API */

struct kcov_child;
struct childdata;

/* KCOV ioctl commands (from linux/kcov.h). */
#define KCOV_INIT_TRACE    _IOR('c', 1, unsigned long)
#define KCOV_ENABLE        _IO('c', 100)
#define KCOV_DISABLE       _IO('c', 101)
#define KCOV_REMOTE_ENABLE _IOW('c', 102, struct kcov_remote_arg)

/*
 * Userspace copy of struct kcov_remote_arg from linux/kcov.h.
 * We define it here to avoid requiring kernel headers at build time.
 */
struct kcov_remote_arg {
	uint32_t	trace_mode;
	uint32_t	area_size;
	uint32_t	num_handles;
	uint32_t	__pad;
	uint64_t	common_handle;
	uint64_t	handles[];
};

/*
 * Fallback flush cadence: bump local_syscalls_since_flush every
 * kcov_collect() call and force a flush once this many syscalls have
 * elapsed without one.  Picked so the parent's per-iteration drain
 * still sees a non-stale total_calls under a workload that goes long
 * stretches without finding a new edge; the found-new piggyback
 * keeps the common-case latency near zero.  Shared between the
 * hot-path bump in kcov_collect and the drain guard in
 * kcov_child_flush_stats.
 */
#define KCOV_LOCAL_STATS_FLUSH_SYSCALLS 4096u

/*
 * Cached KASLR base of the running kernel (_text address as reported by
 * /proc/kallsyms).  Zero when the writer could not resolve it, so callers
 * that stamp or compare the value only need the "!= 0" bit to know
 * whether canonicalisation is in effect.  Defined in kcov.c alongside
 * the KASLR lookup helpers; the persist and (later) collection clusters
 * read the value directly so the on-disk header records the same base
 * the hot path canonicalises against.
 */
extern uint64_t kcov_kaslr_base;

/*
 * Record a KCOV PC or remote enable/disable failure into the parent-
 * visible pc_diag / cmp_diag slots.  Lives in kcov/diag.c alongside
 * the other diag helpers; the enable / lifecycle clusters call it
 * from the ioctl error arms so the failure surfaces in the periodic
 * stats dump.  First failure wins for the errno slot; the count slot
 * bumps unconditionally so aggregate failure rates are visible even
 * when everyone hits the same errno.
 */
void kcov_diag_record(int *errno_slot, unsigned int *count_slot, int err);

/*
 * One-shot chronicle latch for the first EBADF ever observed on a
 * PC-enable ioctl.  Lives in kcov/diag.c so the ring-walk helpers
 * that classify which fuzzed syscall plausibly aliased the kcov fd
 * stay next to their diag formatter.  Called from both PC-enable
 * error arms in kcov/enable.c; CAS-from-zero on first_ebadf_op_nr
 * makes the latch fire at most once per run.
 */
void kcov_latch_first_ebadf(struct kcov_child *kc, struct childdata *c);

/*
 * Recover a kcov fd that returned EBADF from an enable ioctl by re-
 * opening /sys/kernel/debug/kcov, re-mmapping the trace buffer, and
 * relocating the fd back into the high-fd range.  Lives in
 * kcov/lifecycle.c so all kcov-fd lifetime invariants have a single
 * home; the enable arms in kcov/enable.c call it from their EBADF
 * error branches.  Returns true when the fd was successfully
 * re-established, false when the child should exit with the recovery-
 * exhausted sentinel.
 */
bool kcov_recover_fd(struct kcov_child *kc, bool is_cmp);

/*
 * Coverage-jump breadcrumb, sampled at the tail of kcov_collect() when
 * call_nr is in hand.  Lives in kcov/plateau.c alongside kcov_plateau_
 * check so all fleet-level coverage-curve reactions sit in one place;
 * kcov/collect.c calls it via this extern from the hot path.
 */
void kcov_covjump_breadcrumb_maybe(unsigned long call_nr);
