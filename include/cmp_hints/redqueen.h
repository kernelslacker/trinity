#pragma once

/*
 * Per-call attribution scratch for the greedy CMP RedQueen re-exec.
 * cmp_hints_collect() scans each CMP record's arg1 (the
 * compile-time constant the kernel compared against) against the
 * dispatching syscall's rec->a1..aN.  On match it stamps (slot, cmp_ip,
 * value, size) here; the dispatch_step tail drains the buffer and re-runs
 * the syscall with the targeted slot pinned to the captured constant.
 *
 * Sized 8 entries (32 B each, ~256 B per child) so a single dispatch
 * can stage multiple attributions without truncation; the per-call
 * re-exec cap keeps actual drain to one per parent dispatch
 * in the initial deployment.  Reset every dispatch_step tail (drain +
 * count = 0) so attribution buffers do NOT carry forward across calls.
 *
 * "slot" is a 1-based arg index (1..6) matching the rec->aN naming
 * convention.  cmp_ip / value / size mirror the (ip, val, size) tuple
 * the existing pool entry uses; cmp_ip is the canonical (KASLR-stripped)
 * comparison-instruction address, the same value cmp_hints_collect()
 * routes into the bloom and the per-syscall pool.
 *
 * field_kind selects how the consumer applies the pin for the
 * field-scoped pool.
 * REEXEC_FIELD_NONE is the scalar-slot pin: the consumer splices `value`
 * into rec->a<slot>'s low `size` bytes and preserves its high bits (a
 * full or unknown width overwrites the whole slot outright).  The field
 * kinds instead treat rec->a<slot> as a pointer to a fixed-size struct
 * and pin ONE field
 * inside the freshly regenerated buffer, leaving the rest of the
 * generated struct intact -- so a kernel comparison that fired on a
 * single struct field is satisfied without spraying the constant across
 * the whole arg.  The scalar attribution scan runs first and stays
 * byte-for-byte unchanged; a field scan only runs after the scalar +
 * width passes miss, and only on syscalls that actually carry a
 * field-eligible arg, so scalar RedQueen stays cheap.  Today only the
 * ARG_TIMESPEC fixed-layout tv_sec/tv_nsec pair is wired; the xattr
 * namespace vocab and the variable-length / nested buffers land in the
 * follow-up alongside the field-scoped CMP pool.
 */
#define MAX_REEXEC_PENDING	8U

enum reexec_field_kind {
	REEXEC_FIELD_NONE = 0,		/* scalar slot pin (historical) */
	REEXEC_FIELD_TIMESPEC_SEC,	/* pin ((struct timespec *)slot)->tv_sec */
	REEXEC_FIELD_TIMESPEC_NSEC,	/* pin ((struct timespec *)slot)->tv_nsec */
};

struct reexec_pending {
	unsigned long cmp_ip;
	unsigned long value;
	unsigned int size;
	unsigned int slot;
	enum reexec_field_kind field_kind;
};

/*
 * Baseline re-exec gate denominator: ONE_IN(N) gate at the dispatch_step
 * tail outside plateau windows; inside a plateau classified as
 * CMP_RISING_PC_FLAT the gate switches to always-on (the intensification
 * arm).  4 == 25% baseline rate; the
 * realised per-CMP-child overhead is attribution_rate * 0.25 syscalls,
 * with the CMP-mode pool being roughly --cmp-fraction of the fleet, so
 * fleet-wide steady-state cost is well within noise.
 */
#define REDQUEEN_REEXEC_GATE_DENOM	4

/*
 * Per-window cap on re-exec dispatches.  Bounds runaway when a
 * hot attributing syscall accumulates a stream of matches: per-child
 * re-exec count is reset every REDQUEEN_REEXEC_WINDOW_OPS child
 * iterations and capped at REDQUEEN_REEXEC_WINDOW_CAP within the
 * window.  Exceedance bumps kcov_shm->reexec_flat.reexec_window_cap_hit and skips
 * further re-execs until the next window roll.
 *
 * Sized off STRATEGY_WINDOW so the cap is conceptually "no more than
 * 25% of the bandit's rotation budget" -- matches the same headroom
 * fraction the baseline re-exec gate targets.
 */
#define REDQUEEN_REEXEC_WINDOW_OPS	(1UL << 17)	/* mirror STRATEGY_WINDOW */
#define REDQUEEN_REEXEC_WINDOW_CAP	(REDQUEEN_REEXEC_WINDOW_OPS / 4)

/*
 * Per-call burst-drain cap for the CMP_RISING_PC_FLAT plateau A/B measure
 * arm.  When plateau_burst && child->burst_drain_arm_b, the dispatch_step
 * tail caps the per-call drain at this many reexec_pending[] entries and
 * breaks the loop on a helper FAIL (the per-window ceiling hit); the
 * control arm (burst_drain_arm_b == false) is unaffected and continues to
 * drain up to MAX_REEXEC_PENDING per the greedy baseline landed in
 * b86f2e77a846 ("drain all staged reexec_pending entries per dispatch").
 * K=4 is half the producer-side buffer cap: the measurement asks whether
 * a surgical top-K drain converts to more distinct-edge lift per attempt
 * than the greedy drain during the exact plateau where the greedy drain
 * has the most fuel to burn.
 */
#define REDQUEEN_REEXEC_BURST_DRAIN	4U
