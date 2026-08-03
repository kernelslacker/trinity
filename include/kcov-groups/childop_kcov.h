#pragma once

/* Sub-struct of struct kcov_shared, embedded as .childop_kcov.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_childop_kcov {
/* Childop bracket attempt + skip-reason counters.  Every gated
 * kcov_bracket_begin() call from child.c bumps childop_kcov_attempts
 * once; the begin then either fires (childop_kcov_bracketed) or
 * short-circuits at one of the four reject arms (skipped_cmp /
 * skipped_nested / skipped_inactive / skipped_sample — see
 * kcov_bracket_begin in kcov.c for the first three, and the
 * --childop-kcov-sample 1-of-N gate in child_process() for the
 * fourth).  The arms are mutually exclusive per attempt, so the
 * invariant
 *   attempts == bracketed + skipped_cmp + skipped_nested
 *             + skipped_inactive + skipped_sample
 * holds at run end (and is the smoke-test gate on this row).
 * Prereq for the childop-dual default flip: without the
 * per-reason split a low childop_edges_clean / attempts ratio can't
 * be told apart from "bracket never fired because of a known
 * short-circuit" vs "bracket fired but found nothing".
 *
 * skipped_sample is the 1-of-N outer-bracket sampler skip arm:
 * when --childop-kcov-sample=N (default N=4) is >1, only 1 in every
 * N eligible dispatches opens the outer bracket, so the cost of the
 * KCOV_ENABLE / KCOV_DISABLE ioctl pair is amortised across N
 * dispatches.  Inner per-syscall brackets (do_syscall's own
 * kcov_enable_trace / kcov_disable / kcov_collect cycle) still fire
 * every call regardless -- sampling only touches the OUTER childop
 * bracket introduced by --childop-kcov-attribution.  The bump lives
 * at the child.c gate BEFORE kcov_bracket_begin() so a sampled-out
 * dispatch never opens an ioctl on the KCOV fd, distinguishing it
 * cleanly from skipped_inactive (bracket began, then bailed on
 * ioctl failure) and skipped_nested (bracket refused because an
 * outer was in flight).  Non-eligible dispatches
 * (!op_uses_outer_bracket, mode == OFF, !have_kcov) bump nothing
 * at all -- the attempts counter is scoped to eligible-and-mode-on
 * dispatches, so a run with sample_n=1 keeps every counter
 * byte-identical to the pre-sample codepath. */
unsigned long childop_kcov_attempts;
unsigned long childop_kcov_bracketed;
unsigned long childop_kcov_skipped_cmp;
unsigned long childop_kcov_skipped_nested;
unsigned long childop_kcov_skipped_inactive;
unsigned long childop_kcov_skipped_sample;
/* Per-childop mirrors of the aggregate childop_kcov_* counters above,
 * indexed by enum child_op_type.  Sized to KCOV_CHILDOP_NR_MAX (same
 * bound as childop_kcov_trace_truncated[] below); kcov.c's build-time
 * assertion on NR_CHILD_OP_TYPES applies to this shape as well.
 *
 * The aggregate counters answer "did any childop's outer bracket get
 * declined for reason X?", but cannot say WHICH ops were affected.
 * That distinction matters for the canary queue: a childop_edges_
 * clean[op] == 0 window is indistinguishable from "signal unavailable
 * (MODE ARTIFACT of the CMP-mode PC-bracket rejection)" without a
 * per-op reason attribution.  These slots let close_window_and_
 * decide() detect the confounded shape and route it to the
 * unattributed_edges recommendation instead of silently promoting on
 * discovered-only traffic or demoting a still-productive op.
 *
 * Producers are in child_process() (child/child.c), mirroring the
 * decision tree kcov_bracket_begin() runs.  Kept in sync with that
 * function; if a new reject arm is added there, add the matching
 * per-op counter here and a bump in the caller.
 *
 * Invariant per op:
 *   childop_kcov_op_attempts[op] ==
 *       childop_kcov_op_bracketed[op]
 *     + childop_kcov_op_skipped_cmp[op]
 *     + childop_kcov_op_skipped_nested[op]
 *     + childop_kcov_op_skipped_inactive[op]
 *     + childop_kcov_op_skipped_sample[op]
 * (the smoke-test gate on this row, parallel to the aggregate one). */
unsigned long childop_kcov_op_attempts[KCOV_CHILDOP_NR_MAX];
unsigned long childop_kcov_op_bracketed[KCOV_CHILDOP_NR_MAX];
unsigned long childop_kcov_op_skipped_cmp[KCOV_CHILDOP_NR_MAX];
unsigned long childop_kcov_op_skipped_nested[KCOV_CHILDOP_NR_MAX];
unsigned long childop_kcov_op_skipped_inactive[KCOV_CHILDOP_NR_MAX];
unsigned long childop_kcov_op_skipped_sample[KCOV_CHILDOP_NR_MAX];
/* Per-childop trace-truncation count, indexed by enum child_op_type
 * (op = nr - CHILDOP_KCOV_NR_BASE inside kcov_collect()).  Mirrors
 * per_syscall_diag[].trace_truncated for the childop bracket path:
 * bumped when the kernel filled the entire trace buffer for a
 * bracketed childop call so the tail of the trace was dropped.
 * Sized to KCOV_CHILDOP_NR_MAX; a build-time assertion in kcov.c
 * pins NR_CHILD_OP_TYPES below the bound. */
unsigned long childop_kcov_trace_truncated[KCOV_CHILDOP_NR_MAX];
/* Per-childop KCOV bracket trace-size telemetry.  Populated in
 * kcov_bracket_end() from the struct kcov_pc_result.trace_size the
 * kcov_collect() PC walk already stores (post-cap PC count for this
 * bracket).  Together with childop_kcov_op_bracketed[] (sample count)
 * and childop_kcov_trace_truncated[] (buffer-full events), operators
 * can compute mean and peak buffer utilisation per op:
 *
 *   mean = trace_size_sum[op] / childop_kcov_op_bracketed[op]
 *   peak = trace_size_max[op]
 *   truncation-rate = childop_kcov_trace_truncated[op] /
 *                     childop_kcov_op_bracketed[op]
 *
 * An op whose mean approaches KCOV_TRACE_SIZE or whose truncation-rate
 * is non-trivial is dropping tail edges under a single outer bracket
 * -- the signal that motivates a sub-burst refactor (split the hot
 * loop into N smaller brackets so each fits the buffer, then credit
 * new edges proportionally instead of raw).  Kept as pure telemetry
 * for now; no scoring path consumes these yet.  Sized to
 * KCOV_CHILDOP_NR_MAX; same NR_CHILD_OP_TYPES build-time bound
 * asserted in kcov.c applies here.
 *
 * trace_size_max uses a compare-and-swap high-water update in
 * kcov_bracket_end() (same shape as per_syscall_diag[].max_trace_size
 * in kcov_collect()); trace_size_sum uses a plain relaxed add.  Sum
 * is unsigned long -- at KCOV_TRACE_SIZE == 65535 and 2^63 brackets
 * before overflow the counter is unreachable for any real run. */
unsigned long childop_kcov_op_trace_size_sum[KCOV_CHILDOP_NR_MAX];
unsigned long childop_kcov_op_trace_size_max[KCOV_CHILDOP_NR_MAX];
};
