#pragma once

/* Sub-struct of struct kcov_shared, embedded as .childop_kcov.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_childop_kcov {
/* Childop bracket attempt + skip-reason counters.  Every gated
 * kcov_bracket_begin() call from child.c bumps childop_kcov_attempts
 * once; the begin then either fires (childop_kcov_bracketed) or
 * short-circuits at one of the three reject arms (skipped_cmp /
 * skipped_nested / skipped_inactive — see kcov_bracket_begin in
 * kcov.c for the reject contract).  The arms are mutually exclusive
 * per attempt, so the invariant
 *   attempts == bracketed + skipped_cmp + skipped_nested
 *             + skipped_inactive
 * holds at run end (and is the smoke-test gate on this row).
 * Prereq for the childop-dual default flip: without the
 * per-reason split a low childop_edges_clean / attempts ratio can't
 * be told apart from "bracket never fired because of a known
 * short-circuit" vs "bracket fired but found nothing". */
unsigned long childop_kcov_attempts;
unsigned long childop_kcov_bracketed;
unsigned long childop_kcov_skipped_cmp;
unsigned long childop_kcov_skipped_nested;
unsigned long childop_kcov_skipped_inactive;
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
 * (the smoke-test gate on this row, parallel to the aggregate one). */
unsigned long childop_kcov_op_attempts[KCOV_CHILDOP_NR_MAX];
unsigned long childop_kcov_op_bracketed[KCOV_CHILDOP_NR_MAX];
unsigned long childop_kcov_op_skipped_cmp[KCOV_CHILDOP_NR_MAX];
unsigned long childop_kcov_op_skipped_nested[KCOV_CHILDOP_NR_MAX];
unsigned long childop_kcov_op_skipped_inactive[KCOV_CHILDOP_NR_MAX];
/* Per-childop trace-truncation count, indexed by enum child_op_type
 * (op = nr - CHILDOP_KCOV_NR_BASE inside kcov_collect()).  Mirrors
 * per_syscall_diag[].trace_truncated for the childop bracket path:
 * bumped when the kernel filled the entire trace buffer for a
 * bracketed childop call so the tail of the trace was dropped.
 * Sized to KCOV_CHILDOP_NR_MAX; a build-time assertion in kcov.c
 * pins NR_CHILD_OP_TYPES below the bound. */
unsigned long childop_kcov_trace_truncated[KCOV_CHILDOP_NR_MAX];
};
