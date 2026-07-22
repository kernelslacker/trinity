#pragma once

/* Sub-struct of struct kcov_shared, embedded as .reexec_pending_hist.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_reexec_pending_hist {
unsigned long reexec_attempts_by_syscall[MAX_NR_SYSCALL];
unsigned long reexec_ambiguous_by_syscall[MAX_NR_SYSCALL];
unsigned long reexec_attribution_slot_hist[CMP_REDQUEEN_SLOT_HIST_NR];
unsigned long reexec_success_by_slot[CMP_REDQUEEN_SLOT_HIST_NR];
unsigned long typed_inject_fill_slot_hist[CMP_REDQUEEN_SLOT_HIST_NR];
unsigned long reexec_pending_dropped;
/*
 * Vestigial wastage counter.  Always zero: the dispatch_step tail
 * drains every staged reexec_pending[] entry per parent dispatch,
 * so no gate-pass entry is ever left behind.  Field retained only
 * for shm-ABI stability so existing stats consumers keep parsing
 * the layout unchanged.
 */
unsigned long reexec_pending_drain_unused;
unsigned long reexec_pending_pick_success[REEXEC_PENDING_PICK_HIST_NR];
};
