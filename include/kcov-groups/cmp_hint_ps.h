#pragma once

/* Sub-struct of struct kcov_shared, embedded as .cmp_hint_ps.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_cmp_hint_ps {
unsigned long per_syscall_cmp_injected[MAX_NR_SYSCALL];
unsigned long per_syscall_cmp_hint_pc_wins[MAX_NR_SYSCALL];

/* Per-syscall typed-hyp outcome partition.  Pairs with the
 * per_syscall_cmp_injected/_pc_wins counters above so the
 * cmp-frontier weight can route on real conversion rate rather
 * than insert volume alone.  Bumped from cmp_hyp_credit_outcome()
 * under the same nr-bounds guard as the sibling per-syscall
 * counters; only the typed-hyp outcome channels that can fire
 * today are partitioned. */
unsigned long per_syscall_cmp_hint_transition_wins[MAX_NR_SYSCALL];
unsigned long per_syscall_cmp_hint_misses[MAX_NR_SYSCALL];
unsigned long per_syscall_cmp_hint_corpus_saves[MAX_NR_SYSCALL];
unsigned long per_syscall_cmp_hint_destructive_skips[MAX_NR_SYSCALL];
unsigned long per_syscall_cmp_hint_cmp_novelty_wins[MAX_NR_SYSCALL];
};
