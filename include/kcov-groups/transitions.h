#pragma once

/* Sub-struct of struct kcov_shared, embedded as .transitions.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_transitions {
unsigned long transition_edges_found;
unsigned long transition_distinct_edges;
unsigned long per_syscall_transition_edges[MAX_NR_SYSCALL];
unsigned long per_syscall_transition_edges_previous[MAX_NR_SYSCALL];
unsigned long per_syscall_transition_edges_real[MAX_NR_SYSCALL];
unsigned long per_syscall_transition_edges_real_local[MAX_NR_SYSCALL];
unsigned char transition_seen[KCOV_NUM_TRANSITIONS];
};
