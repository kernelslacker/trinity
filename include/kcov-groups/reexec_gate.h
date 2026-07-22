#pragma once

/* Sub-struct of struct kcov_shared, embedded as .reexec_gate.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_reexec_gate {
unsigned long reexec_attribution_found_by_syscall[MAX_NR_SYSCALL];
unsigned long reexec_attribution_dropped_pending_by_syscall[MAX_NR_SYSCALL];
unsigned long reexec_attribution_found_by_childop[KCOV_CHILDOP_NR_MAX];
unsigned long reexec_attribution_ambiguous_by_childop[KCOV_CHILDOP_NR_MAX];
unsigned long reexec_attempts_by_childop[KCOV_CHILDOP_NR_MAX];
unsigned long per_childop_cmp_novelty_reexec[KCOV_CHILDOP_NR_MAX];
unsigned long reexec_gate_skip_in_reexec;
unsigned long reexec_gate_skip_disabled;
unsigned long reexec_gate_skip_mode;
unsigned long reexec_gate_skip_chain_mid;
unsigned long reexec_gate_skip_no_new_cmp;
unsigned long reexec_gate_skip_no_pending;
unsigned long reexec_gate_skip_rate;
unsigned long reexec_gate_pass;
unsigned long cmp_attribution_calls_eligible;
unsigned long cmp_attribution_snapshot_unavailable;
};
