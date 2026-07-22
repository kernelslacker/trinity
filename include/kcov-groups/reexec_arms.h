#pragma once

/* Sub-struct of struct kcov_shared, embedded as .reexec_arms.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_reexec_arms {
unsigned long reexec_new_edges_total;
unsigned long reexec_attempts_by_arm[2];
unsigned long reexec_new_cmps_by_arm[2];
unsigned long reexec_new_edges_by_arm[2];
};
