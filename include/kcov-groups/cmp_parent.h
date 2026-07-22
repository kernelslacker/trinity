#pragma once

/* Sub-struct of struct kcov_shared, embedded as .cmp_parent.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_cmp_parent {
unsigned long cmp_parent_calls_enabled;
unsigned long cmp_parent_calls_control;
unsigned long cmp_parent_new_cmps_enabled;
unsigned long cmp_parent_new_cmps_control;
};
