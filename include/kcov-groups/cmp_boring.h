#pragma once

/* Sub-struct of struct kcov_shared, embedded as .cmp_boring.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_cmp_boring {
unsigned long cmp_hints_boring_arm_b_drops;
};
