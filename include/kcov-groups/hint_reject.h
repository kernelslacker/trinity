#pragma once

/* Sub-struct of struct kcov_shared, embedded as .hint_reject.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_hint_reject {
unsigned long cmp_hints_save_reject_nonconst;
unsigned long cmp_hints_save_reject_uninteresting;
unsigned long cmp_hints_save_reject_sentinel;
unsigned long cmp_hints_save_reject_dup;
unsigned long cmp_hints_save_reject_cap;
};
