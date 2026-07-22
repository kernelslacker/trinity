#pragma once

/* Sub-struct of struct kcov_shared, embedded as .reexec_step.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_reexec_step {
unsigned long reexec_step_skip_entry_null;
unsigned long reexec_step_skip_bad_slot;
};
