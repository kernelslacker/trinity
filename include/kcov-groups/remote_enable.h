#pragma once

/* Sub-struct of struct kcov_shared, embedded as .remote_enable.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_remote_enable {
unsigned long remote_enable_requested[MAX_NR_SYSCALL];
unsigned long remote_enable_succeeded[MAX_NR_SYSCALL];
unsigned long remote_enable_failed[MAX_NR_SYSCALL];
unsigned long remote_fallback_to_local[MAX_NR_SYSCALL];
};
