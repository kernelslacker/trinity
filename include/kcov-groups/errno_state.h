#pragma once

/* Sub-struct of struct kcov_shared, embedded as .errno_state.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_errno_state {
unsigned long per_syscall_errno[MAX_NR_SYSCALL][ERRNO_BUCKET_NR];
/* Per-syscall errno-bucket "seen at least once in this run" bitmask.
 * Bit `bucket` set iff a call with errno bucket `bucket` has been
 * classified for syscall slot nr.  Set via __atomic_fetch_or by the
 * errno-gradient-save trigger in handle_syscall_ret() to detect
 * "first non-EFAULT bucket per syscall per window" events; the EFAULT
 * bit is deliberately never set (the trigger excludes EFAULT, the
 * userspace-pointer noise floor, so its seen-state is uninteresting).
 * SHADOW-ONLY: no live selection or scoring code consumes this; only
 * the errno-gradient save predicate reads it.  RELAXED atomics --
 * concurrent writers across children can race a bit-set with no harm
 * (the loser's first-seen test fails, the winner's succeeds; either
 * way the bit lands set). */
unsigned int errno_bucket_seen[MAX_NR_SYSCALL];
/* Sibling of last_edge_at: stamps total_calls at the moment the
 * most recent EFAULT return was observed for this syscall slot.
 * Lets a future picker pass bias selection away from syscalls
 * stuck in pure-EFAULT regimes (no recent edges + a recent EFAULT
 * stamp is the diagnostic signature).  Stored as the same
 * total_calls counter last_edge_at uses so the two fields are
 * directly comparable (delta = last_edge_at[nr] - last_efault_at[nr]
 * is a signed "has progress outrun the fault?" signal). */
unsigned long last_efault_at[MAX_NR_SYSCALL];
};
