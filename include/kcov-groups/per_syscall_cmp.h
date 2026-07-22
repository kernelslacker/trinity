#pragma once

/* Sub-struct of struct kcov_shared, embedded as .per_syscall_cmp.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_per_syscall_cmp {
unsigned long per_syscall_cmp_inserts[MAX_NR_SYSCALL];
/* Snapshot of per_syscall_cmp_inserts at the previous dump_stats()
 * call, matching the per_syscall_edges_previous pattern above so the
 * sibling top-N block can compute the same kind of delta. */
unsigned long per_syscall_cmp_inserts_previous[MAX_NR_SYSCALL];
/* See struct kcov_per_syscall_diag.  Indexed by [nr][do32 ? 1 : 0]
 * so the 32-bit-record vs 64-bit-record arch dimension is preserved
 * alongside the syscall slot.  ~96 KiB of shm. */
struct kcov_per_syscall_diag per_syscall_diag[MAX_NR_SYSCALL][2];
};
