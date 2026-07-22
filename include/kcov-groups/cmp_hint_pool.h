#pragma once

/* Sub-struct of struct kcov_shared, embedded as .cmp_hint_pool.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_cmp_hint_pool {
unsigned long cmp_hint_consumed_by_pool[CMP_HINT_POOL_KIND_NR];
unsigned long cmp_hint_pc_wins_by_pool[CMP_HINT_POOL_KIND_NR];
unsigned long cmp_hint_misses_by_pool[CMP_HINT_POOL_KIND_NR];
unsigned long cmp_hint_cmp_novelty_wins_by_pool[CMP_HINT_POOL_KIND_NR];

/*
 * SHADOW zero-PC-win hard-cool budget census for the old-flat
 * per-syscall pool.  The by-pool counters above quantify per-pool
 * conversion but say nothing about how many injections a
 * consecutive-miss cooling policy would have prevented.  Together
 * these two counters answer that question at the fixed budget
 * CMP_HINT_ZERO_WIN_BUDGET_T (see include/cmp_hints.h) so the
 * follow-up live-cool switchover can be sized against real data
 * rather than a guess.
 *
 * Bumped from cmp_hints_feedback_credit_pc()'s per-syscall arm
 * using the per-pool zero_win_streak state on struct cmp_hint_pool.
 * Only the CMP_HINT_POOL_PER_SYSCALL pool_kind participates -- the
 * field-scoped pool is a different structural cohort (hash-keyed
 * open-addressed buckets, not the flat pools[nr][do32] grid the
 * "old-flat" language refers to) and would need its own budget
 * shadow before it can be counted here.
 *
 *  cmp_hint_pool_zero_win_would_retire
 *      Bumped once per per-syscall pool crossing the streak from
 *      T-1 to T after a PC-outcome MISS credit -- the moment the
 *      hypothetical hard-cool would first fire on that pool.  A
 *      pool that gets a subsequent WIN resets its streak and can
 *      cross again on a later run of misses, contributing a
 *      second bump.  Interpret as "retire decisions the shadow
 *      would have made", not "distinct pools retired".
 *  cmp_hint_pool_zero_win_would_save
 *      Bumped once per PC-outcome credit whose per-pool streak
 *      (observed before this credit's update) was already >= T,
 *      counting both MISS credits past the retirement threshold
 *      and the WIN credits that would have been forfeit under a
 *      permanent hard-cool.  Interpret as "injections a cool at
 *      budget T would have prevented", spanning the saved-miss
 *      lane the retirement is designed to avoid and the lost-win
 *      lane it pays for.
 *
 * Live behaviour is byte-identical -- zero_win_streak is written
 * and read but never consulted by any injection / eviction /
 * ranking path; the shadow is measurement-only until the paired
 * live-cool hypothesis-gate switchover lands.
 */
unsigned long cmp_hint_pool_zero_win_would_retire;
unsigned long cmp_hint_pool_zero_win_would_save;
};
