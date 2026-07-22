#pragma once

/* Sub-struct of struct kcov_shared, embedded as .hints_canary.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_hints_canary {
/* Wild-write detection in the cmp_hints SHM pool.  Bumped when a
 * read path (cmp_hints_try_get / pool_add_locked) observes a
 * pool->count value above the CMP_HINTS_PER_SYSCALL hard cap --
 * the only way that can happen is a kernel-side store through a
 * fuzzed syscall arg pointer landing on the count field.  Without
 * this gate the bogus count drives rnd_modulo_u32 to a wild index
 * and the entries[].value load walks off the 1.1 MB SHM mapping. */
unsigned long cmp_hints_count_oob;
/* Companion canary-channel counters bumped from the same gate.
 * Probed only on a count_oob hit, so the cost is paid only when
 * a stomp has already happened; in steady state these stay at 0
 * and the canary loads never run.  A direct stomp that lands
 * exactly on the count field (4 bytes at the cap-violating
 * offset) trips NONE of these -- only cmp_hints_count_oob -- so
 * a real wild-write event commonly surfaces as count_oob > 0
 * with all three canary counters at 0.  Non-zero canary deltas
 * narrow the stomp's width and direction:
 *  - canary_lock_post: write overshot the lock or undershot
 *    the count area, landing between offset 24 and 32 in the
 *    pool (gap between lock_t and count).
 *  - canary_pre: write reached entries[] from the header side
 *    (overshot last_used_stamp into entries).
 *  - canary_post: write reached entries[] from the tail side
 *    (overran entries[] from beyond the last slot). */
unsigned long cmp_hints_canary_lock_post_corrupt;
unsigned long cmp_hints_canary_pre_corrupt;
unsigned long cmp_hints_canary_post_corrupt;
};
