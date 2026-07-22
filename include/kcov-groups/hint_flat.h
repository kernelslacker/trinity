#pragma once

/* Sub-struct of struct kcov_shared, embedded as .hint_flat.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_hint_flat {
unsigned long cmp_hints_consumed;
unsigned long cmp_hint_wins;
unsigned long cmp_hint_misses;
unsigned long cmp_hint_cmp_novelty_wins;
unsigned long cmp_hint_stash_overflow;
unsigned long cmp_hint_credit_entry_evicted;
};
