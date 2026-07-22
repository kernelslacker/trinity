#pragma once

/* Sub-struct of struct kcov_shared, embedded as .hyp_flat.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_hyp_flat {
unsigned long cmp_hyp_observations;
unsigned long cmp_hyp_inserted;
unsigned long cmp_hyp_pool_full;
unsigned long cmp_hyp_kind_full;
unsigned long cmp_hyp_consumed;
unsigned long cmp_hyp_pc_wins;
unsigned long cmp_hyp_transition_wins;
unsigned long cmp_hyp_cmp_novelty_wins;
unsigned long cmp_hyp_misses;
unsigned long cmp_hyp_disabled_skips;
unsigned long cmp_hyp_corpus_save;
unsigned long cmp_hyp_destructive;
unsigned long cmp_hyp_context_skip;
};
