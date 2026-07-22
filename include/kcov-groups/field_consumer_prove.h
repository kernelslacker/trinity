#pragma once

/* Sub-struct of struct kcov_shared, embedded as .field_consumer_prove.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_field_consumer_prove {
unsigned long cmp_field_consumer_prove_eligible;
unsigned long cmp_field_consumer_prove_edges_at_pick;
unsigned long cmp_field_consumer_prove_cmp_records_at_pick;
unsigned long cmp_field_consumer_prove_einval_at_pick;
};
