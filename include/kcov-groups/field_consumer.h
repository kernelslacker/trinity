#pragma once

/* Sub-struct of struct kcov_shared, embedded as .field_consumer.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_field_consumer {
unsigned long cmp_field_consumer_would_pick;
unsigned long cmp_field_consumer_would_miss;
unsigned long cmp_field_consumer_key_absent;
unsigned long cmp_field_consumer_pool_corrupted;
unsigned long cmp_field_consumer_live_picks;
};
