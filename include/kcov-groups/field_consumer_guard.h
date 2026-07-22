#pragma once

/* Sub-struct of struct kcov_shared, embedded as .field_consumer_guard.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_field_consumer_guard {
unsigned long cmp_field_consumer_guard_variant_layout;
unsigned long cmp_field_consumer_guard_buffer_discrim;
unsigned long cmp_field_consumer_guard_len_pair;
unsigned long cmp_field_consumer_guard_nested_pointer;
unsigned long cmp_field_consumer_guard_dependent;
};
