#pragma once

/* Sub-struct of struct kcov_shared, embedded as .field_consumer_shadow.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_field_consumer_shadow {
unsigned long cmp_field_consumer_would_value_differs;
};
