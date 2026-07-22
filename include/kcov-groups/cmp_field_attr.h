#pragma once

/* Sub-struct of struct kcov_shared, embedded as .cmp_field_attr.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_cmp_field_attr {
unsigned long cmp_field_attribution_scanned;
unsigned long cmp_field_attribution_found;
unsigned long cmp_field_attribution_pool_full;
unsigned long cmp_field_attribution_arg_skipped_bad_ptr;
unsigned long cmp_field_attribution_arg_skipped_short_alloc;
unsigned long cmp_field_timespec_skipped_bad_ptr;
};
