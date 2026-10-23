#pragma once

/* Sub-struct of struct kcov_shared, embedded as .cmp_field_attr.
 * Layout is offset-sensitive; do not reorder fields.
 *
 * The timespec counter belongs to the live field-scoped RedQueen
 * pin. */

struct kcov_cmp_field_attr {
unsigned long cmp_field_timespec_skipped_bad_ptr;
};
