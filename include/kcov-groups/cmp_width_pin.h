#pragma once

/* Sub-struct of struct kcov_shared, embedded as .cmp_width_pin.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_cmp_width_pin {
unsigned long cmp_width_pin_total;           /* unique width-match stamps executed */
unsigned long cmp_width_pin_would_differ;    /* subset where the matched slot has non-zero
					      * bits outside width_mask, so a high-bit-
					      * preserving splice would produce a value
					      * different from today's whole-slot overwrite */
};
