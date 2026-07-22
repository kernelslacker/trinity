#pragma once

/* Sub-struct of struct kcov_shared, embedded as .cmp_shared_tier_shadow.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_cmp_shared_tier_shadow {
unsigned long cmp_shared_tier_shadow_would_confirm;
};
