#pragma once

/* Sub-struct of struct kcov_shared, embedded as .cmp_recent.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_cmp_recent {
unsigned long cmp_recent_inserts;
unsigned long cmp_recent_evicts;
unsigned long cmp_recent_would_pick;
unsigned long cmp_recent_would_miss;
unsigned long cmp_recent_live_picks;
};
