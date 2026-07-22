#pragma once

/* Sub-struct of struct kcov_shared, embedded as .hint_tier.
 * Layout is offset-sensitive; do not reorder fields. */

/*
 * Number of age-bucket slots for the CMP-hint staleness histogram
 * below.  Buckets are coarse-spaced log2 ranges of the durable
 * pool's LRU-clock delta at pick time (see cmp_hint_age_bucket()
 * in cmp_hints.c); 7 slots gives bucket-0 == hottest (delta == 0,
 * just-refreshed entry) through bucket-6 == staid tail (delta >=
 * 2048 pool mutations since refresh).  Defined here rather than in
 * cmp_hints.h because kcov.h must not include cmp_hints.h (see the
 * MAX_REEXEC_PENDING comment above for the dependency rationale).
 */
#define CMP_HINT_AGE_BUCKETS	7U

struct kcov_hint_tier {
unsigned long cmp_hint_tier_recent_wins;
unsigned long cmp_hint_tier_recent_misses;
unsigned long cmp_hint_tier_durable_wins;
unsigned long cmp_hint_tier_durable_misses;
unsigned long cmp_hint_durable_consumed_age[CMP_HINT_AGE_BUCKETS];
unsigned long cmp_hint_durable_age_wins[CMP_HINT_AGE_BUCKETS];
unsigned long cmp_hint_durable_age_misses[CMP_HINT_AGE_BUCKETS];
unsigned long per_syscall_cmp_reject_cap[MAX_NR_SYSCALL];
};
