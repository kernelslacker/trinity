#pragma once

/* Sub-struct of struct kcov_shared, embedded as .dedup.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_dedup {
	/* Total number of dedup_inc() calls that walked the full probe chain
	 * without finding either an empty slot or the matching edge.  When
	 * this happens, the call's bucket fidelity collapses to old any-hit
	 * semantics (count forced to 1).  Non-zero suggests KCOV_DEDUP_SIZE
	 * may need to grow. */
	unsigned long dedup_probe_overflow;
	/* Largest probe distance observed by dedup_inc() so far.  Monotonic
	 * across the run; useful for sizing KCOV_DEDUP_SIZE relative to the
	 * fattest single-call edge load actually seen. */
	unsigned long dedup_max_probe_seen;
};
