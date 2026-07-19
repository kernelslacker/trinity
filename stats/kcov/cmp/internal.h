/*
 * Private declarations shared across stats/kcov/cmp/ render TUs.
 *
 * All prototypes here are called only from within the stats/kcov/cmp/ TUs;
 * the only public entry point is kcov_cmp_stats_periodic_dump(), which stays
 * declared in include/stats.h.  Keep new declarations local to this file
 * unless a non-KCOV-CMP stats file genuinely needs them.
 */

#pragma once

void kcov_cmp_rate_line(long elapsed, const char *name,
			unsigned long delta, unsigned long total);
