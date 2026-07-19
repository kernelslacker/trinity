/*
 * Scalar CMP pipeline rows and shared rate-line helper.
 *
 * kcov_cmp_rate_line() is the shared periodic "name +delta (rate/s, total)"
 * emitter used by every render block in stats/kcov/cmp/.  Zero-delta rows
 * stay silent so unarmed windows and idle counters never appear in the dump.
 * Keep the format string identical: this is an output-contract row consumed
 * by grep-safe scans over stats.log.
 */

#include <stdio.h>

#include "stats-internal.h"

#include "stats/kcov/cmp/internal.h"

void kcov_cmp_rate_line(long elapsed, const char *name,
			unsigned long delta, unsigned long total)
{
	unsigned long rate_milli;

	if (delta == 0)
		return;
	rate_milli = (delta * 1000UL) / (unsigned long)elapsed;
	stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
			name, delta,
			rate_milli / 1000, rate_milli % 1000, total);
}
