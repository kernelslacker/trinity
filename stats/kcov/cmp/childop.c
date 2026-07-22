/*
 * Childop CMP harvest periodic reporting.
 *
 * Owns kcov_cmp_render_childop_cmp_consume_shadow_block(), which reports
 * the childop-specific CMP consume shadow index bounds and names.  Kept
 * out of the generic CMP block so childop-specific fields do not leak
 * into base or hyp render code as more childop-shaped diagnostics grow.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <sys/utsname.h>
#include <stdio.h>
#include "arch.h"
#include "cmp_hints.h"
#include "kcov.h"
#include "shm.h"
#include "stats.h"
#include "stats-internal.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

#include "stats/kcov/cmp/internal.h"

/*
 * SHADOW consume-side render for the childop CMP path.  Aggregates
 * the per-nr childop_cmp_consume_would_pick / would_miss / would_
 * value_differs arrays (see include/kcov.h) into fleet-wide totals,
 * mirroring the hyp would_pick block above -- the per-nr split is
 * available in the raw shm read but the operator-facing dump keys on
 * the fleet-wide would-pull rate + value-differs ratio, which is
 * what the C3/C4 decision gate consults.  Render gated on any-delta
 * so the section stays quiet on a default --childop-cmp-consume=off
 * build (every per-nr counter reads zero).
 */
void kcov_cmp_render_childop_cmp_consume_shadow_block(long elapsed __unused__)
{
	static unsigned long prev_would_pick;
	static unsigned long prev_would_miss;
	static unsigned long prev_would_value_differs;
	unsigned long cur_would_pick = 0;
	unsigned long cur_would_miss = 0;
	unsigned long cur_would_value_differs = 0;
	unsigned long delta_would_pick;
	unsigned long delta_would_miss;
	unsigned long delta_would_value_differs;
	unsigned long any_delta;
	unsigned int nr_syscalls_to_scan;
	unsigned int i;

	if (kcov_shm == NULL)
		return;

	nr_syscalls_to_scan = biarch ? max_nr_64bit_syscalls : max_nr_syscalls;
	if (nr_syscalls_to_scan > MAX_NR_SYSCALL)
		nr_syscalls_to_scan = MAX_NR_SYSCALL;

	for (i = 0; i < nr_syscalls_to_scan; i++) {
		cur_would_pick += __atomic_load_n(
			&kcov_shm->childop_cmp_consume.childop_cmp_consume_would_pick[i],
			__ATOMIC_RELAXED);
		cur_would_miss += __atomic_load_n(
			&kcov_shm->childop_cmp_consume.childop_cmp_consume_would_miss[i],
			__ATOMIC_RELAXED);
		cur_would_value_differs += __atomic_load_n(
			&kcov_shm->childop_cmp_consume.childop_cmp_consume_would_value_differs[i],
			__ATOMIC_RELAXED);
	}

	delta_would_pick = sat_sub_ul(cur_would_pick, prev_would_pick);
	delta_would_miss = sat_sub_ul(cur_would_miss, prev_would_miss);
	delta_would_value_differs = sat_sub_ul(cur_would_value_differs,
					       prev_would_value_differs);
	any_delta = delta_would_pick | delta_would_miss |
		    delta_would_value_differs;

	if (any_delta != 0) {
		stats_log_write("Childop CMP consume shadow stats over last %lds:\n",
				elapsed);
		stats_log_write("  %-48s +%lu  (total %lu)\n",
				"childop_cmp_consume_would_pick",
				delta_would_pick, cur_would_pick);
		stats_log_write("  %-48s +%lu  (total %lu)\n",
				"childop_cmp_consume_would_miss",
				delta_would_miss, cur_would_miss);
		stats_log_write("  %-48s +%lu  (total %lu)\n",
				"childop_cmp_consume_would_value_differs",
				delta_would_value_differs,
				cur_would_value_differs);
	}

	prev_would_pick = cur_would_pick;
	prev_would_miss = cur_would_miss;
	prev_would_value_differs = cur_would_value_differs;
}
