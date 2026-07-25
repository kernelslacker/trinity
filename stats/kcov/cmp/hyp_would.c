/*
 * Typed hypothesis SHADOW would-* render lane.
 *
 * Owns the pure-observation "would" evaluators: would-pick from the
 * cmp_hints_try_get_ex() ladder, and would-promote / would-demote
 * from cmp_hyp_credit_outcome().  These bump on the shadow path only
 * -- h->state is unchanged -- so a delta reads as "would the live
 * state machine have fired here".  Both blocks are any-delta gated so
 * the section stays quiet until credit / pick sites start firing.
 * Called only from kcov_cmp_stats_periodic_dump() in
 * stats/kcov/cmp/periodic.c.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <stdio.h>
#include "arch.h"
#include "child-api.h"
#include "cmp_hints.h"
#include "kcov.h"
#include "params.h"
#include "shm.h"
#include "stats.h"
#include "stats-internal.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

#include "stats/kcov/cmp/internal.h"

/*
 * SHADOW would-pick telemetry from cmp_hints_try_get_ex().  Bumped
 * per successful raw pool return after the typed hypothesis store
 * is walked through the EXACT > ENUM_FAMILY > BITMASK > RANGE
 * ladder for the same (cmp_ip, width).  Independent any-delta
 * gate: a SHADOW run with an empty typed store still bumps
 * would_miss on every pull, and that is exactly the signal worth
 * surfacing once the consumer demand picks up.
 */
void kcov_cmp_render_hyp_would_pick_block(long elapsed __unused__)
{
	static const char * const kind_labels[CMP_HYP_KIND_NR] = {
		"exact", "range", "boundary", "bitmask",
		"enum_family", "alignment", "length",
		"foreign_value",
	};
	static unsigned long prev_hyp_would_pick_kind[CMP_HYP_KIND_NR];
	static unsigned long prev_hyp_would_miss_kind[CMP_HYP_KIND_NR];
	static unsigned long prev_hyp_would_value_differs;
	static unsigned long prev_hyp_would_value_differs_kind[CMP_HYP_KIND_NR];
	unsigned long cur_hyp_would_pick_kind[CMP_HYP_KIND_NR];
	unsigned long cur_hyp_would_miss_kind[CMP_HYP_KIND_NR];
	unsigned long cur_hyp_would_value_differs_kind[CMP_HYP_KIND_NR];
	unsigned long cur_hyp_would_value_differs;
	unsigned long delta_hyp_would_value_differs;
	unsigned long any_would_delta = 0;
	unsigned int k;

	for (k = 0; k < CMP_HYP_KIND_NR; k++) {
		cur_hyp_would_pick_kind[k] = __atomic_load_n(
			&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_would_pick_by_kind[k],
			__ATOMIC_RELAXED);
		cur_hyp_would_miss_kind[k] = __atomic_load_n(
			&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_would_miss_by_kind[k],
			__ATOMIC_RELAXED);
		cur_hyp_would_value_differs_kind[k] = __atomic_load_n(
			&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_would_value_differs_by_kind[k],
			__ATOMIC_RELAXED);
		any_would_delta |=
			sat_sub_ul(cur_hyp_would_pick_kind[k], prev_hyp_would_pick_kind[k]) |
			sat_sub_ul(cur_hyp_would_miss_kind[k], prev_hyp_would_miss_kind[k]) |
			sat_sub_ul(cur_hyp_would_value_differs_kind[k],
				   prev_hyp_would_value_differs_kind[k]);
	}
	cur_hyp_would_value_differs = __atomic_load_n(
		&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_would_value_differs, __ATOMIC_RELAXED);
	delta_hyp_would_value_differs =
		sat_sub_ul(cur_hyp_would_value_differs, prev_hyp_would_value_differs);
	any_would_delta |= delta_hyp_would_value_differs;

	if (any_would_delta != 0) {
		stats_log_write("KCOV CMP hyp would-pick shadow stats over last %lds:\n",
				elapsed);
		for (k = 0; k < CMP_HYP_KIND_NR; k++) {
			stats_log_write(
				"  cmp_hyp_would[%-13s] pick +%lu (total %lu)  miss +%lu (total %lu)  value_differs +%lu (total %lu)\n",
				kind_labels[k],
				sat_sub_ul(cur_hyp_would_pick_kind[k], prev_hyp_would_pick_kind[k]),
				cur_hyp_would_pick_kind[k],
				sat_sub_ul(cur_hyp_would_miss_kind[k], prev_hyp_would_miss_kind[k]),
				cur_hyp_would_miss_kind[k],
				sat_sub_ul(cur_hyp_would_value_differs_kind[k],
					   prev_hyp_would_value_differs_kind[k]),
				cur_hyp_would_value_differs_kind[k]);
		}
		stats_log_write("  %-32s +%lu  (total %lu)\n",
				"cmp_hyp_would_value_differs",
				delta_hyp_would_value_differs,
				cur_hyp_would_value_differs);
	}

	for (k = 0; k < CMP_HYP_KIND_NR; k++) {
		prev_hyp_would_pick_kind[k] = cur_hyp_would_pick_kind[k];
		prev_hyp_would_miss_kind[k] = cur_hyp_would_miss_kind[k];
		prev_hyp_would_value_differs_kind[k] =
			cur_hyp_would_value_differs_kind[k];
	}
	prev_hyp_would_value_differs = cur_hyp_would_value_differs;
}
/*
 * SHADOW would-promote / would-demote eval from
 * cmp_hyp_credit_outcome().  Bumped per credit landing after the
 * per-hyp outcome counter is updated: would_promote when any of
 * (pc_wins, transition_wins, corpus_save_wins) is set, would_demote
 * when misses >= 8 and none of the win counters are set.  Pure
 * observation -- h->state stays CMP_HYP_STATE_OBSERVED.  Render
 * gated on any-delta so the section stays quiet until credit sites
 * start firing.
 */
void kcov_cmp_render_hyp_would_promote_demote_block(long elapsed __unused__)
{
	static const char * const kind_labels[CMP_HYP_KIND_NR] = {
		"exact", "range", "boundary", "bitmask",
		"enum_family", "alignment", "length",
		"foreign_value",
	};
	static unsigned long prev_hyp_would_promote_kind[CMP_HYP_KIND_NR];
	static unsigned long prev_hyp_would_demote_kind[CMP_HYP_KIND_NR];
	unsigned long cur_hyp_would_promote_kind[CMP_HYP_KIND_NR];
	unsigned long cur_hyp_would_demote_kind[CMP_HYP_KIND_NR];
	unsigned long any_delta = 0;
	unsigned int k;

	for (k = 0; k < CMP_HYP_KIND_NR; k++) {
		cur_hyp_would_promote_kind[k] = __atomic_load_n(
			&kcov_shm->cmp_hyp_results.cmp_hyp_would_promote_by_kind[k],
			__ATOMIC_RELAXED);
		cur_hyp_would_demote_kind[k] = __atomic_load_n(
			&kcov_shm->cmp_hyp_results.cmp_hyp_would_demote_by_kind[k],
			__ATOMIC_RELAXED);
		any_delta |=
			sat_sub_ul(cur_hyp_would_promote_kind[k], prev_hyp_would_promote_kind[k]) |
			sat_sub_ul(cur_hyp_would_demote_kind[k], prev_hyp_would_demote_kind[k]);
	}

	if (any_delta != 0) {
		stats_log_write("KCOV CMP hyp would-promote/demote shadow stats over last %lds:\n",
				elapsed);
		for (k = 0; k < CMP_HYP_KIND_NR; k++) {
			stats_log_write(
				"  cmp_hyp_would[%-13s] promote +%lu (total %lu)  demote +%lu (total %lu)\n",
				kind_labels[k],
				sat_sub_ul(cur_hyp_would_promote_kind[k], prev_hyp_would_promote_kind[k]),
				cur_hyp_would_promote_kind[k],
				sat_sub_ul(cur_hyp_would_demote_kind[k], prev_hyp_would_demote_kind[k]),
				cur_hyp_would_demote_kind[k]);
		}
	}

	for (k = 0; k < CMP_HYP_KIND_NR; k++) {
		prev_hyp_would_promote_kind[k] = cur_hyp_would_promote_kind[k];
		prev_hyp_would_demote_kind[k] = cur_hyp_would_demote_kind[k];
	}
}
