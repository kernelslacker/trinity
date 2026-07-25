/*
 * Typed hypothesis SHADOW outcome-histogram render lane.
 *
 * Owns the two per-outcome histograms that are lock-step with a
 * per-hypothesis credit path: the 8-band score-bucket census fed by
 * cmp_hyp_credit_outcome() and the per-probe-class emission census
 * fed at the out_bump label in cmp_hyp_derive_value() (cmp_hints.c).
 * Both read RELAXED from kcov_shm->cmp_hyp_results and are any-delta
 * gated so the section stays quiet until credit / derive sites
 * fire.  Called only from kcov_cmp_stats_periodic_dump() in
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
 * SHADOW 8-band histogram of the per-hypothesis score_bucket value
 * computed in cmp_hyp_credit_outcome().  Bumped lock-step with the
 * h->score_bucket store, using the bucket value just written.
 * Bands: 0 idle, 1 penalty-only, 2 heavy net-neg, 3 slight net-neg,
 * 4 break-even, 5 small net-pos, 6 moderate net-pos, 7 strong net-pos.
 * Render gated on any-delta so the section stays quiet until credit
 * sites start firing.
 */
void kcov_cmp_render_hyp_score_bucket_block(long elapsed __unused__)
{
	static const char * const bucket_labels[8] = {
		"idle",
		"penalty_only",
		"heavy_net_neg",
		"slight_net_neg",
		"break_even",
		"small_net_pos",
		"moderate_net_pos",
		"strong_net_pos",
	};
	static unsigned long prev_hyp_score_bucket[8];
	unsigned long cur_hyp_score_bucket[8];
	unsigned long any_delta = 0;
	unsigned int k;

	for (k = 0; k < 8; k++) {
		cur_hyp_score_bucket[k] = __atomic_load_n(
			&kcov_shm->cmp_hyp_results.cmp_hyp_score_bucket_census[k],
			__ATOMIC_RELAXED);
		any_delta |= sat_sub_ul(cur_hyp_score_bucket[k], prev_hyp_score_bucket[k]);
	}

	if (any_delta != 0) {
		stats_log_write("KCOV CMP hyp score-bucket distribution (bands 0..7) over last %lds:\n",
				elapsed);
		for (k = 0; k < 8; k++) {
			stats_log_write(
				"  cmp_hyp_score_bucket[%u %-16s] +%lu  (total %lu)\n",
				k, bucket_labels[k],
				sat_sub_ul(cur_hyp_score_bucket[k], prev_hyp_score_bucket[k]),
				cur_hyp_score_bucket[k]);
		}
	}

	for (k = 0; k < 8; k++)
		prev_hyp_score_bucket[k] = cur_hyp_score_bucket[k];
}
/*
 * SHADOW per-probe-class histogram of cmp_hyp_derive_value()
 * emissions.  Bumped lock-step (RELAXED) at the out_bump label in
 * cmp_hints.c using the class the derivation just produced; *out is
 * unchanged from the pre-census ladder, so the live inject arm
 * receives a byte-identical value.  Render gated on any-delta so
 * the section stays quiet until the derivation path fires.  The
 * bound CMP_HYP_PROBE_CLASS_NR matches the on-shm array (see the
 * enum and struct kcov_shared in include/kcov.h); using designated
 * initialisers on class_labels[] keeps every label pinned to its
 * enum name so a future re-order of the enum cannot silently
 * mislabel a bucket.  Counters are monotonic on the producer side
 * but the snapshot / prev pair is loaded across separate RELAXED
 * reads; guard the delta with cur >= prev so a reordered
 * observation cannot underflow into a multi-GB delta print.
 */
void kcov_cmp_render_hyp_probe_class_hist_block(long elapsed __unused__)
{
	static const char * const class_labels[CMP_HYP_PROBE_CLASS_NR] = {
		[CMP_HYP_PROBE_CLASS_EXACT_EXEMPLAR]     = "exact_exemplar",
		[CMP_HYP_PROBE_CLASS_ENUM_EXEMPLAR]      = "enum_exemplar",
		[CMP_HYP_PROBE_CLASS_ENUM_LO]            = "enum_lo",
		[CMP_HYP_PROBE_CLASS_ENUM_HI]            = "enum_hi",
		[CMP_HYP_PROBE_CLASS_BITMASK_SINGLE_BIT] = "bitmask_single_bit",
		[CMP_HYP_PROBE_CLASS_EXEMPLAR_FALLBACK]  = "exemplar_fallback",
		[CMP_HYP_PROBE_CLASS_RANGE_LO]           = "range_lo",
		[CMP_HYP_PROBE_CLASS_RANGE_HI]           = "range_hi",
		[CMP_HYP_PROBE_CLASS_RANGE_MIDPOINT]     = "range_midpoint",
		[CMP_HYP_PROBE_CLASS_BOUNDARY_MINUS1]    = "boundary_minus1",
		[CMP_HYP_PROBE_CLASS_BOUNDARY_PLUS1]     = "boundary_plus1",
		[CMP_HYP_PROBE_CLASS_BOUNDARY_EXACT]     = "boundary_exact",
		[CMP_HYP_PROBE_CLASS_BOUNDARY_SWEEP]     = "boundary_sweep",
	};
	static unsigned long prev_hyp_probe_class[CMP_HYP_PROBE_CLASS_NR];
	unsigned long cur_hyp_probe_class[CMP_HYP_PROBE_CLASS_NR];
	unsigned long any_delta = 0;
	unsigned int k;

	for (k = 0; k < CMP_HYP_PROBE_CLASS_NR; k++) {
		cur_hyp_probe_class[k] = __atomic_load_n(
			&kcov_shm->cmp_hyp_results.cmp_hyp_probe_class_hist[k],
			__ATOMIC_RELAXED);
		if (cur_hyp_probe_class[k] >= prev_hyp_probe_class[k])
			any_delta |= cur_hyp_probe_class[k] -
				     prev_hyp_probe_class[k];
	}

	if (any_delta != 0) {
		stats_log_write("KCOV CMP hyp probe-class histogram over last %lds:\n",
				elapsed);
		for (k = 0; k < CMP_HYP_PROBE_CLASS_NR; k++) {
			unsigned long delta = 0;

			if (cur_hyp_probe_class[k] >= prev_hyp_probe_class[k])
				delta = cur_hyp_probe_class[k] -
					prev_hyp_probe_class[k];
			stats_log_write(
				"  cmp_hyp_probe_class[%2u %-18s] +%lu  (total %lu)\n",
				k, class_labels[k],
				delta,
				cur_hyp_probe_class[k]);
		}
	}

	for (k = 0; k < CMP_HYP_PROBE_CLASS_NR; k++)
		prev_hyp_probe_class[k] = cur_hyp_probe_class[k];
}
