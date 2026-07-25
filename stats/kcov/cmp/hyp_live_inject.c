/*
 * Typed hypothesis LIVE inject render lane.
 *
 * Owns the fleet-level view of the conservative live-inject arm from
 * cmp_hints_try_get_ex(): the (gate_passed, injected, no_pick) triad
 * with its per-kind partition, the per-reason gate-close breakdown
 * from cmp_hyp_try_live_inject(), and the BOUNDARY-arm scorecard
 * that reads the boundary-kind shadow counters together in one
 * render.  All read RELAXED from kcov_shm->cmp_hyp_lifecycle and
 * kcov_shm->cmp_hyp_results; the live-inject umbrella renders every
 * window (no delta gate) so "fired with zero wins" is
 * distinguishable from "never fired", while the reasons block and
 * BOUNDARY scorecard stay any-delta gated.  Called only from
 * kcov_cmp_stats_periodic_dump() in stats/kcov/cmp/periodic.c.
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
 * LIVE typed-hypothesis inject arm telemetry.  Fleet-level view of
 * the conservative inject arm rate from cmp_hints_try_get_ex():
 * how often the gate passed, how often the resolver produced a
 * derived value, and the per-kind partition of those produced
 * values.  The pair (gate_passed, injected) separates "the arm
 * fired and there was nothing in the typed store" from "the arm
 * fired and substituted a derived value", which is what bounds
 * the achievable conversion ceiling; the explicit no_pick gap
 * (gate_passed - injected) names that empty-site case directly.
 * Rendered every window with no delta gate so a quiet arm reads
 * as zeros rather than silence -- the validation question is "did
 * a typed-derived pick lift cmp_hyp_pc_wins" and that requires
 * being able to tell "fired with zero wins" from "never fired".
 * Conversion outcomes (pc_wins/misses) are credited only to
 * live-arm entries and render in the cmp_hyp shadow stats block
 * above; not duplicated here.
 */
void kcov_cmp_render_hyp_live_inject_block(long elapsed __unused__)
{
	static const char * const kind_labels[CMP_HYP_KIND_NR] = {
		"exact", "range", "boundary", "bitmask",
		"enum_family", "alignment", "length",
		"foreign_value",
	};
	static unsigned long prev_hyp_live_injected;
	static unsigned long prev_hyp_live_gate_passed;
	static unsigned long prev_hyp_live_injected_kind[CMP_HYP_KIND_NR];
	/*
	 * Load injected before gate_passed.  cmp_hints_try_get_ex()
	 * bumps gate_passed first and only later bumps injected on a
	 * successful pick+derive, so producer-side gate_passed >=
	 * injected always.  Reading injected first means a paired
	 * (gate_passed, injected) increment in flight between the two
	 * loads gets snapshotted as a gate_passed-only bump (over-
	 * counting no_pick by 1) rather than as an injected-only bump
	 * (which would make cur gap go negative under RELAXED).
	 */
	unsigned long cur_hyp_live_injected = __atomic_load_n(
		&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_live_injected, __ATOMIC_RELAXED);
	unsigned long cur_hyp_live_gate_passed = __atomic_load_n(
		&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_live_inject_gate_passed,
		__ATOMIC_RELAXED);
	unsigned long cur_hyp_live_injected_kind[CMP_HYP_KIND_NR];
	unsigned long delta_hyp_live_injected =
		sat_sub_ul(cur_hyp_live_injected, prev_hyp_live_injected);
	unsigned long delta_hyp_live_gate_passed =
		sat_sub_ul(cur_hyp_live_gate_passed, prev_hyp_live_gate_passed);
	/*
	 * gate_passed and injected are loaded separately with RELAXED
	 * ordering.  injected-first keeps the gap non-negative for the
	 * common steady state, but once the live-inject arm fires a
	 * sample can observe injected > gate_passed (the gate counter
	 * is bumped slightly after the inject counter on the producer
	 * side).  An unguarded unsigned subtraction wraps to ~ULONG_MAX
	 * in the rendered total; clamp.
	 */
	unsigned long cur_hyp_live_inject_no_pick =
		(cur_hyp_live_gate_passed >= cur_hyp_live_injected)
			? (cur_hyp_live_gate_passed - cur_hyp_live_injected)
			: 0;
	/*
	 * delta_gate_passed - delta_injected can wrap when the over-
	 * count drift in the previous sample exceeded the over-count
	 * drift in this sample (cur gap < prev gap), even though the
	 * underlying no_pick total is monotone non-decreasing.  Clamp.
	 */
	unsigned long delta_hyp_live_inject_no_pick =
		(delta_hyp_live_gate_passed >= delta_hyp_live_injected)
			? (delta_hyp_live_gate_passed - delta_hyp_live_injected)
			: 0;
	unsigned int k;

	for (k = 0; k < CMP_HYP_KIND_NR; k++) {
		cur_hyp_live_injected_kind[k] = __atomic_load_n(
			&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_live_injected_by_kind[k],
			__ATOMIC_RELAXED);
	}

	stats_log_write("KCOV CMP hyp live inject stats over last %lds:\n",
			elapsed);
	stats_log_write("  %-32s +%lu  (total %lu)\n",
			"cmp_hyp_live_inject_gate_passed",
			delta_hyp_live_gate_passed,
			cur_hyp_live_gate_passed);
	stats_log_write("  %-32s +%lu  (total %lu)\n",
			"cmp_hyp_live_injected",
			delta_hyp_live_injected,
			cur_hyp_live_injected);
	stats_log_write("  %-32s +%lu  (total %lu)\n",
			"cmp_hyp_live_inject_no_pick",
			delta_hyp_live_inject_no_pick,
			cur_hyp_live_inject_no_pick);
	for (k = 0; k < CMP_HYP_KIND_NR; k++) {
		stats_log_write(
			"  cmp_hyp_live_inject[%-13s] +%lu (total %lu)\n",
			kind_labels[k],
			sat_sub_ul(cur_hyp_live_injected_kind[k],
				   prev_hyp_live_injected_kind[k]),
			cur_hyp_live_injected_kind[k]);
	}
	stats_log_write(
		"  (conversion outcomes: see cmp_hyp_pc_wins / cmp_hyp_misses in cmp_hyp shadow stats above)\n");

	prev_hyp_live_injected = cur_hyp_live_injected;
	prev_hyp_live_gate_passed = cur_hyp_live_gate_passed;
	for (k = 0; k < CMP_HYP_KIND_NR; k++)
		prev_hyp_live_injected_kind[k] = cur_hyp_live_injected_kind[k];
}
/*
 * Per-reason gate-close partition for the LIVE inject path.  Each
 * slot names a distinct early-return / reject site so a
 * gate_passed=0 diagnosis can be attributed to a specific gate
 * rather than stay opaque.  Pure observability -- mirrors the
 * counters bumped from cmp_hyp_try_live_inject() and its
 * accept-gated caller in cmp_hints.c.  Section stays quiet until
 * something on the inject path actually fires.
 */
void kcov_cmp_render_hyp_live_inject_reasons_block(long elapsed __unused__)
{
	static const char * const reason_labels[CMP_HYP_LIVE_INJECT_REASON_NR] = {
		[CMP_HYP_LIVE_INJECT_REASON_NOT_PLATEAU]     = "not_plateau",
		[CMP_HYP_LIVE_INJECT_REASON_DICE_MISS]       = "dice_miss",
		[CMP_HYP_LIVE_INJECT_REASON_NO_MATCH]        = "no_match",
		[CMP_HYP_LIVE_INJECT_REASON_DERIVE_FAIL]     = "derive_fail",
		[CMP_HYP_LIVE_INJECT_REASON_ACCEPT_REJECT]   = "accept_reject",
		[CMP_HYP_LIVE_INJECT_REASON_BOOTSTRAP]       = "bootstrap",
		[CMP_HYP_LIVE_INJECT_REASON_PROMOTED_BYPASS] = "promoted_bypass",
	};
	static unsigned long prev_hyp_live_inject_reason[CMP_HYP_LIVE_INJECT_REASON_NR];
	unsigned long cur_hyp_live_inject_reason[CMP_HYP_LIVE_INJECT_REASON_NR];
	unsigned long any_delta = 0;
	unsigned int r;

	for (r = 0; r < CMP_HYP_LIVE_INJECT_REASON_NR; r++) {
		cur_hyp_live_inject_reason[r] = __atomic_load_n(
			&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_live_inject_reason[r],
			__ATOMIC_RELAXED);
		any_delta |=
			sat_sub_ul(cur_hyp_live_inject_reason[r],
				   prev_hyp_live_inject_reason[r]);
	}

	if (any_delta != 0) {
		stats_log_write("KCOV CMP live-inject gate-close reasons over last %lds:\n",
				elapsed);
		for (r = 0; r < CMP_HYP_LIVE_INJECT_REASON_NR; r++) {
			stats_log_write(
				"  cmp_hyp_live_inject_reason[%-13s] +%lu (total %lu)\n",
				reason_labels[r],
				sat_sub_ul(cur_hyp_live_inject_reason[r],
					   prev_hyp_live_inject_reason[r]),
				cur_hyp_live_inject_reason[r]);
		}
	}

	for (r = 0; r < CMP_HYP_LIVE_INJECT_REASON_NR; r++)
		prev_hyp_live_inject_reason[r] = cur_hyp_live_inject_reason[r];
}
/*
 * BOUNDARY-arm scorecard.  Pulls the existing boundary-kind
 * shadow counters into one render so the operator can read the
 * inserted-vs-consumed ratio at a glance: how often a BOUNDARY
 * hypothesis was created, how often one was available at a
 * served pick site, how often the value-keyed would-pick ladder
 * picked it (expected near zero -- EXACT outranks), how often
 * the live inject arm derived from it, and how often a credited
 * PC / transition resolved to BOUNDARY via the |v - exemplar|
 * <= 2 window.  Gated on any-delta so a quiet run reads as
 * silence, matching the sibling cmp_hyp shadow blocks above.
 */
void kcov_cmp_render_hyp_boundary_scorecard_block(long elapsed __unused__)
{
	static unsigned long prev_b_inserted;
	static unsigned long prev_b_candidate_available;
	static unsigned long prev_b_credit_window_hits;
	static unsigned long prev_b_would_pick;
	static unsigned long prev_b_would_miss;
	static unsigned long prev_b_live_injected;
	static unsigned long prev_b_consumed;
	unsigned long cur_b_inserted = __atomic_load_n(
		&kcov_shm->cmp_hyp_results.cmp_hyp_boundary_inserted, __ATOMIC_RELAXED);
	unsigned long cur_b_candidate_available = __atomic_load_n(
		&kcov_shm->cmp_hyp_results.cmp_hyp_boundary_candidate_available,
		__ATOMIC_RELAXED);
	unsigned long cur_b_credit_window_hits = __atomic_load_n(
		&kcov_shm->cmp_hyp_results.cmp_hyp_boundary_credit_window_hits,
		__ATOMIC_RELAXED);
	unsigned long cur_b_would_pick = __atomic_load_n(
		&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_would_pick_by_kind[CMP_HYP_BOUNDARY],
		__ATOMIC_RELAXED);
	unsigned long cur_b_would_miss = __atomic_load_n(
		&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_would_miss_by_kind[CMP_HYP_BOUNDARY],
		__ATOMIC_RELAXED);
	unsigned long cur_b_live_injected = __atomic_load_n(
		&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_live_injected_by_kind[CMP_HYP_BOUNDARY],
		__ATOMIC_RELAXED);
	unsigned long cur_b_consumed = __atomic_load_n(
		&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_consumed_by_kind[CMP_HYP_BOUNDARY],
		__ATOMIC_RELAXED);
	unsigned long any_delta =
		sat_sub_ul(cur_b_inserted, prev_b_inserted) |
		sat_sub_ul(cur_b_candidate_available, prev_b_candidate_available) |
		sat_sub_ul(cur_b_credit_window_hits, prev_b_credit_window_hits) |
		sat_sub_ul(cur_b_would_pick, prev_b_would_pick) |
		sat_sub_ul(cur_b_would_miss, prev_b_would_miss) |
		sat_sub_ul(cur_b_live_injected, prev_b_live_injected) |
		sat_sub_ul(cur_b_consumed, prev_b_consumed);

	if (any_delta != 0) {
		stats_log_write("KCOV CMP hyp BOUNDARY-arm scorecard over last %lds:\n",
				elapsed);
		stats_log_write("  %-40s +%lu  (total %lu)\n",
				"cmp_hyp_boundary_inserted",
				sat_sub_ul(cur_b_inserted, prev_b_inserted),
				cur_b_inserted);
		stats_log_write("  %-40s +%lu  (total %lu)\n",
				"cmp_hyp_boundary_candidate_available",
				sat_sub_ul(cur_b_candidate_available, prev_b_candidate_available),
				cur_b_candidate_available);
		stats_log_write("  %-40s +%lu  (total %lu)\n",
				"cmp_hyp_would_pick_by_kind[boundary]",
				sat_sub_ul(cur_b_would_pick, prev_b_would_pick),
				cur_b_would_pick);
		stats_log_write("  %-40s +%lu  (total %lu)\n",
				"cmp_hyp_would_miss_by_kind[boundary]",
				sat_sub_ul(cur_b_would_miss, prev_b_would_miss),
				cur_b_would_miss);
		stats_log_write("  %-40s +%lu  (total %lu)\n",
				"cmp_hyp_live_injected_by_kind[boundary]",
				sat_sub_ul(cur_b_live_injected, prev_b_live_injected),
				cur_b_live_injected);
		stats_log_write("  %-40s +%lu  (total %lu)\n",
				"cmp_hyp_consumed_by_kind[boundary]",
				sat_sub_ul(cur_b_consumed, prev_b_consumed),
				cur_b_consumed);
		stats_log_write("  %-40s +%lu  (total %lu)\n",
				"cmp_hyp_boundary_credit_window_hits",
				sat_sub_ul(cur_b_credit_window_hits, prev_b_credit_window_hits),
				cur_b_credit_window_hits);
	}

	prev_b_inserted = cur_b_inserted;
	prev_b_candidate_available = cur_b_candidate_available;
	prev_b_credit_window_hits = cur_b_credit_window_hits;
	prev_b_would_pick = cur_b_would_pick;
	prev_b_would_miss = cur_b_would_miss;
	prev_b_live_injected = cur_b_live_injected;
	prev_b_consumed = cur_b_consumed;
}
