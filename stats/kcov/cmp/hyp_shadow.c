/*
 * Typed hypothesis SHADOW stats render lane.
 *
 * Owns the umbrella cmp_hyp shadow-stats block (flat lifecycle
 * counters delta-gated) plus the per-kind / consume / picker / state-
 * transition / outcome-partition breakouts it delegates to.  All
 * counters read RELAXED from kcov_shm->cmp_hyp_lifecycle and
 * kcov_shm->cmp_hyp_results; render is gated on any-delta so a quiet
 * run stays silent.  Called only from kcov_cmp_stats_periodic_dump()
 * in stats/kcov/cmp/periodic.c (the umbrella entry) or from within
 * this TU (the delegated breakouts).
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

/* Per-kind census: accepted (inserted_by_kind) vs dropped
 * at the per-kind sub-cap (kind_full_by_kind) vs dropped
 * at the total pool cap (pool_full_by_kind -- an attempted
 * hypothesis of this kind was rejected because the TOTAL
 * pool was full, NOT that this kind filled the pool).
 * Surfaces which kind dominates cmp_hyp_kind_full so the
 * CMP_HYP_PER_KIND cap can be tuned at the right kind, and
 * which kinds are most often the would-be insertion when
 * CMP_HYP_PER_SYSCALL is reached. */
void kcov_cmp_render_hyp_shadow_per_kind_census(void)
{
	static const char * const kind_labels[CMP_HYP_KIND_NR] = {
		"exact", "range", "boundary", "bitmask",
		"enum_family", "alignment", "length",
		"foreign_value",
	};
	static unsigned long prev_hyp_ins_kind[CMP_HYP_KIND_NR];
	static unsigned long prev_hyp_full_kind[CMP_HYP_KIND_NR];
	static unsigned long prev_hyp_pool_full_kind[CMP_HYP_KIND_NR];
	unsigned int k;

	for (k = 0; k < CMP_HYP_KIND_NR; k++) {
		unsigned long cur_ins = __atomic_load_n(
			&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_inserted_by_kind[k],
			__ATOMIC_RELAXED);
		unsigned long cur_full = __atomic_load_n(
			&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_kind_full_by_kind[k],
			__ATOMIC_RELAXED);
		unsigned long cur_pool_full = __atomic_load_n(
			&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_pool_full_by_kind[k],
			__ATOMIC_RELAXED);

		stats_log_write(
			"  cmp_hyp[%-13s] inserted +%lu (total %lu)  kind_full +%lu (total %lu)  pool_full +%lu (total %lu)\n",
			kind_labels[k],
			sat_sub_ul(cur_ins, prev_hyp_ins_kind[k]), cur_ins,
			sat_sub_ul(cur_full, prev_hyp_full_kind[k]), cur_full,
			sat_sub_ul(cur_pool_full, prev_hyp_pool_full_kind[k]),
			cur_pool_full);
		prev_hyp_ins_kind[k] = cur_ins;
		prev_hyp_full_kind[k] = cur_full;
		prev_hyp_pool_full_kind[k] = cur_pool_full;
	}
}
/* Per-kind census of typed-hypothesis consumes.  Bumped in
 * lock-step with the scalar cmp_hyp_consumed from
 * cmp_hyp_credit_consume(); sum across kinds equals
 * cmp_hyp_consumed modulo concurrent sampling.  Paired
 * with cmp_hyp_inserted_by_kind this shows, per kind, the
 * share of insertions the typed consumer is pulling. */
void kcov_cmp_render_hyp_shadow_consumes_census(void)
{
	static const char * const kind_labels[CMP_HYP_KIND_NR] = {
		"exact", "range", "boundary", "bitmask",
		"enum_family", "alignment", "length",
		"foreign_value",
	};
	static unsigned long prev_hyp_consumed_kind[CMP_HYP_KIND_NR];
	unsigned int k;

	for (k = 0; k < CMP_HYP_KIND_NR; k++) {
		unsigned long cur_cons = __atomic_load_n(
			&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_consumed_by_kind[k],
			__ATOMIC_RELAXED);

		stats_log_write(
			"  cmp_hyp[%-13s] consumed +%lu (total %lu)\n",
			kind_labels[k],
			sat_sub_ul(cur_cons, prev_hyp_consumed_kind[k]), cur_cons);
		prev_hyp_consumed_kind[k] = cur_cons;
	}
}
/* Picker decision census by h->state.  Bumped from
 * cmp_hyp_would_pick_locked() on every non-NULL
 * return: PROMOTED should dominate steady-state,
 * OBSERVED holds the cold-site share, DEMOTED
 * reflects the 1/CMP_HYP_DEMOTED_RETRY_DENOM
 * re-roll surfacing.  Companion counters:
 * skipped_retired tallies RETIRED slots walked past;
 * demoted_reroll_picked tallies fired re-rolls.
 * Together these are the directly-measurable proof
 * that the state-aware picker is doing what it
 * should. */
void kcov_cmp_render_hyp_shadow_picker_census(void)
{
	static const char * const state_labels[CMP_HYP_STATE_NR] = {
		"observed", "testing", "promoted",
		"demoted",  "retired",
	};
	static const char * const kind_labels[CMP_HYP_KIND_NR] = {
		"exact", "range", "boundary", "bitmask",
		"enum_family", "alignment", "length",
		"foreign_value",
	};
	static unsigned long prev_picked[CMP_HYP_STATE_NR];
	static unsigned long prev_skipped_retired_kind[CMP_HYP_KIND_NR];
	static unsigned long prev_demoted_reroll_kind[CMP_HYP_KIND_NR];
	unsigned int s, k;

	for (s = 0; s < CMP_HYP_STATE_NR; s++) {
		unsigned long cur = __atomic_load_n(
			&kcov_shm->cmp_hyp_results.cmp_hyp_picked_by_state[s],
			__ATOMIC_RELAXED);
		unsigned long delta = sat_sub_ul(cur, prev_picked[s]);

		prev_picked[s] = cur;
		if (delta == 0 && cur == 0)
			continue;
		stats_log_write(
			"  cmp_hyp_picked[%-8s] +%lu  (total %lu)\n",
			state_labels[s], delta, cur);
	}
	for (k = 0; k < CMP_HYP_KIND_NR; k++) {
		unsigned long cur = __atomic_load_n(
			&kcov_shm->cmp_hyp_results.cmp_hyp_skipped_retired_by_kind[k],
			__ATOMIC_RELAXED);
		unsigned long delta = sat_sub_ul(cur, prev_skipped_retired_kind[k]);

		prev_skipped_retired_kind[k] = cur;
		if (delta == 0 && cur == 0)
			continue;
		stats_log_write(
			"  cmp_hyp_skipped_retired[%-13s] +%lu  (total %lu)\n",
			kind_labels[k], delta, cur);
	}
	for (k = 0; k < CMP_HYP_KIND_NR; k++) {
		unsigned long cur = __atomic_load_n(
			&kcov_shm->cmp_hyp_results.cmp_hyp_demoted_reroll_picked_by_kind[k],
			__ATOMIC_RELAXED);
		unsigned long delta = sat_sub_ul(cur, prev_demoted_reroll_kind[k]);

		prev_demoted_reroll_kind[k] = cur;
		if (delta == 0 && cur == 0)
			continue;
		stats_log_write(
			"  cmp_hyp_demoted_reroll_picked[%-13s] +%lu  (total %lu)\n",
			kind_labels[k], delta, cur);
	}
}
/* h->state live transition census.  Bumped from
 * cmp_hyp_credit_outcome() once per state mutation.
 * Pairs with the would_promote_by_kind /
 * would_demote_by_kind shadow counters above: the
 * shadow counters report "would the live state
 * machine fire", the transitions matrix reports
 * "did it".  Only the active off-diagonal slots
 * print (zero rows suppressed). */
void kcov_cmp_render_hyp_shadow_state_transitions(void)
{
	static const char * const state_labels[CMP_HYP_STATE_NR] = {
		"observed", "testing", "promoted",
		"demoted",  "retired",
	};
	static unsigned long prev_trans[CMP_HYP_STATE_NR][CMP_HYP_STATE_NR];
	unsigned int from, to;

	for (from = 0; from < CMP_HYP_STATE_NR; from++) {
		for (to = 0; to < CMP_HYP_STATE_NR; to++) {
			unsigned long cur;
			unsigned long delta;

			if (from == to)
				continue;
			cur = __atomic_load_n(
				&kcov_shm->cmp_hyp_results.cmp_hyp_state_transitions[from][to],
				__ATOMIC_RELAXED);
			delta = sat_sub_ul(cur, prev_trans[from][to]);
			prev_trans[from][to] = cur;
			if (delta == 0 && cur == 0)
				continue;
			stats_log_write(
				"  cmp_hyp_state[%-8s -> %-8s] +%lu  (total %lu)\n",
				state_labels[from],
				state_labels[to],
				delta, cur);
		}
	}
}
/* Per-kind outcome partition.  Lock-step with the flat
 * cmp_hyp_pc_wins / _transition_wins / _misses /
 * _corpus_save / _destructive / _context_skip /
 * _cmp_novelty_wins above; the per-kind drilldown tells
 * which hypothesis kind is converting versus which kind
 * is consuming credit without conversion. */
void kcov_cmp_render_hyp_shadow_outcome_partition(void)
{
	static const char * const kind_labels[CMP_HYP_KIND_NR] = {
		"exact", "range", "boundary", "bitmask",
		"enum_family", "alignment", "length",
		"foreign_value",
	};
	static unsigned long prev_pc[CMP_HYP_KIND_NR];
	static unsigned long prev_tr[CMP_HYP_KIND_NR];
	static unsigned long prev_ms[CMP_HYP_KIND_NR];
	static unsigned long prev_cs[CMP_HYP_KIND_NR];
	static unsigned long prev_ds[CMP_HYP_KIND_NR];
	static unsigned long prev_ks[CMP_HYP_KIND_NR];
	static unsigned long prev_nv[CMP_HYP_KIND_NR];
	unsigned int k;

	for (k = 0; k < CMP_HYP_KIND_NR; k++) {
		unsigned long pc = __atomic_load_n(
			&kcov_shm->cmp_hyp_results.cmp_hyp_pc_wins_by_kind[k], __ATOMIC_RELAXED);
		unsigned long tr = __atomic_load_n(
			&kcov_shm->cmp_hyp_results.cmp_hyp_transition_wins_by_kind[k], __ATOMIC_RELAXED);
		unsigned long ms = __atomic_load_n(
			&kcov_shm->cmp_hyp_results.cmp_hyp_misses_by_kind[k], __ATOMIC_RELAXED);
		unsigned long cs = __atomic_load_n(
			&kcov_shm->cmp_hyp_results.cmp_hyp_corpus_save_by_kind[k], __ATOMIC_RELAXED);
		unsigned long ds = __atomic_load_n(
			&kcov_shm->cmp_hyp_results.cmp_hyp_destructive_by_kind[k], __ATOMIC_RELAXED);
		unsigned long ks = __atomic_load_n(
			&kcov_shm->cmp_hyp_results.cmp_hyp_context_skip_by_kind[k], __ATOMIC_RELAXED);
		unsigned long nv = __atomic_load_n(
			&kcov_shm->cmp_hyp_results.cmp_hyp_cmp_novelty_wins_by_kind[k], __ATOMIC_RELAXED);

		stats_log_write(
			"  cmp_hyp[%-13s] outcome  pc +%lu  tr +%lu  ms +%lu  cs +%lu  ds +%lu  ks +%lu  nv +%lu\n",
			kind_labels[k],
			sat_sub_ul(pc, prev_pc[k]), sat_sub_ul(tr, prev_tr[k]),
			sat_sub_ul(ms, prev_ms[k]), sat_sub_ul(cs, prev_cs[k]),
			sat_sub_ul(ds, prev_ds[k]), sat_sub_ul(ks, prev_ks[k]),
			sat_sub_ul(nv, prev_nv[k]));
		prev_pc[k] = pc;
		prev_tr[k] = tr;
		prev_ms[k] = ms;
		prev_cs[k] = cs;
		prev_ds[k] = ds;
		prev_ks[k] = ks;
		prev_nv[k] = nv;
	}
}
void kcov_cmp_render_hyp_shadow_stats_block(long elapsed)
{
	static unsigned long prev_hyp_observations;
	static unsigned long prev_hyp_inserted;
	static unsigned long prev_hyp_pool_full;
	static unsigned long prev_hyp_pool_overflow;
	static unsigned long prev_hyp_kind_full;
	static unsigned long prev_hyp_consumed;
	static unsigned long prev_hyp_pc_wins;
	static unsigned long prev_hyp_transition_wins;
	static unsigned long prev_hyp_cmp_novelty_wins;
	static unsigned long prev_hyp_misses;
	static unsigned long prev_hyp_disabled_skips;
	static unsigned long prev_hyp_corpus_save;
	static unsigned long prev_hyp_destructive;
	static unsigned long prev_hyp_context_skip;
	unsigned long cur_hyp_observations =
		__atomic_load_n(&kcov_shm->hyp_flat.cmp_hyp_observations, __ATOMIC_RELAXED);
	unsigned long cur_hyp_inserted =
		__atomic_load_n(&kcov_shm->hyp_flat.cmp_hyp_inserted, __ATOMIC_RELAXED);
	unsigned long cur_hyp_pool_full =
		__atomic_load_n(&kcov_shm->hyp_flat.cmp_hyp_pool_full, __ATOMIC_RELAXED);
	unsigned long cur_hyp_pool_overflow =
		__atomic_load_n(&kcov_shm->cmp_hyp_results.cmp_hyp_pool_overflow, __ATOMIC_RELAXED);
	unsigned long cur_hyp_kind_full =
		__atomic_load_n(&kcov_shm->hyp_flat.cmp_hyp_kind_full, __ATOMIC_RELAXED);
	unsigned long cur_hyp_consumed =
		__atomic_load_n(&kcov_shm->hyp_flat.cmp_hyp_consumed, __ATOMIC_RELAXED);
	unsigned long cur_hyp_pc_wins =
		__atomic_load_n(&kcov_shm->hyp_flat.cmp_hyp_pc_wins, __ATOMIC_RELAXED);
	unsigned long cur_hyp_transition_wins =
		__atomic_load_n(&kcov_shm->hyp_flat.cmp_hyp_transition_wins, __ATOMIC_RELAXED);
	unsigned long cur_hyp_cmp_novelty_wins =
		__atomic_load_n(&kcov_shm->hyp_flat.cmp_hyp_cmp_novelty_wins, __ATOMIC_RELAXED);
	unsigned long cur_hyp_misses =
		__atomic_load_n(&kcov_shm->hyp_flat.cmp_hyp_misses, __ATOMIC_RELAXED);
	unsigned long cur_hyp_disabled_skips =
		__atomic_load_n(&kcov_shm->hyp_flat.cmp_hyp_disabled_skips, __ATOMIC_RELAXED);
	unsigned long cur_hyp_corpus_save =
		__atomic_load_n(&kcov_shm->hyp_flat.cmp_hyp_corpus_save, __ATOMIC_RELAXED);
	unsigned long cur_hyp_destructive =
		__atomic_load_n(&kcov_shm->hyp_flat.cmp_hyp_destructive, __ATOMIC_RELAXED);
	unsigned long cur_hyp_context_skip =
		__atomic_load_n(&kcov_shm->hyp_flat.cmp_hyp_context_skip, __ATOMIC_RELAXED);
	unsigned long delta_hyp_observations = sat_sub_ul(cur_hyp_observations, prev_hyp_observations);
	unsigned long delta_hyp_inserted = sat_sub_ul(cur_hyp_inserted, prev_hyp_inserted);
	unsigned long delta_hyp_pool_full = sat_sub_ul(cur_hyp_pool_full, prev_hyp_pool_full);
	unsigned long delta_hyp_pool_overflow = sat_sub_ul(cur_hyp_pool_overflow, prev_hyp_pool_overflow);
	unsigned long delta_hyp_kind_full = sat_sub_ul(cur_hyp_kind_full, prev_hyp_kind_full);
	unsigned long delta_hyp_consumed = sat_sub_ul(cur_hyp_consumed, prev_hyp_consumed);
	unsigned long delta_hyp_pc_wins = sat_sub_ul(cur_hyp_pc_wins, prev_hyp_pc_wins);
	unsigned long delta_hyp_transition_wins = sat_sub_ul(cur_hyp_transition_wins, prev_hyp_transition_wins);
	unsigned long delta_hyp_cmp_novelty_wins = sat_sub_ul(cur_hyp_cmp_novelty_wins, prev_hyp_cmp_novelty_wins);
	unsigned long delta_hyp_misses = sat_sub_ul(cur_hyp_misses, prev_hyp_misses);
	unsigned long delta_hyp_disabled_skips = sat_sub_ul(cur_hyp_disabled_skips, prev_hyp_disabled_skips);
	unsigned long delta_hyp_corpus_save = sat_sub_ul(cur_hyp_corpus_save, prev_hyp_corpus_save);
	unsigned long delta_hyp_destructive = sat_sub_ul(cur_hyp_destructive, prev_hyp_destructive);
	unsigned long delta_hyp_context_skip = sat_sub_ul(cur_hyp_context_skip, prev_hyp_context_skip);

	if ((delta_hyp_observations | delta_hyp_inserted | delta_hyp_pool_full |
	     delta_hyp_pool_overflow | delta_hyp_kind_full |
	     delta_hyp_consumed | delta_hyp_pc_wins |
	     delta_hyp_transition_wins | delta_hyp_cmp_novelty_wins |
	     delta_hyp_misses | delta_hyp_disabled_skips |
	     delta_hyp_corpus_save | delta_hyp_destructive |
	     delta_hyp_context_skip) != 0) {
		stats_log_write("KCOV CMP hyp shadow stats over last %lds:\n", elapsed);
		stats_log_write("  %-32s +%lu  (total %lu)\n",
				"cmp_hyp_observations", delta_hyp_observations, cur_hyp_observations);
		stats_log_write("  %-32s +%lu  (total %lu)\n",
				"cmp_hyp_inserted", delta_hyp_inserted, cur_hyp_inserted);
		stats_log_write("  %-32s +%lu  (total %lu)\n",
				"cmp_hyp_pool_full", delta_hyp_pool_full, cur_hyp_pool_full);
		stats_log_write("  %-32s +%lu  (total %lu)\n",
				"cmp_hyp_pool_overflow",
				delta_hyp_pool_overflow, cur_hyp_pool_overflow);
		stats_log_write("  %-32s +%lu  (total %lu)\n",
				"cmp_hyp_kind_full", delta_hyp_kind_full, cur_hyp_kind_full);
		stats_log_write("  %-32s +%lu  (total %lu)\n",
				"cmp_hyp_consumed", delta_hyp_consumed, cur_hyp_consumed);
		stats_log_write("  %-32s +%lu  (total %lu)\n",
				"cmp_hyp_pc_wins", delta_hyp_pc_wins, cur_hyp_pc_wins);
		stats_log_write("  %-32s +%lu  (total %lu)\n",
				"cmp_hyp_transition_wins",
				delta_hyp_transition_wins, cur_hyp_transition_wins);
		stats_log_write("  %-32s +%lu  (total %lu)\n",
				"cmp_hyp_cmp_novelty_wins",
				delta_hyp_cmp_novelty_wins, cur_hyp_cmp_novelty_wins);
		stats_log_write("  %-32s +%lu  (total %lu)\n",
				"cmp_hyp_misses", delta_hyp_misses, cur_hyp_misses);
		stats_log_write("  %-32s +%lu  (total %lu)\n",
				"cmp_hyp_disabled_skips",
				delta_hyp_disabled_skips, cur_hyp_disabled_skips);
		stats_log_write("  %-32s +%lu  (total %lu)\n",
				"cmp_hyp_corpus_save",
				delta_hyp_corpus_save, cur_hyp_corpus_save);
		stats_log_write("  %-32s +%lu  (total %lu)\n",
				"cmp_hyp_destructive",
				delta_hyp_destructive, cur_hyp_destructive);
		stats_log_write("  %-32s +%lu  (total %lu)\n",
				"cmp_hyp_context_skip",
				delta_hyp_context_skip, cur_hyp_context_skip);

		kcov_cmp_render_hyp_shadow_per_kind_census();
		kcov_cmp_render_hyp_shadow_consumes_census();
		kcov_cmp_render_hyp_shadow_picker_census();
		kcov_cmp_render_hyp_shadow_state_transitions();
		kcov_cmp_render_hyp_shadow_outcome_partition();
	}

	prev_hyp_observations = cur_hyp_observations;
	prev_hyp_inserted = cur_hyp_inserted;
	prev_hyp_pool_full = cur_hyp_pool_full;
	prev_hyp_pool_overflow = cur_hyp_pool_overflow;
	prev_hyp_kind_full = cur_hyp_kind_full;
	prev_hyp_consumed = cur_hyp_consumed;
	prev_hyp_pc_wins = cur_hyp_pc_wins;
	prev_hyp_transition_wins = cur_hyp_transition_wins;
	prev_hyp_cmp_novelty_wins = cur_hyp_cmp_novelty_wins;
	prev_hyp_misses = cur_hyp_misses;
	prev_hyp_disabled_skips = cur_hyp_disabled_skips;
	prev_hyp_corpus_save = cur_hyp_corpus_save;
	prev_hyp_destructive = cur_hyp_destructive;
	prev_hyp_context_skip = cur_hyp_context_skip;
}
