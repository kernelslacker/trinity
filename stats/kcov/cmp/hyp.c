/*
 * Typed hypothesis periodic reporting.
 *
 * Owns the typed cmp-hypothesis renderer family: saturation gauge,
 * per-kind / consume / picker census, state transitions, outcome
 * partition, SHADOW stats block, would-pick / would-promote / would-
 * demote blocks, live inject block and its reason breakdown, boundary
 * scorecard, per-hypothesis aggregates, score-bucket histogram, and
 * probe-class histogram.  All are called only from
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
 * Per-syscall typed-hypothesis store SATURATION: top-N (nr, do32) pools
 * ranked by pool->count, with the per_kind_count[] breakdown so the
 * (nr, kind) cells that crowd the store are visible.
 *
 * pool->count and pool->per_kind_count[] have no kcov_shm scalar twin:
 * the cumulative cmp_hyp_kind_full / inserted_by_kind producer counters
 * never surface the live occupancy, so an exhausted (nr, kind) cell is
 * invisible from the cumulative producer view alone.
 *
 * Read-side only: relaxed loads against lockless observe / scrub bumps,
 * count clamped to CMP_HYP_PER_SYSCALL and per_kind to CMP_HYP_PER_KIND
 * so a torn load cannot drive a downstream divide or fixed-width column
 * past its cap.  Gated on any-occupancy so an empty store stays quiet.
 */
void kcov_cmp_hyp_saturation_block_render(long elapsed __unused__)
{
#define KCOV_CMP_HYP_SAT_TOPN	32
	static const char * const kind_labels[CMP_HYP_KIND_NR] = {
		"exact", "range", "boundary", "bitmask",
		"enum_family", "alignment", "length",
		"foreign_value",
	};
	struct sat_row {
		unsigned int nr;
		unsigned int do32;
		unsigned int count;
		unsigned int per_kind[CMP_HYP_KIND_NR];
	};
	struct sat_row top[KCOV_CMP_HYP_SAT_TOPN];
	unsigned int top_count = 0;
	unsigned int nr_scan[2];
	unsigned int nr_i, do32_i, k, j;
	unsigned long occupied_pools = 0;
	unsigned long total_entries = 0;

	if (cmp_hints_shm == NULL)
		return;

	nr_scan[0] = biarch ? max_nr_64bit_syscalls : max_nr_syscalls;
	nr_scan[1] = biarch ? max_nr_32bit_syscalls : 0;
	for (do32_i = 0; do32_i < 2; do32_i++)
		if (nr_scan[do32_i] > MAX_NR_SYSCALL)
			nr_scan[do32_i] = MAX_NR_SYSCALL;

	for (do32_i = 0; do32_i < 2; do32_i++) {
		for (nr_i = 0; nr_i < nr_scan[do32_i]; nr_i++) {
			struct cmp_hyp_pool *p =
				&cmp_hints_shm->hyp_pools[nr_i][do32_i];
			unsigned int count = __atomic_load_n(
				&p->count, __ATOMIC_RELAXED);
			struct sat_row cand;

			if (count == 0)
				continue;
			if (count > CMP_HYP_PER_SYSCALL)
				count = CMP_HYP_PER_SYSCALL;

			occupied_pools++;
			total_entries += count;

			cand.nr = nr_i;
			cand.do32 = do32_i;
			cand.count = count;
			for (k = 0; k < CMP_HYP_KIND_NR; k++) {
				unsigned int pk = __atomic_load_n(
					&p->per_kind_count[k], __ATOMIC_RELAXED);

				if (pk > CMP_HYP_PER_KIND)
					pk = CMP_HYP_PER_KIND;
				cand.per_kind[k] = pk;
			}

			for (j = top_count;
			     j > 0 && count > top[j - 1].count;
			     j--) {
				if (j < KCOV_CMP_HYP_SAT_TOPN)
					top[j] = top[j - 1];
			}
			if (j < KCOV_CMP_HYP_SAT_TOPN) {
				top[j] = cand;
				if (top_count < KCOV_CMP_HYP_SAT_TOPN)
					top_count++;
			}
		}
	}

	if (top_count == 0)
		return;

	stats_log_write("KCOV CMP hyp store per-syscall saturation over last %lds (top-%u of %lu occupied pools, %lu entries, cap %u/pool):\n",
			elapsed, top_count, occupied_pools,
			total_entries, CMP_HYP_PER_SYSCALL);
	{
		char hdr[CMP_HYP_KIND_NR * 12 + 1];
		int off = 0;

		hdr[0] = '\0';
		for (k = 0; k < CMP_HYP_KIND_NR; k++) {
			int w = snprintf(hdr + off, sizeof(hdr) - off,
					 " %11s", kind_labels[k]);
			if (w < 0 || (size_t)w >= sizeof(hdr) - (size_t)off)
				break;
			off += w;
		}
		stats_log_write("  %-24s %4s %9s %5s%s\n",
				"syscall", "arch", "count/cap", "fill%", hdr);
	}

	for (j = 0; j < top_count; j++) {
		const struct sat_row *r = &top[j];
		const struct syscalltable *tab;
		struct syscallentry *entry;
		const char *name;
		const char *arch_tag;
		unsigned int nr_max;
		unsigned int pct;
		char count_buf[16];
		char row[CMP_HYP_KIND_NR * 12 + 1];
		int off = 0;

		if (biarch) {
			if (r->do32) {
				tab = syscalls_32bit;
				nr_max = max_nr_32bit_syscalls;
				arch_tag = "32";
			} else {
				tab = syscalls_64bit;
				nr_max = max_nr_64bit_syscalls;
				arch_tag = "64";
			}
		} else {
			tab = syscalls;
			nr_max = max_nr_syscalls;
			arch_tag = "-";
		}
		entry = (r->nr < nr_max) ? tab[r->nr].entry : NULL;
		name = entry ? entry->name : "???";
		pct = (unsigned int)(((unsigned long)r->count * 100UL) /
				     CMP_HYP_PER_SYSCALL);

		snprintf(count_buf, sizeof(count_buf), "%u/%u",
			 r->count, CMP_HYP_PER_SYSCALL);

		row[0] = '\0';
		for (k = 0; k < CMP_HYP_KIND_NR; k++) {
			int w = snprintf(row + off, sizeof(row) - off,
					 " %11u", r->per_kind[k]);
			if (w < 0 || (size_t)w >= sizeof(row) - (size_t)off)
				break;
			off += w;
		}

		stats_log_write("  %-24s %4s %9s %4u%%%s\n",
				name, arch_tag, count_buf, pct, row);
	}
#undef KCOV_CMP_HYP_SAT_TOPN
}
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
			&kcov_shm->cmp_hyp_picked_by_state[s],
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
			&kcov_shm->cmp_hyp_skipped_retired_by_kind[k],
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
			&kcov_shm->cmp_hyp_demoted_reroll_picked_by_kind[k],
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
				&kcov_shm->cmp_hyp_state_transitions[from][to],
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
			&kcov_shm->cmp_hyp_pc_wins_by_kind[k], __ATOMIC_RELAXED);
		unsigned long tr = __atomic_load_n(
			&kcov_shm->cmp_hyp_transition_wins_by_kind[k], __ATOMIC_RELAXED);
		unsigned long ms = __atomic_load_n(
			&kcov_shm->cmp_hyp_misses_by_kind[k], __ATOMIC_RELAXED);
		unsigned long cs = __atomic_load_n(
			&kcov_shm->cmp_hyp_corpus_save_by_kind[k], __ATOMIC_RELAXED);
		unsigned long ds = __atomic_load_n(
			&kcov_shm->cmp_hyp_destructive_by_kind[k], __ATOMIC_RELAXED);
		unsigned long ks = __atomic_load_n(
			&kcov_shm->cmp_hyp_context_skip_by_kind[k], __ATOMIC_RELAXED);
		unsigned long nv = __atomic_load_n(
			&kcov_shm->cmp_hyp_cmp_novelty_wins_by_kind[k], __ATOMIC_RELAXED);

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
		__atomic_load_n(&kcov_shm->cmp_hyp_pool_overflow, __ATOMIC_RELAXED);
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
			&kcov_shm->cmp_hyp_would_promote_by_kind[k],
			__ATOMIC_RELAXED);
		cur_hyp_would_demote_kind[k] = __atomic_load_n(
			&kcov_shm->cmp_hyp_would_demote_by_kind[k],
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
		&kcov_shm->cmp_hyp_boundary_inserted, __ATOMIC_RELAXED);
	unsigned long cur_b_candidate_available = __atomic_load_n(
		&kcov_shm->cmp_hyp_boundary_candidate_available,
		__ATOMIC_RELAXED);
	unsigned long cur_b_credit_window_hits = __atomic_load_n(
		&kcov_shm->cmp_hyp_boundary_credit_window_hits,
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
/*
 * SHADOW per-hypothesis outcome aggregates that have no kcov_shm
 * flat-counter twin (corpus_save_wins / destructive_skips /
 * context_skips).  Walk the hyp_pools[][] grid once per window and
 * sum the per-entry u64s; render gated on any-delta so the section
 * stays quiet until a future credit site fires.  The walk is bounded
 * (MAX_NR_SYSCALL * 2 pools * CMP_HYP_PER_SYSCALL entries) and runs
 * at parent stats cadence, well below any noticeable cost.  Reads
 * are RELAXED against credit-side bumps; a torn sum at most under-
 * counts a single in-flight credit on this window and converges on
 * the next render.
 */
void kcov_cmp_render_hyp_per_hypothesis_aggregates_block(long elapsed)
{
	if (cmp_hints_shm == NULL)
		return;

	static uint64_t prev_hyp_corpus_save_wins;
	static uint64_t prev_hyp_destructive_skips;
	static uint64_t prev_hyp_context_skips;
	uint64_t cur_hyp_corpus_save_wins = 0;
	uint64_t cur_hyp_destructive_skips = 0;
	uint64_t cur_hyp_context_skips = 0;
	uint64_t delta_hyp_corpus_save_wins;
	uint64_t delta_hyp_destructive_skips;
	uint64_t delta_hyp_context_skips;
	unsigned int nr_i, do32_i, e_i;

	for (nr_i = 0; nr_i < MAX_NR_SYSCALL; nr_i++) {
		for (do32_i = 0; do32_i < 2; do32_i++) {
			struct cmp_hyp_pool *p =
				&cmp_hints_shm->hyp_pools[nr_i][do32_i];
			unsigned int n = p->count;

			if (n > CMP_HYP_PER_SYSCALL)
				n = CMP_HYP_PER_SYSCALL;
			for (e_i = 0; e_i < n; e_i++) {
				struct cmp_hypothesis *h = &p->entries[e_i];

				cur_hyp_corpus_save_wins +=
					__atomic_load_n(&h->corpus_save_wins,
							__ATOMIC_RELAXED);
				cur_hyp_destructive_skips +=
					__atomic_load_n(&h->destructive_skips,
							__ATOMIC_RELAXED);
				cur_hyp_context_skips +=
					__atomic_load_n(&h->context_skips,
							__ATOMIC_RELAXED);
			}
		}
	}

	delta_hyp_corpus_save_wins = sat_sub_ul(cur_hyp_corpus_save_wins, prev_hyp_corpus_save_wins);
	delta_hyp_destructive_skips = sat_sub_ul(cur_hyp_destructive_skips, prev_hyp_destructive_skips);
	delta_hyp_context_skips = sat_sub_ul(cur_hyp_context_skips, prev_hyp_context_skips);

	if ((delta_hyp_corpus_save_wins | delta_hyp_destructive_skips |
	     delta_hyp_context_skips) != 0) {
		stats_log_write("KCOV CMP hyp per-hypothesis aggregates over last %lds:\n", elapsed);
		stats_log_write("  %-32s +%lu  (total %lu)\n",
				"cmp_hyp_corpus_save_wins",
				(unsigned long)delta_hyp_corpus_save_wins,
				(unsigned long)cur_hyp_corpus_save_wins);
		stats_log_write("  %-32s +%lu  (total %lu)\n",
				"cmp_hyp_destructive_skips",
				(unsigned long)delta_hyp_destructive_skips,
				(unsigned long)cur_hyp_destructive_skips);
		stats_log_write("  %-32s +%lu  (total %lu)\n",
				"cmp_hyp_context_skips",
				(unsigned long)delta_hyp_context_skips,
				(unsigned long)cur_hyp_context_skips);
	}

	prev_hyp_corpus_save_wins = cur_hyp_corpus_save_wins;
	prev_hyp_destructive_skips = cur_hyp_destructive_skips;
	prev_hyp_context_skips = cur_hyp_context_skips;
}
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
			&kcov_shm->cmp_hyp_score_bucket_census[k],
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
			&kcov_shm->cmp_hyp_probe_class_hist[k],
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
