/*
 * Raw cmp-hint pool and tier periodic reporting.
 *
 * Owns the pre-typed pool blocks -- per-syscall top-N over the raw cmp
 * hint pool, the oldpool-vs-shadow diagnostic tables, the PC-win
 * conversion split, and the SHADOW per-entry feedback plus recent-CMP-
 * pool tier rows.  This maps to the raw cmp_hints/ pool layer, not the
 * typed hypothesis layer that lives in stats/kcov/cmp/hyp.c.
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
#include "pc_format.h"
#include "shm.h"
#include "stats.h"
#include "stats-internal.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

#include "stats/kcov/cmp/internal.h"

/*
 * Sum the SHADOW typed-hypothesis per-syscall counters (pc_wins,
 * consumed_count, misses) across the parallel hyp_pools[nr][0/1]
 * entries for a single syscall nr.  The shadow store has no per-
 * syscall scalar, but the per-hypothesis counters are bumped by
 * cmp_hyp_credit_outcome() from the same credit drain, so the per-
 * syscall sum is the natural shadow counterpart to the OLD per-
 * syscall pool scalars.  No-op when cmp_hints_shm is not attached.
 */
void kcov_cmp_sum_hyp_counters_per_syscall(unsigned int nr,
						  uint64_t *pc_wins,
						  uint64_t *consumed,
						  uint64_t *misses)
{
	unsigned int do32_i, e_i;

	if (cmp_hints_shm == NULL)
		return;

	for (do32_i = 0; do32_i < 2; do32_i++) {
		struct cmp_hyp_pool *p =
			&cmp_hints_shm->hyp_pools[nr][do32_i];
		unsigned int n = p->count;

		if (n > CMP_HYP_PER_SYSCALL)
			n = CMP_HYP_PER_SYSCALL;
		for (e_i = 0; e_i < n; e_i++) {
			struct cmp_hypothesis *h = &p->entries[e_i];

			*pc_wins += __atomic_load_n(
				&h->pc_wins, __ATOMIC_RELAXED);
			*consumed += __atomic_load_n(
				&h->consumed_count, __ATOMIC_RELAXED);
			*misses += __atomic_load_n(
				&h->misses, __ATOMIC_RELAXED);
		}
	}
}
/*
 * Per-syscall top-N table: for the top syscalls by per-window cmp-hint
 * injection delta, print the OLD per-syscall pool's conversion
 * (per_syscall_cmp_hint_pc_wins / per_syscall_cmp_injected) alongside
 * the SHADOW typed-hypothesis per-syscall pc-wins (summed across the
 * matching hyp_pools[nr][0/1] entries).  The two columns answer the t75
 * question directly: does the typed store predict better-converting
 * picks than the flat pool on the same syscalls the flat pool is most
 * active on.
 */
void kcov_cmp_render_oldpool_per_syscall_topn(void)
{
	static unsigned long prev_per_nr_injected[MAX_NR_SYSCALL];
	static unsigned long prev_per_nr_pc_wins[MAX_NR_SYSCALL];
	static uint64_t prev_per_nr_hyp_pc_wins[MAX_NR_SYSCALL];

	unsigned int top_nr[10];
	unsigned long top_injected[10];
	unsigned long top_pc_wins[10];
	unsigned long top_pc_wins_cum[10];
	unsigned long top_injected_cum[10];
	uint64_t top_hyp_pc_wins_cum[10];
	uint64_t top_hyp_pc_wins_delta[10];
	uint64_t top_hyp_consumed_cum[10];
	uint64_t top_hyp_misses_cum[10];
	unsigned int top_count = 0;

	unsigned int nr_syscalls_to_scan;
	const struct syscalltable *table;
	unsigned int i, j;

	/* Per-syscall top-N: OLD per-syscall pool conversion vs SHADOW
	 * hypothesis pc-wins.  Rank rows by per-window injected delta -- the
	 * "kernel actually drove cmp-hint substitution into this syscall this
	 * window" column -- so the comparison is anchored on syscalls where
	 * the OLD pool was active enough for the conversion ratio to be
	 * meaningful.  Hyp pc-wins is summed across the parallel
	 * hyp_pools[nr][0/1] entries: the shadow store has no per-syscall
	 * scalar, but the per-hypothesis pc_wins counter is bumped by
	 * cmp_hyp_credit_outcome() from the same credit drain, so the per-
	 * syscall sum is the natural shadow counterpart. */
	nr_syscalls_to_scan = biarch ? max_nr_64bit_syscalls : max_nr_syscalls;
	if (nr_syscalls_to_scan > MAX_NR_SYSCALL)
		nr_syscalls_to_scan = MAX_NR_SYSCALL;
	table = biarch ? syscalls_64bit : syscalls;

	memset(top_injected, 0, sizeof(top_injected));
	memset(top_pc_wins, 0, sizeof(top_pc_wins));
	memset(top_pc_wins_cum, 0, sizeof(top_pc_wins_cum));
	memset(top_injected_cum, 0, sizeof(top_injected_cum));
	memset(top_hyp_pc_wins_cum, 0, sizeof(top_hyp_pc_wins_cum));
	memset(top_hyp_pc_wins_delta, 0, sizeof(top_hyp_pc_wins_delta));
	memset(top_hyp_consumed_cum, 0, sizeof(top_hyp_consumed_cum));
	memset(top_hyp_misses_cum, 0, sizeof(top_hyp_misses_cum));

	for (i = 0; i < nr_syscalls_to_scan; i++) {
		unsigned long cur_injected = __atomic_load_n(
			&kcov_shm->cmp_hint_ps.per_syscall_cmp_injected[i],
			__ATOMIC_RELAXED);
		unsigned long cur_pc_wins = __atomic_load_n(
			&kcov_shm->cmp_hint_ps.per_syscall_cmp_hint_pc_wins[i],
			__ATOMIC_RELAXED);
		uint64_t cur_hyp_pc_wins_nr = 0;
		uint64_t cur_hyp_consumed_nr = 0;
		uint64_t cur_hyp_misses_nr = 0;
		unsigned long delta_injected;
		unsigned long delta_pc_wins;
		uint64_t delta_hyp_pc_wins_nr;

		kcov_cmp_sum_hyp_counters_per_syscall(i,
						      &cur_hyp_pc_wins_nr,
						      &cur_hyp_consumed_nr,
						      &cur_hyp_misses_nr);

		delta_injected = (cur_injected > prev_per_nr_injected[i]) ?
			cur_injected - prev_per_nr_injected[i] : 0;
		delta_pc_wins  = (cur_pc_wins  > prev_per_nr_pc_wins[i])  ?
			cur_pc_wins  - prev_per_nr_pc_wins[i]  : 0;
		delta_hyp_pc_wins_nr = (cur_hyp_pc_wins_nr > prev_per_nr_hyp_pc_wins[i]) ?
			cur_hyp_pc_wins_nr - prev_per_nr_hyp_pc_wins[i] : 0;

		prev_per_nr_injected[i]    = cur_injected;
		prev_per_nr_pc_wins[i]     = cur_pc_wins;
		prev_per_nr_hyp_pc_wins[i] = cur_hyp_pc_wins_nr;

		if (delta_injected == 0)
			continue;

		for (j = top_count; j > 0 && delta_injected > top_injected[j - 1]; j--) {
			if (j < 10) {
				top_injected[j]          = top_injected[j - 1];
				top_pc_wins[j]           = top_pc_wins[j - 1];
				top_pc_wins_cum[j]       = top_pc_wins_cum[j - 1];
				top_injected_cum[j]      = top_injected_cum[j - 1];
				top_hyp_pc_wins_cum[j]   = top_hyp_pc_wins_cum[j - 1];
				top_hyp_pc_wins_delta[j] = top_hyp_pc_wins_delta[j - 1];
				top_hyp_consumed_cum[j]  = top_hyp_consumed_cum[j - 1];
				top_hyp_misses_cum[j]    = top_hyp_misses_cum[j - 1];
				top_nr[j]                = top_nr[j - 1];
			}
		}
		{
			unsigned int kk = j;

			if (kk < 10) {
				top_injected[kk]          = delta_injected;
				top_pc_wins[kk]           = delta_pc_wins;
				top_pc_wins_cum[kk]       = cur_pc_wins;
				top_injected_cum[kk]      = cur_injected;
				top_hyp_pc_wins_cum[kk]   = cur_hyp_pc_wins_nr;
				top_hyp_pc_wins_delta[kk] = delta_hyp_pc_wins_nr;
				top_hyp_consumed_cum[kk]  = cur_hyp_consumed_nr;
				top_hyp_misses_cum[kk]    = cur_hyp_misses_nr;
				top_nr[kk]                = i;
				if (top_count < 10)
					top_count++;
			}
		}
	}

	if (top_count == 0)
		return;

	stats_log_write("KCOV CMP per-syscall old-pool vs shadow-hyp pc-wins (top by injected delta):\n");
	stats_log_write("  %-24s %10s %10s %8s %10s %10s %10s %10s\n",
			"syscall", "inj+", "old-pc+", "old-pc%",
			"hyp-pc+", "hyp-pc-tot", "consume", "miss");
	for (j = 0; j < top_count; j++) {
		struct syscallentry *entry = table[top_nr[j]].entry;
		const char *name = entry ? entry->name : "???";
		unsigned int pct = top_injected_cum[j] ?
			(unsigned int)((top_pc_wins_cum[j] * 100UL) /
				       top_injected_cum[j]) : 0;

		stats_log_write("  %-24s %10lu %10lu %7u%% %10lu %10lu %10lu %10lu\n",
				name,
				top_injected[j],
				top_pc_wins[j],
				pct,
				(unsigned long)top_hyp_pc_wins_delta[j],
				(unsigned long)top_hyp_pc_wins_cum[j],
				(unsigned long)top_hyp_consumed_cum[j],
				(unsigned long)top_hyp_misses_cum[j]);
	}
}
/*
 * Old-flat-pool vs shadow-hypothesis comparison block.  Two sub-blocks:
 *
 *   1. Flat per-pool-kind summary: per-pool consumed / pc-wins / misses /
 *      cmp-novelty cumulative + window-delta.  Lets an operator read the
 *      per-syscall vs field-pool conversion ratio at a glance without
 *      having to thread per-syscall arrays.
 *
 *   2. Per-syscall top-N table (rendered by
 *      kcov_cmp_render_oldpool_per_syscall_topn()).
 *
 * Pure SHADOW: every counter read here is bumped by paths that already
 * existed (the by-pool partition bumps land alongside the existing flat
 * counters and the cmp_hyp_credit_outcome paths); this function only
 * formats the comparison.  Independent prev_* snapshots so other dump
 * blocks that read the same arrays do not desync the window deltas here.
 */
void kcov_cmp_oldpool_vs_shadow_block_render(long elapsed __unused__)
{
	static unsigned long prev_consumed_by_pool[CMP_HINT_POOL_KIND_NR];
	static unsigned long prev_pc_wins_by_pool[CMP_HINT_POOL_KIND_NR];
	static unsigned long prev_misses_by_pool[CMP_HINT_POOL_KIND_NR];
	static unsigned long prev_cmp_novelty_by_pool[CMP_HINT_POOL_KIND_NR];
	static bool armed;

	unsigned long cur_consumed_by_pool[CMP_HINT_POOL_KIND_NR];
	unsigned long cur_pc_wins_by_pool[CMP_HINT_POOL_KIND_NR];
	unsigned long cur_misses_by_pool[CMP_HINT_POOL_KIND_NR];
	unsigned long cur_cmp_novelty_by_pool[CMP_HINT_POOL_KIND_NR];
	unsigned long delta_consumed_by_pool[CMP_HINT_POOL_KIND_NR];
	unsigned long delta_pc_wins_by_pool[CMP_HINT_POOL_KIND_NR];
	unsigned long delta_misses_by_pool[CMP_HINT_POOL_KIND_NR];
	unsigned long delta_cmp_novelty_by_pool[CMP_HINT_POOL_KIND_NR];

	unsigned int k;
	bool any_pool_delta = false;

	static const char *const pool_kind_name[CMP_HINT_POOL_KIND_NR] = {
		[CMP_HINT_POOL_PER_SYSCALL] = "per-syscall",
		[CMP_HINT_POOL_FIELD]       = "field",
	};

	if (kcov_shm == NULL)
		return;

	for (k = 0; k < CMP_HINT_POOL_KIND_NR; k++) {
		cur_consumed_by_pool[k] = __atomic_load_n(
			&kcov_shm->cmp_hint_pool.cmp_hint_consumed_by_pool[k],
			__ATOMIC_RELAXED);
		cur_pc_wins_by_pool[k] = __atomic_load_n(
			&kcov_shm->cmp_hint_pool.cmp_hint_pc_wins_by_pool[k],
			__ATOMIC_RELAXED);
		cur_misses_by_pool[k] = __atomic_load_n(
			&kcov_shm->cmp_hint_pool.cmp_hint_misses_by_pool[k],
			__ATOMIC_RELAXED);
		cur_cmp_novelty_by_pool[k] = __atomic_load_n(
			&kcov_shm->cmp_hint_pool.cmp_hint_cmp_novelty_wins_by_pool[k],
			__ATOMIC_RELAXED);
	}

	if (!armed) {
		for (k = 0; k < CMP_HINT_POOL_KIND_NR; k++) {
			prev_consumed_by_pool[k] = cur_consumed_by_pool[k];
			prev_pc_wins_by_pool[k] = cur_pc_wins_by_pool[k];
			prev_misses_by_pool[k] = cur_misses_by_pool[k];
			prev_cmp_novelty_by_pool[k] = cur_cmp_novelty_by_pool[k];
		}
		/* per-nr snapshots and hyp walk are armed on the first
		 * windowed emit inside kcov_cmp_render_oldpool_per_syscall_topn();
		 * the first call here seeds prev_ and skips the comparison,
		 * identical to the pattern in
		 * kcov_cmp_observability_block_render(). */
		armed = true;
		return;
	}

	for (k = 0; k < CMP_HINT_POOL_KIND_NR; k++) {
		/* Counters are monotonic but guard the subtraction defensively
		 * the same way the existing per-syscall topn does -- a torn
		 * load on a hot relaxed atomic could otherwise underflow to
		 * ~ULONG_MAX and dominate the table. */
		delta_consumed_by_pool[k] = (cur_consumed_by_pool[k] > prev_consumed_by_pool[k]) ?
			cur_consumed_by_pool[k] - prev_consumed_by_pool[k] : 0;
		delta_pc_wins_by_pool[k] = (cur_pc_wins_by_pool[k] > prev_pc_wins_by_pool[k]) ?
			cur_pc_wins_by_pool[k] - prev_pc_wins_by_pool[k] : 0;
		delta_misses_by_pool[k] = (cur_misses_by_pool[k] > prev_misses_by_pool[k]) ?
			cur_misses_by_pool[k] - prev_misses_by_pool[k] : 0;
		delta_cmp_novelty_by_pool[k] = (cur_cmp_novelty_by_pool[k] > prev_cmp_novelty_by_pool[k]) ?
			cur_cmp_novelty_by_pool[k] - prev_cmp_novelty_by_pool[k] : 0;

		if ((delta_consumed_by_pool[k] | delta_pc_wins_by_pool[k] |
		     delta_misses_by_pool[k] | delta_cmp_novelty_by_pool[k]) != 0)
			any_pool_delta = true;
	}

	if (any_pool_delta) {
		stats_log_write("KCOV CMP old-flat-pool conversion by pool kind over last %lds:\n",
				elapsed);
		stats_log_write("  %-12s %12s %12s %12s %12s %8s\n",
				"pool", "consumed+", "pc-wins+", "misses+",
				"novelty+", "pc-rate");
		for (k = 0; k < CMP_HINT_POOL_KIND_NR; k++) {
			unsigned long denom = delta_pc_wins_by_pool[k] +
					      delta_misses_by_pool[k];
			unsigned int pct = denom ?
				(unsigned int)((delta_pc_wins_by_pool[k] * 100UL) /
					       denom) : 0;
			const char *name = pool_kind_name[k];

			if (name == NULL)
				name = "?";
			stats_log_write("  %-12s %12lu %12lu %12lu %12lu %7u%%\n",
					name,
					delta_consumed_by_pool[k],
					delta_pc_wins_by_pool[k],
					delta_misses_by_pool[k],
					delta_cmp_novelty_by_pool[k],
					pct);
		}
		stats_log_write("  cumulative:\n");
		for (k = 0; k < CMP_HINT_POOL_KIND_NR; k++) {
			unsigned long denom_cum = cur_pc_wins_by_pool[k] +
						  cur_misses_by_pool[k];
			unsigned int pct_cum = denom_cum ?
				(unsigned int)((cur_pc_wins_by_pool[k] * 100UL) /
					       denom_cum) : 0;
			const char *name = pool_kind_name[k];

			if (name == NULL)
				name = "?";
			stats_log_write("  %-12s %12lu %12lu %12lu %12lu %7u%%\n",
					name,
					cur_consumed_by_pool[k],
					cur_pc_wins_by_pool[k],
					cur_misses_by_pool[k],
					cur_cmp_novelty_by_pool[k],
					pct_cum);
		}
	}

	for (k = 0; k < CMP_HINT_POOL_KIND_NR; k++) {
		prev_consumed_by_pool[k] = cur_consumed_by_pool[k];
		prev_pc_wins_by_pool[k] = cur_pc_wins_by_pool[k];
		prev_misses_by_pool[k] = cur_misses_by_pool[k];
		prev_cmp_novelty_by_pool[k] = cur_cmp_novelty_by_pool[k];
	}

	kcov_cmp_render_oldpool_per_syscall_topn();
}
/*
 * PC-win CONVERSION split by source-path.  One rendered surface for
 * three attribution rates over the same PC-win outcome:
 *
 *   1. flat-replay conversion    -- (sum_k cmp_hint_pc_wins_by_pool[k]
 *      - cmp_hyp_pc_wins) wins over (cmp_hints_injected -
 *      cmp_hyp_live_injected) replays: how often the raw-pool arm
 *      turned a REPLAY into a PC-edge win.
 *   2. typed-hyp LIVE conversion -- cmp_hyp_pc_wins over
 *      cmp_hyp_live_injected: the typed derive-and-inject arm's yield.
 *   3. by-kind typed conversion  -- per CMP_HYP_KIND slot the same
 *      numerator/denominator split so it is legible which typed kind
 *      is actually driving the aggregate typed yield.
 *
 * GRANULARITY: cmp_hint_wins (the "=2" aggregate rendered elsewhere)
 * is bumped per DISPATCH, while the split numerators (by_pool sum,
 * cmp_hyp_pc_wins) are bumped per STASH-ENTRY.  The per-entry basis
 * is finer and is the correct attribution granularity for the split;
 * do NOT expect flat_wins + typed_wins == cmp_hint_wins.
 *
 * Pure RENDER: every atomic load below hits a counter bumped by paths
 * that already existed; each subtraction is folded through sat_sub_ul
 * so a torn read (concurrent bump on the same window boundary, or a
 * numerator bumped while its denominator has not yet caught up) folds
 * to zero rather than wrap.  Independent prev_* snapshots so other
 * dump blocks that read the same arrays do not desync the window
 * deltas here (same discipline as the by-pool block above).
 */
void kcov_cmp_render_pc_win_conversion_split_block(long elapsed __unused__)
{
	static const char * const kind_labels[CMP_HYP_KIND_NR] = {
		"exact", "range", "boundary", "bitmask",
		"enum_family", "alignment", "length",
		"foreign_value",
	};
	static bool armed;
	static unsigned long prev_hints_injected;
	static unsigned long prev_hyp_live_injected;
	static unsigned long prev_hyp_pc_wins;
	static unsigned long prev_hint_pc_wins_by_pool[CMP_HINT_POOL_KIND_NR];
	static unsigned long prev_hyp_live_injected_by_kind[CMP_HYP_KIND_NR];
	static unsigned long prev_hyp_pc_wins_by_kind[CMP_HYP_KIND_NR];

	unsigned long cur_hints_injected;
	unsigned long cur_hyp_live_injected;
	unsigned long cur_hyp_pc_wins;
	unsigned long cur_hint_pc_wins_by_pool[CMP_HINT_POOL_KIND_NR];
	unsigned long cur_hyp_live_injected_by_kind[CMP_HYP_KIND_NR];
	unsigned long cur_hyp_pc_wins_by_kind[CMP_HYP_KIND_NR];
	unsigned long cur_pool_pc_wins_sum = 0;
	unsigned long prev_pool_pc_wins_sum = 0;
	unsigned long d_hints_inj, d_hyp_live_inj, d_hyp_pc_wins;
	unsigned long d_pool_pc_wins_sum, d_flat_replays, d_flat_wins;
	unsigned long c_flat_replays, c_flat_wins;
	unsigned int pct_flat_w, pct_typed_w, pct_flat_c, pct_typed_c;
	unsigned int k;

	if (kcov_shm == NULL)
		return;

	cur_hints_injected = __atomic_load_n(&kcov_shm->hints_flat.cmp_hints_injected,
					     __ATOMIC_RELAXED);
	cur_hyp_live_injected = __atomic_load_n(&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_live_injected,
						__ATOMIC_RELAXED);
	cur_hyp_pc_wins = __atomic_load_n(&kcov_shm->hyp_flat.cmp_hyp_pc_wins,
					  __ATOMIC_RELAXED);
	for (k = 0; k < CMP_HINT_POOL_KIND_NR; k++) {
		cur_hint_pc_wins_by_pool[k] = __atomic_load_n(
			&kcov_shm->cmp_hint_pool.cmp_hint_pc_wins_by_pool[k],
			__ATOMIC_RELAXED);
		cur_pool_pc_wins_sum += cur_hint_pc_wins_by_pool[k];
		prev_pool_pc_wins_sum += prev_hint_pc_wins_by_pool[k];
	}
	for (k = 0; k < CMP_HYP_KIND_NR; k++) {
		cur_hyp_live_injected_by_kind[k] = __atomic_load_n(
			&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_live_injected_by_kind[k],
			__ATOMIC_RELAXED);
		cur_hyp_pc_wins_by_kind[k] = __atomic_load_n(
			&kcov_shm->cmp_hyp_results.cmp_hyp_pc_wins_by_kind[k],
			__ATOMIC_RELAXED);
	}

	if (!armed) {
		prev_hints_injected = cur_hints_injected;
		prev_hyp_live_injected = cur_hyp_live_injected;
		prev_hyp_pc_wins = cur_hyp_pc_wins;
		for (k = 0; k < CMP_HINT_POOL_KIND_NR; k++)
			prev_hint_pc_wins_by_pool[k] = cur_hint_pc_wins_by_pool[k];
		for (k = 0; k < CMP_HYP_KIND_NR; k++) {
			prev_hyp_live_injected_by_kind[k] =
				cur_hyp_live_injected_by_kind[k];
			prev_hyp_pc_wins_by_kind[k] =
				cur_hyp_pc_wins_by_kind[k];
		}
		armed = true;
		return;
	}

	d_hints_inj        = sat_sub_ul(cur_hints_injected, prev_hints_injected);
	d_hyp_live_inj     = sat_sub_ul(cur_hyp_live_injected, prev_hyp_live_injected);
	d_hyp_pc_wins      = sat_sub_ul(cur_hyp_pc_wins, prev_hyp_pc_wins);
	d_pool_pc_wins_sum = sat_sub_ul(cur_pool_pc_wins_sum, prev_pool_pc_wins_sum);
	d_flat_replays     = sat_sub_ul(d_hints_inj, d_hyp_live_inj);
	d_flat_wins        = sat_sub_ul(d_pool_pc_wins_sum, d_hyp_pc_wins);
	c_flat_replays     = sat_sub_ul(cur_hints_injected, cur_hyp_live_injected);
	c_flat_wins        = sat_sub_ul(cur_pool_pc_wins_sum, cur_hyp_pc_wins);

	pct_flat_w  = d_flat_replays ?
		(unsigned int)((d_flat_wins * 100UL) / d_flat_replays) : 0;
	pct_typed_w = d_hyp_live_inj ?
		(unsigned int)((d_hyp_pc_wins * 100UL) / d_hyp_live_inj) : 0;
	pct_flat_c  = c_flat_replays ?
		(unsigned int)((c_flat_wins * 100UL) / c_flat_replays) : 0;
	pct_typed_c = cur_hyp_live_injected ?
		(unsigned int)((cur_hyp_pc_wins * 100UL) / cur_hyp_live_injected) : 0;

	if ((d_hints_inj | d_hyp_live_inj | d_hyp_pc_wins |
	     d_pool_pc_wins_sum) != 0) {
		stats_log_write("KCOV CMP PC-win conversion by source-path over last %lds:\n",
				elapsed);
		stats_log_write("  (numerators bumped per-stash-entry; the aggregate cmp_hint_wins is per-dispatch and NOT the sum of these rows)\n");
		stats_log_write("  %-24s %12s %12s %8s\n",
				"source-path", "wins+", "replays+", "rate");
		stats_log_write("  %-24s %12lu %12lu %7u%%\n",
				"flat-replay",
				d_flat_wins, d_flat_replays, pct_flat_w);
		stats_log_write("  %-24s %12lu %12lu %7u%%\n",
				"typed-hyp-live",
				d_hyp_pc_wins, d_hyp_live_inj, pct_typed_w);
		stats_log_write("  typed-hyp-live by kind:\n");
		for (k = 0; k < CMP_HYP_KIND_NR; k++) {
			unsigned long d_k_wins = sat_sub_ul(
				cur_hyp_pc_wins_by_kind[k],
				prev_hyp_pc_wins_by_kind[k]);
			unsigned long d_k_inj  = sat_sub_ul(
				cur_hyp_live_injected_by_kind[k],
				prev_hyp_live_injected_by_kind[k]);
			unsigned int pct = d_k_inj ?
				(unsigned int)((d_k_wins * 100UL) / d_k_inj) : 0;

			stats_log_write("    %-22s %12lu %12lu %7u%%\n",
					kind_labels[k],
					d_k_wins, d_k_inj, pct);
		}
		stats_log_write("  cumulative:\n");
		stats_log_write("  %-24s %12lu %12lu %7u%%\n",
				"flat-replay",
				c_flat_wins, c_flat_replays, pct_flat_c);
		stats_log_write("  %-24s %12lu %12lu %7u%%\n",
				"typed-hyp-live",
				cur_hyp_pc_wins, cur_hyp_live_injected,
				pct_typed_c);
		stats_log_write("  typed-hyp-live by kind:\n");
		for (k = 0; k < CMP_HYP_KIND_NR; k++) {
			unsigned int pct = cur_hyp_live_injected_by_kind[k] ?
				(unsigned int)((cur_hyp_pc_wins_by_kind[k] * 100UL) /
					       cur_hyp_live_injected_by_kind[k]) : 0;

			stats_log_write("    %-22s %12lu %12lu %7u%%\n",
					kind_labels[k],
					cur_hyp_pc_wins_by_kind[k],
					cur_hyp_live_injected_by_kind[k], pct);
		}
	}

	prev_hints_injected = cur_hints_injected;
	prev_hyp_live_injected = cur_hyp_live_injected;
	prev_hyp_pc_wins = cur_hyp_pc_wins;
	for (k = 0; k < CMP_HINT_POOL_KIND_NR; k++)
		prev_hint_pc_wins_by_pool[k] = cur_hint_pc_wins_by_pool[k];
	for (k = 0; k < CMP_HYP_KIND_NR; k++) {
		prev_hyp_live_injected_by_kind[k] = cur_hyp_live_injected_by_kind[k];
		prev_hyp_pc_wins_by_kind[k] = cur_hyp_pc_wins_by_kind[k];
	}
}
void kcov_cmp_render_per_entry_feedback_scoring(long elapsed,
						       unsigned long delta_cmp_hints_consumed, unsigned long cur_cmp_hints_consumed,
						       unsigned long delta_cmp_hint_wins, unsigned long cur_cmp_hint_wins,
						       unsigned long delta_cmp_hint_misses, unsigned long cur_cmp_hint_misses,
						       unsigned long delta_cmp_hint_cmp_novelty_wins, unsigned long cur_cmp_hint_cmp_novelty_wins,
						       unsigned long delta_cmp_hint_stash_overflow, unsigned long cur_cmp_hint_stash_overflow,
						       unsigned long delta_cmp_hint_credit_entry_evicted, unsigned long cur_cmp_hint_credit_entry_evicted)
{
	/* SHADOW per-entry feedback scoring counters
	 * ([11-feedback-loop] PHASE 4).  Live pool selection is
	 * uniform here -- these counters record outcomes for a future
	 * A/B-gated live-pick weight to read.  cmp_hint_wins /
	 * cmp_hint_misses are PC-edge only; cmp_hint_cmp_novelty_wins
	 * is the SEPARATE CMP-mode novelty channel (kept out of the
	 * PC-edge score). */
	kcov_cmp_rate_line(elapsed, "cmp_hints_consumed", delta_cmp_hints_consumed, cur_cmp_hints_consumed);
	kcov_cmp_rate_line(elapsed, "cmp_hint_wins", delta_cmp_hint_wins, cur_cmp_hint_wins);
	kcov_cmp_rate_line(elapsed, "cmp_hint_misses", delta_cmp_hint_misses, cur_cmp_hint_misses);
	kcov_cmp_rate_line(elapsed, "cmp_hint_cmp_novelty_wins", delta_cmp_hint_cmp_novelty_wins, cur_cmp_hint_cmp_novelty_wins);
	kcov_cmp_rate_line(elapsed, "cmp_hint_stash_overflow", delta_cmp_hint_stash_overflow, cur_cmp_hint_stash_overflow);
	kcov_cmp_rate_line(elapsed, "cmp_hint_credit_entry_evicted", delta_cmp_hint_credit_entry_evicted, cur_cmp_hint_credit_entry_evicted);
}
void kcov_cmp_render_recent_cmp_pool_tier(long elapsed,
						 unsigned long delta_cmp_recent_inserts, unsigned long cur_cmp_recent_inserts,
						 unsigned long delta_cmp_recent_evicts, unsigned long cur_cmp_recent_evicts,
						 unsigned long delta_cmp_recent_would_pick, unsigned long cur_cmp_recent_would_pick,
						 unsigned long delta_cmp_recent_would_miss, unsigned long cur_cmp_recent_would_miss,
						 unsigned long delta_cmp_recent_live_picks, unsigned long cur_cmp_recent_live_picks)
{
	/* SHADOW recent-CMP-pool tier: inserts/evicts measure the
	 * absorbed-but-otherwise-dropped throughput; would_pick /
	 * would_miss is the plateau-window try_get population the
	 * recent-first arm would sample from (legible from the default
	 * durable-first run); live_picks stays at zero until the A/B
	 * flag is flipped to recent-first; promotions is the recording-
	 * only conversion counter the follow-up commit will route into
	 * a recent->durable promotion.  Without these rows the tier
	 * looks identical to "disabled" in the logs -- a non-zero
	 * would_pick rate with cmp_recent_inserts == 0 is the empty-
	 * ring signature; a healthy non-zero would_pick alongside
	 * inserts says the recent-first arm has real signal to draw
	 * from. */
	kcov_cmp_rate_line(elapsed, "cmp_recent_inserts", delta_cmp_recent_inserts, cur_cmp_recent_inserts);
	kcov_cmp_rate_line(elapsed, "cmp_recent_evicts", delta_cmp_recent_evicts, cur_cmp_recent_evicts);
	kcov_cmp_rate_line(elapsed, "cmp_recent_would_pick", delta_cmp_recent_would_pick, cur_cmp_recent_would_pick);
	kcov_cmp_rate_line(elapsed, "cmp_recent_would_miss", delta_cmp_recent_would_miss, cur_cmp_recent_would_miss);
	kcov_cmp_rate_line(elapsed, "cmp_recent_live_picks", delta_cmp_recent_live_picks, cur_cmp_recent_live_picks);
}
