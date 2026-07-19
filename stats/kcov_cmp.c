/*
 * KCOV CMP observability blocks.
 *
 * Carved verbatim out of stats.c.  Contains the four static
 * per-window render helpers -- kcov_cmp_observability_block_render,
 * kcov_redqueen_observability_block_render,
 * kcov_cmp_oldpool_vs_shadow_block_render,
 * kcov_cmp_hyp_saturation_block_render -- and the top-level
 * kcov_cmp_stats_periodic_dump that fans out to them from the
 * parent's periodic tick.
 *
 * The four block_render helpers are called only from
 * kcov_cmp_stats_periodic_dump in this same TU so they keep their
 * file-static tag.  kcov_cmp_stats_periodic_dump itself is already
 * declared in include/stats.h; nothing new is added to
 * stats-internal.h for this cluster.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "arch.h"
#include "arg-len-semantics.h"
#include "breadcrumb_ring.h"
#include "child-api.h"
#include "cmp_hints.h"
#include "cred_throttle.h"
#include "fd.h"
#include "kcov.h"
#include "minicorpus.h"
#include "params.h"
#include "pc_format.h"
#include "pids.h"
#include "reach-band.h"
#include "sequence.h"
#include "shm.h"
#include "stats.h"
#include "stats-internal.h"
#include "stats_ring.h"
#include "syscall.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"
#include "utils.h"
#include "version.h"


#include "stats/kcov/cmp/internal.h"

/*
 * RedQueen observability: top-N syscalls by re-exec
 * attempt delta + flat aggregates for the per-slot histograms.  The
 * per-slot histograms stay flat (6 entries each) rather than per-nr to
 * keep the block readable -- the "which arg slot won attribution" and
 * "which arg slot produced novelty" questions are aggregate-shaped, not
 * per-syscall, so the answer is two short rows of counts.  The per-nr
 * partition for attempts and ambiguity is the syscall-shaped half: that
 * goes through the top-N table.
 */
static void kcov_redqueen_observability_block_render(long elapsed __unused__)
{
	static unsigned long prev_attempts[MAX_NR_SYSCALL];
	static unsigned long prev_ambiguous[MAX_NR_SYSCALL];
	static bool armed;
	unsigned int top_nr[10];
	unsigned long top_attempts[10];
	unsigned long top_ambiguous[10];
	unsigned int top_count = 0;
	unsigned long slot_hist[CMP_REDQUEEN_SLOT_HIST_NR];
	unsigned long slot_success[CMP_REDQUEEN_SLOT_HIST_NR];
	unsigned long slot_fill[CMP_REDQUEEN_SLOT_HIST_NR];
	bool any_slot = false;
	unsigned long pick_success[REEXEC_PENDING_PICK_HIST_NR];
	bool any_pick_success = false;
	unsigned int nr_syscalls_to_scan;
	const struct syscalltable *table;
	unsigned int i;
	unsigned int j;

	if (kcov_shm == NULL)
		return;

	nr_syscalls_to_scan = biarch ? max_nr_64bit_syscalls : max_nr_syscalls;
	if (nr_syscalls_to_scan > MAX_NR_SYSCALL)
		nr_syscalls_to_scan = MAX_NR_SYSCALL;
	table = biarch ? syscalls_64bit : syscalls;

	memset(top_attempts, 0, sizeof(top_attempts));
	memset(top_ambiguous, 0, sizeof(top_ambiguous));

	for (i = 0; i < nr_syscalls_to_scan; i++) {
		unsigned long cur_attempts = __atomic_load_n(
			&kcov_shm->reexec_attempts_by_syscall[i], __ATOMIC_RELAXED);
		unsigned long cur_ambig = __atomic_load_n(
			&kcov_shm->reexec_ambiguous_by_syscall[i], __ATOMIC_RELAXED);
		unsigned long delta_attempts;
		unsigned long delta_ambig;
		unsigned int k;

		if (!armed) {
			prev_attempts[i] = cur_attempts;
			prev_ambiguous[i] = cur_ambig;
			continue;
		}

		delta_attempts = sat_sub_ul(cur_attempts, prev_attempts[i]);
		delta_ambig    = sat_sub_ul(cur_ambig,    prev_ambiguous[i]);

		prev_attempts[i] = cur_attempts;
		prev_ambiguous[i] = cur_ambig;

		if (delta_attempts == 0)
			continue;

		for (j = top_count; j > 0 && delta_attempts > top_attempts[j - 1]; j--) {
			if (j < 10) {
				top_attempts[j]  = top_attempts[j - 1];
				top_ambiguous[j] = top_ambiguous[j - 1];
				top_nr[j]        = top_nr[j - 1];
			}
		}
		k = j;
		if (k < 10) {
			top_attempts[k]  = delta_attempts;
			top_ambiguous[k] = delta_ambig;
			top_nr[k]        = i;
			if (top_count < 10)
				top_count++;
		}
	}

	for (i = 0; i < CMP_REDQUEEN_SLOT_HIST_NR; i++) {
		slot_hist[i] = __atomic_load_n(
			&kcov_shm->reexec_attribution_slot_hist[i],
			__ATOMIC_RELAXED);
		slot_success[i] = __atomic_load_n(
			&kcov_shm->reexec_success_by_slot[i],
			__ATOMIC_RELAXED);
		slot_fill[i] = __atomic_load_n(
			&kcov_shm->typed_inject_fill_slot_hist[i],
			__ATOMIC_RELAXED);
		if ((slot_hist[i] | slot_success[i] | slot_fill[i]) != 0)
			any_slot = true;
	}

	for (i = 0; i < REEXEC_PENDING_PICK_HIST_NR; i++) {
		pick_success[i] = __atomic_load_n(
			&kcov_shm->reexec_pending_pick_success[i],
			__ATOMIC_RELAXED);
		if (pick_success[i] != 0)
			any_pick_success = true;
	}

	if (!armed) {
		armed = true;
		return;
	}

	if (top_count > 0) {
		stats_log_write("KCOV RedQueen syscalls (top by per-window reexec_attempts delta):\n");
		stats_log_write("  %-24s %12s %12s\n",
				"syscall", "attempts+", "ambiguous+");
		for (j = 0; j < top_count; j++) {
			struct syscallentry *entry = table[top_nr[j]].entry;
			const char *name = entry ? entry->name : "???";

			stats_log_write("  %-24s %12lu %12lu\n",
					name, top_attempts[j], top_ambiguous[j]);
		}
	}

	if (any_slot) {
		stats_log_write("KCOV RedQueen arg-slot attribution (cumulative, slot=index+1):\n");
		stats_log_write("  %-12s %10s %10s %10s %10s %10s %10s\n",
				"counter", "a1", "a2", "a3", "a4", "a5", "a6");
		stats_log_write("  %-12s %10lu %10lu %10lu %10lu %10lu %10lu\n",
				"attribute",
				slot_hist[0], slot_hist[1], slot_hist[2],
				slot_hist[3], slot_hist[4], slot_hist[5]);
		stats_log_write("  %-12s %10lu %10lu %10lu %10lu %10lu %10lu\n",
				"success",
				slot_success[0], slot_success[1], slot_success[2],
				slot_success[3], slot_success[4], slot_success[5]);
		/* Placement-proof fill-slot histogram: the arg slot the
		 * typed-hypothesis LIVE inject actually landed in (bumped
		 * inside the accept-gated commit block in
		 * cmp_try_get_durable_tier).  Rendered on the same row set
		 * as the source-slot attribute row so an operator can read
		 * the (fill vs attribute) divergence directly: an inject
		 * that consistently lands on a different arg slot than the
		 * kernel-side CMP fired on confirms placement is the CMP-
		 * conversion killer. */
		stats_log_write("  %-12s %10lu %10lu %10lu %10lu %10lu %10lu\n",
				"fill",
				slot_fill[0], slot_fill[1], slot_fill[2],
				slot_fill[3], slot_fill[4], slot_fill[5]);
	}

	/* Per-pending-buffer-index success counter (A/B signal for
	 * --redqueen-pending-pick).  Cumulative across both pick modes:
	 * a heavy load at index 0 with a flat tail under the FIRST policy
	 * versus a spread under RANDOM tells whether trace-order bias is
	 * costing signal.  Header is the policy name so an operator
	 * eyeballing the dump knows which arm is currently active. */
	if (any_pick_success) {
		stats_log_write("KCOV RedQueen pending-buffer pick success (cumulative, policy=%s):\n",
				redqueen_pending_pick_name(
					redqueen_pending_pick_mode_arg));
		stats_log_write("  %-12s %10s %10s %10s %10s %10s %10s %10s %10s\n",
				"counter",
				"p0", "p1", "p2", "p3",
				"p4", "p5", "p6", "p7");
		stats_log_write("  %-12s %10lu %10lu %10lu %10lu %10lu %10lu %10lu %10lu\n",
				"success",
				pick_success[0], pick_success[1],
				pick_success[2], pick_success[3],
				pick_success[4], pick_success[5],
				pick_success[6], pick_success[7]);
	}
}

/*
 * Sum the SHADOW typed-hypothesis per-syscall counters (pc_wins,
 * consumed_count, misses) across the parallel hyp_pools[nr][0/1]
 * entries for a single syscall nr.  The shadow store has no per-
 * syscall scalar, but the per-hypothesis counters are bumped by
 * cmp_hyp_credit_outcome() from the same credit drain, so the per-
 * syscall sum is the natural shadow counterpart to the OLD per-
 * syscall pool scalars.  No-op when cmp_hints_shm is not attached.
 */
static void kcov_cmp_sum_hyp_counters_per_syscall(unsigned int nr,
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
static void kcov_cmp_render_oldpool_per_syscall_topn(void)
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
			&kcov_shm->per_syscall_cmp_injected[i],
			__ATOMIC_RELAXED);
		unsigned long cur_pc_wins = __atomic_load_n(
			&kcov_shm->per_syscall_cmp_hint_pc_wins[i],
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
static void kcov_cmp_oldpool_vs_shadow_block_render(long elapsed __unused__)
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
			&kcov_shm->cmp_hint_consumed_by_pool[k],
			__ATOMIC_RELAXED);
		cur_pc_wins_by_pool[k] = __atomic_load_n(
			&kcov_shm->cmp_hint_pc_wins_by_pool[k],
			__ATOMIC_RELAXED);
		cur_misses_by_pool[k] = __atomic_load_n(
			&kcov_shm->cmp_hint_misses_by_pool[k],
			__ATOMIC_RELAXED);
		cur_cmp_novelty_by_pool[k] = __atomic_load_n(
			&kcov_shm->cmp_hint_cmp_novelty_wins_by_pool[k],
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
static void kcov_cmp_render_pc_win_conversion_split_block(long elapsed __unused__)
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

	cur_hints_injected = __atomic_load_n(&kcov_shm->cmp_hints_injected,
					     __ATOMIC_RELAXED);
	cur_hyp_live_injected = __atomic_load_n(&kcov_shm->cmp_hyp_live_injected,
						__ATOMIC_RELAXED);
	cur_hyp_pc_wins = __atomic_load_n(&kcov_shm->cmp_hyp_pc_wins,
					  __ATOMIC_RELAXED);
	for (k = 0; k < CMP_HINT_POOL_KIND_NR; k++) {
		cur_hint_pc_wins_by_pool[k] = __atomic_load_n(
			&kcov_shm->cmp_hint_pc_wins_by_pool[k],
			__ATOMIC_RELAXED);
		cur_pool_pc_wins_sum += cur_hint_pc_wins_by_pool[k];
		prev_pool_pc_wins_sum += prev_hint_pc_wins_by_pool[k];
	}
	for (k = 0; k < CMP_HYP_KIND_NR; k++) {
		cur_hyp_live_injected_by_kind[k] = __atomic_load_n(
			&kcov_shm->cmp_hyp_live_injected_by_kind[k],
			__ATOMIC_RELAXED);
		cur_hyp_pc_wins_by_kind[k] = __atomic_load_n(
			&kcov_shm->cmp_hyp_pc_wins_by_kind[k],
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
static void kcov_cmp_hyp_saturation_block_render(long elapsed __unused__)
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

/*
 * SHADOW typed-CMP-hypothesis store render block.
 *
 * Self-contained mini-section so the skeleton's all-zero counters do
 * not need to be folded into the giant delta-gate above.  All eleven
 * counters read zero in this commit: the observation hook is a no-op
 * and no inference / consumer / feedback path bumps any of them yet.
 * The renders fire once the follow-up units land and the deltas
 * become non-zero; the section header itself is gated on any-delta
 * so the log stays quiet in the meantime.
 */
/* Per-kind census: accepted (inserted_by_kind) vs dropped
 * at the per-kind sub-cap (kind_full_by_kind) vs dropped
 * at the total pool cap (pool_full_by_kind -- an attempted
 * hypothesis of this kind was rejected because the TOTAL
 * pool was full, NOT that this kind filled the pool).
 * Surfaces which kind dominates cmp_hyp_kind_full so the
 * CMP_HYP_PER_KIND cap can be tuned at the right kind, and
 * which kinds are most often the would-be insertion when
 * CMP_HYP_PER_SYSCALL is reached. */
static void kcov_cmp_render_hyp_shadow_per_kind_census(void)
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
			&kcov_shm->cmp_hyp_inserted_by_kind[k],
			__ATOMIC_RELAXED);
		unsigned long cur_full = __atomic_load_n(
			&kcov_shm->cmp_hyp_kind_full_by_kind[k],
			__ATOMIC_RELAXED);
		unsigned long cur_pool_full = __atomic_load_n(
			&kcov_shm->cmp_hyp_pool_full_by_kind[k],
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
static void kcov_cmp_render_hyp_shadow_consumes_census(void)
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
			&kcov_shm->cmp_hyp_consumed_by_kind[k],
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
static void kcov_cmp_render_hyp_shadow_picker_census(void)
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
static void kcov_cmp_render_hyp_shadow_state_transitions(void)
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
static void kcov_cmp_render_hyp_shadow_outcome_partition(void)
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

static void kcov_cmp_render_hyp_shadow_stats_block(long elapsed)
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
		__atomic_load_n(&kcov_shm->cmp_hyp_observations, __ATOMIC_RELAXED);
	unsigned long cur_hyp_inserted =
		__atomic_load_n(&kcov_shm->cmp_hyp_inserted, __ATOMIC_RELAXED);
	unsigned long cur_hyp_pool_full =
		__atomic_load_n(&kcov_shm->cmp_hyp_pool_full, __ATOMIC_RELAXED);
	unsigned long cur_hyp_pool_overflow =
		__atomic_load_n(&kcov_shm->cmp_hyp_pool_overflow, __ATOMIC_RELAXED);
	unsigned long cur_hyp_kind_full =
		__atomic_load_n(&kcov_shm->cmp_hyp_kind_full, __ATOMIC_RELAXED);
	unsigned long cur_hyp_consumed =
		__atomic_load_n(&kcov_shm->cmp_hyp_consumed, __ATOMIC_RELAXED);
	unsigned long cur_hyp_pc_wins =
		__atomic_load_n(&kcov_shm->cmp_hyp_pc_wins, __ATOMIC_RELAXED);
	unsigned long cur_hyp_transition_wins =
		__atomic_load_n(&kcov_shm->cmp_hyp_transition_wins, __ATOMIC_RELAXED);
	unsigned long cur_hyp_cmp_novelty_wins =
		__atomic_load_n(&kcov_shm->cmp_hyp_cmp_novelty_wins, __ATOMIC_RELAXED);
	unsigned long cur_hyp_misses =
		__atomic_load_n(&kcov_shm->cmp_hyp_misses, __ATOMIC_RELAXED);
	unsigned long cur_hyp_disabled_skips =
		__atomic_load_n(&kcov_shm->cmp_hyp_disabled_skips, __ATOMIC_RELAXED);
	unsigned long cur_hyp_corpus_save =
		__atomic_load_n(&kcov_shm->cmp_hyp_corpus_save, __ATOMIC_RELAXED);
	unsigned long cur_hyp_destructive =
		__atomic_load_n(&kcov_shm->cmp_hyp_destructive, __ATOMIC_RELAXED);
	unsigned long cur_hyp_context_skip =
		__atomic_load_n(&kcov_shm->cmp_hyp_context_skip, __ATOMIC_RELAXED);
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
static void kcov_cmp_render_hyp_would_pick_block(long elapsed __unused__)
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
			&kcov_shm->cmp_hyp_would_pick_by_kind[k],
			__ATOMIC_RELAXED);
		cur_hyp_would_miss_kind[k] = __atomic_load_n(
			&kcov_shm->cmp_hyp_would_miss_by_kind[k],
			__ATOMIC_RELAXED);
		cur_hyp_would_value_differs_kind[k] = __atomic_load_n(
			&kcov_shm->cmp_hyp_would_value_differs_by_kind[k],
			__ATOMIC_RELAXED);
		any_would_delta |=
			sat_sub_ul(cur_hyp_would_pick_kind[k], prev_hyp_would_pick_kind[k]) |
			sat_sub_ul(cur_hyp_would_miss_kind[k], prev_hyp_would_miss_kind[k]) |
			sat_sub_ul(cur_hyp_would_value_differs_kind[k],
				   prev_hyp_would_value_differs_kind[k]);
	}
	cur_hyp_would_value_differs = __atomic_load_n(
		&kcov_shm->cmp_hyp_would_value_differs, __ATOMIC_RELAXED);
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
static void kcov_cmp_render_childop_cmp_consume_shadow_block(long elapsed __unused__)
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
			&kcov_shm->childop_cmp_consume_would_pick[i],
			__ATOMIC_RELAXED);
		cur_would_miss += __atomic_load_n(
			&kcov_shm->childop_cmp_consume_would_miss[i],
			__ATOMIC_RELAXED);
		cur_would_value_differs += __atomic_load_n(
			&kcov_shm->childop_cmp_consume_would_value_differs[i],
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
static void kcov_cmp_render_hyp_would_promote_demote_block(long elapsed __unused__)
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
static void kcov_cmp_render_hyp_live_inject_block(long elapsed __unused__)
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
		&kcov_shm->cmp_hyp_live_injected, __ATOMIC_RELAXED);
	unsigned long cur_hyp_live_gate_passed = __atomic_load_n(
		&kcov_shm->cmp_hyp_live_inject_gate_passed,
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
			&kcov_shm->cmp_hyp_live_injected_by_kind[k],
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
static void kcov_cmp_render_hyp_live_inject_reasons_block(long elapsed __unused__)
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
			&kcov_shm->cmp_hyp_live_inject_reason[r],
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
static void kcov_cmp_render_hyp_boundary_scorecard_block(long elapsed __unused__)
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
		&kcov_shm->cmp_hyp_would_pick_by_kind[CMP_HYP_BOUNDARY],
		__ATOMIC_RELAXED);
	unsigned long cur_b_would_miss = __atomic_load_n(
		&kcov_shm->cmp_hyp_would_miss_by_kind[CMP_HYP_BOUNDARY],
		__ATOMIC_RELAXED);
	unsigned long cur_b_live_injected = __atomic_load_n(
		&kcov_shm->cmp_hyp_live_injected_by_kind[CMP_HYP_BOUNDARY],
		__ATOMIC_RELAXED);
	unsigned long cur_b_consumed = __atomic_load_n(
		&kcov_shm->cmp_hyp_consumed_by_kind[CMP_HYP_BOUNDARY],
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
static void kcov_cmp_render_hyp_per_hypothesis_aggregates_block(long elapsed)
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
static void kcov_cmp_render_hyp_score_bucket_block(long elapsed __unused__)
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
static void kcov_cmp_render_hyp_probe_class_hist_block(long elapsed __unused__)
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

/*
 * Per-mode child population (cumulative).  Realised PC/CMP mode mix in the
 * time series so the operator can read the split at each dump window rather
 * than only at shutdown.
 */
static void kcov_cmp_render_modes_block(void)
{
	unsigned int pc_kids, cmp_kids;

	pc_kids  = __atomic_load_n(&kcov_shm->pc_mode_children,  __ATOMIC_RELAXED);
	cmp_kids = __atomic_load_n(&kcov_shm->cmp_mode_children, __ATOMIC_RELAXED);

	if ((pc_kids | cmp_kids) != 0) {
		stats_log_write("KCOV CMP modes (cumulative):\n");
		stats_log_write("  pc_mode_children=%u cmp_mode_children=%u\n",
				pc_kids, cmp_kids);
	}
}

static void kcov_cmp_render_diag_errnos_block(void)
{
	char init_buf[256];
	char rt_buf[256];
	int ni, nr;

	ni = kcov_cmp_diag_format(init_buf, sizeof(init_buf),
				  KCOV_CMP_DIAG_INIT);
	nr = kcov_cmp_diag_format(rt_buf, sizeof(rt_buf),
				  KCOV_CMP_DIAG_RUNTIME);

	if (ni > 0 || nr > 0) {
		stats_log_write("KCOV CMP DIAG errnos (first-failure-wins, cumulative count):\n");
		if (ni > 0)
			stats_log_write(" %s\n", init_buf);
		if (nr > 0)
			stats_log_write(" %s\n", rt_buf);
	}
}

static void kcov_cmp_render_pc_diag_block(void)
{
	char pc_buf[256];
	int np;

	np = kcov_pc_diag_format(pc_buf, sizeof(pc_buf));
	if (np > 0) {
		stats_log_write("KCOV PC DIAG (first-failure-wins errnos + retry counters, cumulative):\n");
		stats_log_write(" %s\n", pc_buf);
	}
}

static void kcov_cmp_render_reexec_skip_reason_breakdown(long elapsed,
							 unsigned long delta_reexec_gate_skip_in_reexec, unsigned long cur_reexec_gate_skip_in_reexec,
							 unsigned long delta_reexec_gate_skip_disabled, unsigned long cur_reexec_gate_skip_disabled,
							 unsigned long delta_reexec_gate_skip_mode, unsigned long cur_reexec_gate_skip_mode,
							 unsigned long delta_reexec_gate_skip_chain_mid, unsigned long cur_reexec_gate_skip_chain_mid,
							 unsigned long delta_reexec_gate_skip_no_new_cmp, unsigned long cur_reexec_gate_skip_no_new_cmp,
							 unsigned long delta_reexec_gate_skip_no_pending, unsigned long cur_reexec_gate_skip_no_pending,
							 unsigned long delta_reexec_gate_skip_rate, unsigned long cur_reexec_gate_skip_rate,
							 unsigned long delta_reexec_gate_pass, unsigned long cur_reexec_gate_pass)
{
	/* Re-exec gate skip-reason breakdown.  Counters are mutually
	 * exclusive: every dispatch_step that reaches the tail bumps
	 * exactly one of {skip_in_reexec, skip_disabled, skip_mode,
	 * skip_chain_mid, skip_no_new_cmp, skip_no_pending, skip_rate,
	 * pass}.  The sum across the eight is the parent-call
	 * population the gate samples from -- read the per-reason
	 * fractions to see why reexec_attribution_found shrinks to
	 * reexec_attempts (rate-gate skip vs destructive vs pending-
	 * full vs pass), instead of inferring it from a single delta.
	 * Skip-row order mirrors the evaluation order in
	 * random-syscall.c so the funnel reads top-to-bottom. */
	kcov_cmp_rate_line(elapsed, "reexec_gate_skip_in_reexec", delta_reexec_gate_skip_in_reexec, cur_reexec_gate_skip_in_reexec);
	kcov_cmp_rate_line(elapsed, "reexec_gate_skip_disabled", delta_reexec_gate_skip_disabled, cur_reexec_gate_skip_disabled);
	kcov_cmp_rate_line(elapsed, "reexec_gate_skip_mode", delta_reexec_gate_skip_mode, cur_reexec_gate_skip_mode);
	kcov_cmp_rate_line(elapsed, "reexec_gate_skip_chain_mid", delta_reexec_gate_skip_chain_mid, cur_reexec_gate_skip_chain_mid);
	kcov_cmp_rate_line(elapsed, "reexec_gate_skip_no_new_cmp", delta_reexec_gate_skip_no_new_cmp, cur_reexec_gate_skip_no_new_cmp);
	kcov_cmp_rate_line(elapsed, "reexec_gate_skip_no_pending", delta_reexec_gate_skip_no_pending, cur_reexec_gate_skip_no_pending);
	kcov_cmp_rate_line(elapsed, "reexec_gate_skip_rate", delta_reexec_gate_skip_rate, cur_reexec_gate_skip_rate);
	kcov_cmp_rate_line(elapsed, "reexec_gate_pass", delta_reexec_gate_pass, cur_reexec_gate_pass);
}

static void kcov_cmp_render_per_entry_feedback_scoring(long elapsed,
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

static void kcov_cmp_render_recent_cmp_pool_tier(long elapsed,
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

static void kcov_cmp_render_ab_baseline_inject_denom(long elapsed,
						     unsigned long delta_cmp_inject_arm_a_baseline_fires, unsigned long cur_cmp_inject_arm_a_baseline_fires,
						     unsigned long delta_cmp_inject_arm_b_baseline_fires, unsigned long cur_cmp_inject_arm_b_baseline_fires,
						     unsigned long delta_cmp_inject_denom_diverged, unsigned long cur_cmp_inject_denom_diverged,
						     unsigned int cur_cmp_inject_arm_a_children,
						     unsigned int cur_cmp_inject_arm_b_children)
{
	/* A/B baseline inject denom (Arm A = 16, Arm B = 12).  Print
	 * the realised cohort split + per-arm baseline-fire deltas +
	 * the per-call divergence count so the operator can size the
	 * A/B effect on PC-edge yield against population-normalised
	 * fire rates without recomputing from cmp_hint_callsite[]. */
	if (delta_cmp_inject_arm_a_baseline_fires) {
		unsigned long rate_milli = (delta_cmp_inject_arm_a_baseline_fires * 1000UL) / (unsigned long)elapsed;
		stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu, children %u)\n",
				"cmp_inject_arm_a_baseline_fires",
				delta_cmp_inject_arm_a_baseline_fires,
				rate_milli / 1000, rate_milli % 1000,
				cur_cmp_inject_arm_a_baseline_fires,
				cur_cmp_inject_arm_a_children);
	}
	if (delta_cmp_inject_arm_b_baseline_fires) {
		unsigned long rate_milli = (delta_cmp_inject_arm_b_baseline_fires * 1000UL) / (unsigned long)elapsed;
		stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu, children %u)\n",
				"cmp_inject_arm_b_baseline_fires",
				delta_cmp_inject_arm_b_baseline_fires,
				rate_milli / 1000, rate_milli % 1000,
				cur_cmp_inject_arm_b_baseline_fires,
				cur_cmp_inject_arm_b_children);
	}
	kcov_cmp_rate_line(elapsed, "cmp_inject_denom_diverged", delta_cmp_inject_denom_diverged, cur_cmp_inject_denom_diverged);
}

static void kcov_cmp_render_handle_arg_op_prop_ring_cohort(long elapsed,
							   unsigned long delta_prop_ring_argop_arm_b_fires,
							   unsigned long cur_prop_ring_argop_arm_b_fires,
							   unsigned int cur_prop_ring_argop_arm_a_children,
							   unsigned int cur_prop_ring_argop_arm_b_children)
{
	/* A/B handle_arg_op prop_ring cohort (Arm A = no pull, Arm B =
	 * low-prob pull).  Print the realised cohort split + the Arm B
	 * fire delta so the operator can size the per-row contribution
	 * to propagation_injected against the population-normalised fire
	 * rate.  Arm A has no symmetric fire counter by design (control
	 * arm skips the pull entirely). */
	if (delta_prop_ring_argop_arm_b_fires) {
		unsigned long rate_milli = (delta_prop_ring_argop_arm_b_fires * 1000UL) / (unsigned long)elapsed;
		stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu, children a=%u b=%u)\n",
				"prop_ring_argop_arm_b_fires",
				delta_prop_ring_argop_arm_b_fires,
				rate_milli / 1000, rate_milli % 1000,
				cur_prop_ring_argop_arm_b_fires,
				cur_prop_ring_argop_arm_a_children,
				cur_prop_ring_argop_arm_b_children);
	}
}

static void kcov_cmp_render_frontier_cold_weight_blend_cohort(long elapsed,
							      unsigned long delta_frontier_blend_samples,
							      unsigned long cur_frontier_blend_samples,
							      unsigned int cur_frontier_blend_arm_a_children,
							      unsigned int cur_frontier_blend_arm_b_children)
{
	/* frontier_cold_weight blend A/B cohort (Arm A = return historical
	 * OLD weight, Arm B = promote blended weight including the
	 * transition term to the picker).  Both arms fire the would-be
	 * divergence sampler frontier_blend_samples in lock-step, so the
	 * delta gate uses that fire counter and the row prints the
	 * realised cohort split as the denominator the operator
	 * normalises the live Arm B promotion against.  Neither arm has
	 * a per-arm fire counter by design -- the blend logic itself is
	 * untouched. */
	if (delta_frontier_blend_samples) {
		unsigned long rate_milli = (delta_frontier_blend_samples * 1000UL) / (unsigned long)elapsed;
		stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu, children a=%u b=%u)\n",
				"frontier_blend_samples",
				delta_frontier_blend_samples,
				rate_milli / 1000, rate_milli % 1000,
				cur_frontier_blend_samples,
				cur_frontier_blend_arm_a_children,
				cur_frontier_blend_arm_b_children);
	}
}

static void kcov_cmp_render_adaptive_remote_kcov_cohort(long elapsed,
							unsigned long delta_remote_adaptive_samples,
							unsigned long cur_remote_adaptive_samples,
							unsigned int cur_remote_adaptive_arm_a_children,
							unsigned int cur_remote_adaptive_arm_b_children,
							unsigned long cur_remote_adaptive_would_demote,
							unsigned long cur_remote_adaptive_would_promote,
							unsigned long cur_remote_adaptive_would_force,
							unsigned long cur_remote_adaptive_would_gate_promote,
							unsigned long cur_remote_adaptive_agree)
{
	/* Adaptive remote-KCOV mode A/B cohort (Arm A = static remote-
	 * mode policy / byte-identical to pre-row baseline, Arm B = the
	 * adaptive demote/promote disposition from
	 * remote_adaptive_decide() substituted as the live remote_mode).
	 * Both arms feed the would-be disposition counters in lock-
	 * step, so the headline samples row uses the realised cohort
	 * split as the denominator the operator normalises the Arm-B-
	 * only live divergence against.  The three sub-rows print
	 * unconditionally inside the gate so the breakdown is visible
	 * even on windows where one disposition is zero (the absence
	 * itself is the diagnostic signal). */
	if (delta_remote_adaptive_samples) {
		unsigned long rate_milli = (delta_remote_adaptive_samples * 1000UL) / (unsigned long)elapsed;
		stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu, children a=%u b=%u)\n",
				"remote_adaptive_samples",
				delta_remote_adaptive_samples,
				rate_milli / 1000, rate_milli % 1000,
				cur_remote_adaptive_samples,
				cur_remote_adaptive_arm_a_children,
				cur_remote_adaptive_arm_b_children);
		stats_log_write("  %-32s total %lu\n",
				"remote_adaptive_would_demote",
				cur_remote_adaptive_would_demote);
		stats_log_write("  %-32s total %lu\n",
				"remote_adaptive_would_promote",
				cur_remote_adaptive_would_promote);
		stats_log_write("  %-32s total %lu\n",
				"remote_adaptive_would_force",
				cur_remote_adaptive_would_force);
		stats_log_write("  %-32s total %lu\n",
				"remote_adaptive_would_gate_promote",
				cur_remote_adaptive_would_gate_promote);
		stats_log_write("  %-32s total %lu\n",
				"remote_adaptive_agree",
				cur_remote_adaptive_agree);
	}
}

static void kcov_cmp_render_per_arg_ownership_sidecar(unsigned long cur_blanket_address_scrub_slots_walked,
						      unsigned long cur_arg_meta_addr_with_meta,
						      unsigned long cur_arg_meta_addr_without_meta,
						      unsigned long cur_arg_meta_argtype_stale,
						      unsigned long cur_arg_meta_scrub_would_destroy_in,
						      unsigned long cur_arg_meta_scrub_would_preserve_out)
{
	/* SHADOW per-arg ownership-metadata sidecar + blanket-scrub
	 * contradiction census.  Telemetry only -- the arg_meta_init
	 * seed pass and blanket_address_scrub walk are byte-unchanged;
	 * no live decision reads dir/owner/flags.  Cumulative totals
	 * (no per-window delta) match the remote_adaptive_would_*
	 * neighbours above: the shadow PROOF here is the ratio between
	 * the with_meta / without_meta rows and the destroy_in /
	 * preserve_out skew the operator is sizing future metadata-
	 * aware scrub coverage against.  Unconditional render so the
	 * baseline (all zero until per-generator coverage populates
	 * dir/owner) is itself visible. */
	stats_log_write("  %-32s total %lu\n",
			"blanket_address_scrub_slots_walked",
			cur_blanket_address_scrub_slots_walked);
	stats_log_write("  %-32s total %lu\n",
			"arg_meta_addr_with_meta",
			cur_arg_meta_addr_with_meta);
	stats_log_write("  %-32s total %lu\n",
			"arg_meta_addr_without_meta",
			cur_arg_meta_addr_without_meta);
	stats_log_write("  %-32s total %lu\n",
			"arg_meta_argtype_stale",
			cur_arg_meta_argtype_stale);
	stats_log_write("  %-32s total %lu\n",
			"arg_meta_scrub_would_destroy_in",
			cur_arg_meta_scrub_would_destroy_in);
	stats_log_write("  %-32s total %lu\n",
			"arg_meta_scrub_would_preserve_out",
			cur_arg_meta_scrub_would_preserve_out);
}

static void kcov_cmp_render_structure_aware_picker_cohort(long elapsed,
							  unsigned long delta_mut_structured_shadow_divergences,
							  unsigned long cur_mut_structured_shadow_divergences,
							  unsigned long cur_mut_structured_shadow_samples,
							  unsigned int cur_mut_structured_arm_a_children,
							  unsigned int cur_mut_structured_arm_b_children)
{
	/* SHADOW structure-aware picker A/B cohort (Arm A = no shadow
	 * draw / RNG byte-identical to pre-shadow control, Arm B =
	 * doubled-pool shadow draw on structured-eligible slots).  Print
	 * the Arm B divergence delta paired with the cumulative sample
	 * base and the realised cohort split so the operator can size
	 * the shadow's per-window steer-rate against the population-
	 * normalised denominator.  Arm A has no symmetric divergence
	 * counter by design (control arm skips the shadow draw entirely);
	 * samples and divergences are both Arm-B-only accumulators. */
	if (delta_mut_structured_shadow_divergences) {
		unsigned long rate_milli = (delta_mut_structured_shadow_divergences * 1000UL) / (unsigned long)elapsed;
		stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu, samples %lu, children a=%u b=%u)\n",
				"mut_structured_shadow_divergences",
				delta_mut_structured_shadow_divergences,
				rate_milli / 1000, rate_milli % 1000,
				cur_mut_structured_shadow_divergences,
				cur_mut_structured_shadow_samples,
				cur_mut_structured_arm_a_children,
				cur_mut_structured_arm_b_children);
	}
}

/*
 * Surface the KCOV CMP counters in the same 600s periodic stats-log-file
 * dump as periodic_counter_rates_dump.  Without this the cmp counters
 * are only visible from dump_stats() (run shutdown) and the JSON dump
 * (on enable), so a long overnight run produces no time-series — just a
 * single end-snapshot — making it impossible to correlate cmp_hints
 * effectiveness with edge-discovery cadence over the run.
 *
 * Three sub-blocks, each gated independently so a healthy run that has
 * no DIAG errnos doesn't carry an empty "DIAG:" line into the log:
 *  - per-window deltas + rates + cumulative totals for the three cmp
 *    counters, formatted to match periodic_counter_rates_dump;
 *  - per-mode child population (cumulative) so the realised PC/CMP
 *    mode mix is visible in the time series, not just at shutdown;
 *  - first-failure-wins errno/count per cmp-init/runtime site.
 */
void __cold kcov_cmp_stats_periodic_dump(void)
{
	static unsigned long prev_records;
	static unsigned long prev_truncated;
	static unsigned long prev_bloom_skipped;
	static unsigned long prev_strip_skipped;
	static unsigned long prev_unique;
	static unsigned long prev_try_get_attempts;
	static unsigned long prev_try_get_returned;
	static unsigned long prev_injected;
	static unsigned long prev_prop_injected;
	static unsigned long prev_chaos_suppressed;
	static unsigned long prev_count_oob;
	static unsigned long prev_canary_lock_post;
	static unsigned long prev_canary_pre;
	static unsigned long prev_canary_post;
	static unsigned long prev_reexec_attempts;
	static unsigned long prev_reexec_attempts_with_new_cmp;
	static unsigned long prev_reexec_attribution_found;
	static unsigned long prev_reexec_attribution_ambiguous;
	static unsigned long prev_reexec_attribution_width_match;
	static unsigned long prev_reexec_new_cmps_total;
	static unsigned long prev_reexec_new_edges_total;
	static unsigned long prev_reexec_attempts_by_arm[2];
	static unsigned long prev_reexec_new_cmps_by_arm[2];
	static unsigned long prev_reexec_new_edges_by_arm[2];
	static unsigned long prev_reexec_skipped_destructive;
	static unsigned long prev_reexec_skipped_validate_silent;
	static unsigned long prev_reexec_window_cap_hit;
	static unsigned long prev_reexec_pending_dropped;
	static unsigned long prev_reexec_gate_skip_in_reexec;
	static unsigned long prev_reexec_gate_skip_disabled;
	static unsigned long prev_reexec_gate_skip_mode;
	static unsigned long prev_reexec_gate_skip_chain_mid;
	static unsigned long prev_reexec_gate_skip_no_new_cmp;
	static unsigned long prev_reexec_gate_skip_no_pending;
	static unsigned long prev_reexec_gate_skip_rate;
	static unsigned long prev_reexec_gate_pass;
	static unsigned long prev_cmp_parent_calls_enabled;
	static unsigned long prev_cmp_parent_calls_control;
	static unsigned long prev_cmp_parent_new_cmps_enabled;
	static unsigned long prev_cmp_parent_new_cmps_control;
	static unsigned long prev_cmp_hint_callsite[CMP_HINT_CALLSITE_NR];
	static unsigned long prev_cmp_hint_callsite_pc_wins[CMP_HINT_CALLSITE_NR];
	static unsigned long prev_cmp_hint_callsite_misses[CMP_HINT_CALLSITE_NR];
	static unsigned long prev_prop_injected_callsite[PROP_INJECTED_CALLSITE_NR];
	static unsigned long prev_save_reject_nonconst;
	static unsigned long prev_save_reject_uninteresting;
	static unsigned long prev_save_reject_sentinel;
	static unsigned long prev_save_reject_dup;
	static unsigned long prev_save_reject_cap;
	static unsigned long prev_cmp_hints_consumed;
	static unsigned long prev_cmp_hint_wins;
	static unsigned long prev_cmp_hint_misses;
	static unsigned long prev_cmp_hint_cmp_novelty_wins;
	static unsigned long prev_cmp_hint_stash_overflow;
	static unsigned long prev_cmp_hint_credit_entry_evicted;
	static unsigned long prev_cmp_recent_inserts;
	static unsigned long prev_cmp_recent_evicts;
	static unsigned long prev_cmp_recent_would_pick;
	static unsigned long prev_cmp_recent_would_miss;
	static unsigned long prev_cmp_recent_live_picks;
	static unsigned long prev_cmp_inject_arm_a_baseline_fires;
	static unsigned long prev_cmp_inject_arm_b_baseline_fires;
	static unsigned long prev_cmp_inject_denom_diverged;
	static unsigned long prev_prop_ring_argop_arm_b_fires;
	static unsigned long prev_frontier_blend_samples;
	static unsigned long prev_remote_adaptive_samples;
	static unsigned long prev_mut_structured_shadow_divergences;
	static struct timespec last_dump;
	struct timespec now;
	long elapsed;
	unsigned long cur_records, cur_truncated, cur_bloom_skipped, cur_unique;
	unsigned long cur_strip_skipped;
	unsigned long cur_try_get_attempts, cur_try_get_returned, cur_injected;
	unsigned long cur_prop_injected;
	unsigned long cur_chaos_suppressed;
	unsigned long cur_count_oob, cur_canary_lock_post, cur_canary_pre, cur_canary_post;
	unsigned long cur_reexec_attempts, cur_reexec_attribution_found;
	unsigned long cur_reexec_attempts_with_new_cmp;
	unsigned long cur_reexec_attribution_ambiguous, cur_reexec_new_cmps_total;
	unsigned long cur_reexec_new_edges_total;
	unsigned long cur_reexec_attempts_by_arm[2];
	unsigned long cur_reexec_new_cmps_by_arm[2];
	unsigned long cur_reexec_new_edges_by_arm[2];
	unsigned long cur_reexec_attribution_width_match;
	unsigned long cur_reexec_skipped_destructive, cur_reexec_skipped_validate_silent;
	unsigned long cur_reexec_window_cap_hit;
	unsigned long cur_reexec_pending_dropped;
	unsigned long cur_reexec_gate_skip_in_reexec;
	unsigned long cur_reexec_gate_skip_disabled;
	unsigned long cur_reexec_gate_skip_mode;
	unsigned long cur_reexec_gate_skip_chain_mid;
	unsigned long cur_reexec_gate_skip_no_new_cmp;
	unsigned long cur_reexec_gate_skip_no_pending;
	unsigned long cur_reexec_gate_skip_rate;
	unsigned long cur_reexec_gate_pass;
	unsigned long cur_cmp_parent_calls_enabled, cur_cmp_parent_calls_control;
	unsigned long cur_cmp_parent_new_cmps_enabled, cur_cmp_parent_new_cmps_control;
	unsigned long cur_cmp_hint_callsite[CMP_HINT_CALLSITE_NR];
	unsigned long cur_cmp_hint_callsite_pc_wins[CMP_HINT_CALLSITE_NR];
	unsigned long cur_cmp_hint_callsite_misses[CMP_HINT_CALLSITE_NR];
	unsigned long cur_prop_injected_callsite[PROP_INJECTED_CALLSITE_NR];
	unsigned long cur_save_reject_nonconst, cur_save_reject_uninteresting;
	unsigned long cur_save_reject_sentinel, cur_save_reject_dup, cur_save_reject_cap;
	unsigned long delta_save_reject_nonconst, delta_save_reject_uninteresting;
	unsigned long delta_save_reject_sentinel, delta_save_reject_dup, delta_save_reject_cap;
	unsigned long delta_records, delta_truncated, delta_bloom_skipped, delta_unique;
	unsigned long delta_strip_skipped;
	unsigned long delta_try_get_attempts, delta_try_get_returned, delta_injected;
	unsigned long delta_prop_injected;
	unsigned long delta_chaos_suppressed;
	unsigned long delta_count_oob, delta_canary_lock_post, delta_canary_pre, delta_canary_post;
	unsigned long delta_reexec_attempts, delta_reexec_attribution_found;
	unsigned long delta_reexec_attempts_with_new_cmp;
	unsigned long delta_reexec_attribution_ambiguous, delta_reexec_new_cmps_total;
	unsigned long delta_reexec_new_edges_total;
	unsigned long delta_reexec_attempts_by_arm[2];
	unsigned long delta_reexec_new_cmps_by_arm[2];
	unsigned long delta_reexec_new_edges_by_arm[2];
	unsigned long delta_reexec_attribution_width_match;
	unsigned long delta_reexec_skipped_destructive, delta_reexec_skipped_validate_silent;
	unsigned long delta_reexec_window_cap_hit;
	unsigned long delta_reexec_pending_dropped;
	unsigned long delta_reexec_gate_skip_in_reexec;
	unsigned long delta_reexec_gate_skip_disabled;
	unsigned long delta_reexec_gate_skip_mode;
	unsigned long delta_reexec_gate_skip_chain_mid;
	unsigned long delta_reexec_gate_skip_no_new_cmp;
	unsigned long delta_reexec_gate_skip_no_pending;
	unsigned long delta_reexec_gate_skip_rate;
	unsigned long delta_reexec_gate_pass;
	unsigned long delta_cmp_parent_calls_enabled, delta_cmp_parent_calls_control;
	unsigned long delta_cmp_parent_new_cmps_enabled, delta_cmp_parent_new_cmps_control;
	unsigned long delta_cmp_hint_callsite[CMP_HINT_CALLSITE_NR];
	unsigned long delta_cmp_hint_callsite_pc_wins[CMP_HINT_CALLSITE_NR];
	unsigned long delta_cmp_hint_callsite_misses[CMP_HINT_CALLSITE_NR];
	unsigned long delta_prop_injected_callsite[PROP_INJECTED_CALLSITE_NR];
	unsigned long cur_cmp_hints_consumed, cur_cmp_hint_wins, cur_cmp_hint_misses;
	unsigned long cur_cmp_hint_cmp_novelty_wins;
	unsigned long cur_cmp_hint_stash_overflow, cur_cmp_hint_credit_entry_evicted;
	unsigned long cur_cmp_recent_inserts, cur_cmp_recent_evicts;
	unsigned long cur_cmp_recent_would_pick, cur_cmp_recent_would_miss;
	unsigned long cur_cmp_recent_live_picks;
	unsigned long delta_cmp_hints_consumed, delta_cmp_hint_wins, delta_cmp_hint_misses;
	unsigned long delta_cmp_hint_cmp_novelty_wins;
	unsigned long delta_cmp_hint_stash_overflow, delta_cmp_hint_credit_entry_evicted;
	unsigned long delta_cmp_recent_inserts, delta_cmp_recent_evicts;
	unsigned long delta_cmp_recent_would_pick, delta_cmp_recent_would_miss;
	unsigned long delta_cmp_recent_live_picks;
	unsigned long cur_cmp_inject_arm_a_baseline_fires, cur_cmp_inject_arm_b_baseline_fires;
	unsigned long cur_cmp_inject_denom_diverged;
	unsigned long delta_cmp_inject_arm_a_baseline_fires, delta_cmp_inject_arm_b_baseline_fires;
	unsigned long delta_cmp_inject_denom_diverged;
	unsigned int  cur_cmp_inject_arm_a_children, cur_cmp_inject_arm_b_children;
	unsigned long cur_prop_ring_argop_arm_b_fires, delta_prop_ring_argop_arm_b_fires;
	unsigned int  cur_prop_ring_argop_arm_a_children, cur_prop_ring_argop_arm_b_children;
	unsigned long cur_frontier_blend_samples, delta_frontier_blend_samples;
	unsigned int  cur_frontier_blend_arm_a_children, cur_frontier_blend_arm_b_children;
	unsigned long cur_remote_adaptive_samples, delta_remote_adaptive_samples;
	unsigned long cur_remote_adaptive_would_demote;
	unsigned long cur_remote_adaptive_would_promote;
	unsigned long cur_remote_adaptive_would_force;
	unsigned long cur_remote_adaptive_would_gate_promote;
	unsigned long cur_remote_adaptive_agree;
	unsigned long cur_arg_meta_addr_with_meta;
	unsigned long cur_arg_meta_addr_without_meta;
	unsigned long cur_arg_meta_argtype_stale;
	unsigned long cur_arg_meta_scrub_would_destroy_in;
	unsigned long cur_arg_meta_scrub_would_preserve_out;
	unsigned long cur_blanket_address_scrub_slots_walked;
	unsigned int  cur_remote_adaptive_arm_a_children, cur_remote_adaptive_arm_b_children;
	unsigned long cur_mut_structured_shadow_samples;
	unsigned long cur_mut_structured_shadow_divergences;
	unsigned long delta_mut_structured_shadow_divergences;
	unsigned int  cur_mut_structured_arm_a_children, cur_mut_structured_arm_b_children;
	bool any_callsite_delta = false;
	bool any_callsite_wins_delta = false;
	bool any_prop_callsite_delta = false;

	if (kcov_shm == NULL)
		return;

	clock_gettime(CLOCK_MONOTONIC, &now);

	cur_records       = __atomic_load_n(&kcov_shm->cmp_records_collected,   __ATOMIC_RELAXED);
	cur_truncated     = __atomic_load_n(&kcov_shm->cmp_trace_truncated,     __ATOMIC_RELAXED);
	cur_bloom_skipped = __atomic_load_n(&kcov_shm->cmp_hints_bloom_skipped, __ATOMIC_RELAXED);
	cur_strip_skipped = __atomic_load_n(&kcov_shm->cmp_hints_strip_skipped, __ATOMIC_RELAXED);
	cur_unique        = __atomic_load_n(&kcov_shm->cmp_hints_unique_inserts, __ATOMIC_RELAXED);
	/* Source from parent_stats: cmp_hints_try_get_ex() now enqueues
	 * +1 per attempt/return via the per-child stats_ring; the kcov_shm
	 * scalars are gone, removing a fuzzer-visible wild-write target. */
	cur_try_get_attempts = parent_stats.cmp_hints_try_get_attempts;
	cur_try_get_returned = parent_stats.cmp_hints_try_get_returned;
	cur_injected         = __atomic_load_n(&kcov_shm->cmp_hints_injected,         __ATOMIC_RELAXED);
	cur_prop_injected    = __atomic_load_n(&kcov_shm->propagation_injected,       __ATOMIC_RELAXED);
	cur_chaos_suppressed = __atomic_load_n(&kcov_shm->cmp_hints_chaos_suppressed, __ATOMIC_RELAXED);
	cur_count_oob        = __atomic_load_n(&kcov_shm->cmp_hints_count_oob,               __ATOMIC_RELAXED);
	cur_canary_lock_post = __atomic_load_n(&kcov_shm->cmp_hints_canary_lock_post_corrupt, __ATOMIC_RELAXED);
	cur_canary_pre       = __atomic_load_n(&kcov_shm->cmp_hints_canary_pre_corrupt,      __ATOMIC_RELAXED);
	cur_canary_post      = __atomic_load_n(&kcov_shm->cmp_hints_canary_post_corrupt,     __ATOMIC_RELAXED);
	cur_reexec_attempts                = __atomic_load_n(&kcov_shm->reexec_attempts,                __ATOMIC_RELAXED);
	cur_reexec_attempts_with_new_cmp   = __atomic_load_n(&kcov_shm->reexec_attempts_with_new_cmp,   __ATOMIC_RELAXED);
	cur_reexec_attribution_found       = __atomic_load_n(&kcov_shm->reexec_attribution_found,       __ATOMIC_RELAXED);
	cur_reexec_attribution_ambiguous   = __atomic_load_n(&kcov_shm->reexec_attribution_ambiguous,   __ATOMIC_RELAXED);
	cur_reexec_attribution_width_match = __atomic_load_n(&kcov_shm->reexec_attribution_width_match, __ATOMIC_RELAXED);
	cur_reexec_new_cmps_total          = __atomic_load_n(&kcov_shm->reexec_new_cmps_total,          __ATOMIC_RELAXED);
	cur_reexec_new_edges_total         = __atomic_load_n(&kcov_shm->reexec_new_edges_total,         __ATOMIC_RELAXED);
	cur_reexec_attempts_by_arm[0]      = __atomic_load_n(&kcov_shm->reexec_attempts_by_arm[0],      __ATOMIC_RELAXED);
	cur_reexec_attempts_by_arm[1]      = __atomic_load_n(&kcov_shm->reexec_attempts_by_arm[1],      __ATOMIC_RELAXED);
	cur_reexec_new_cmps_by_arm[0]      = __atomic_load_n(&kcov_shm->reexec_new_cmps_by_arm[0],      __ATOMIC_RELAXED);
	cur_reexec_new_cmps_by_arm[1]      = __atomic_load_n(&kcov_shm->reexec_new_cmps_by_arm[1],      __ATOMIC_RELAXED);
	cur_reexec_new_edges_by_arm[0]     = __atomic_load_n(&kcov_shm->reexec_new_edges_by_arm[0],     __ATOMIC_RELAXED);
	cur_reexec_new_edges_by_arm[1]     = __atomic_load_n(&kcov_shm->reexec_new_edges_by_arm[1],     __ATOMIC_RELAXED);
	cur_reexec_skipped_destructive     = __atomic_load_n(&kcov_shm->reexec_skipped_destructive,     __ATOMIC_RELAXED);
	cur_reexec_skipped_validate_silent = __atomic_load_n(&kcov_shm->reexec_skipped_validate_silent, __ATOMIC_RELAXED);
	cur_reexec_window_cap_hit          = __atomic_load_n(&kcov_shm->reexec_window_cap_hit,          __ATOMIC_RELAXED);
	cur_reexec_pending_dropped         = __atomic_load_n(&kcov_shm->reexec_pending_dropped,         __ATOMIC_RELAXED);
	cur_reexec_gate_skip_in_reexec     = __atomic_load_n(&kcov_shm->reexec_gate_skip_in_reexec,     __ATOMIC_RELAXED);
	cur_reexec_gate_skip_disabled      = __atomic_load_n(&kcov_shm->reexec_gate_skip_disabled,      __ATOMIC_RELAXED);
	cur_reexec_gate_skip_mode          = __atomic_load_n(&kcov_shm->reexec_gate_skip_mode,          __ATOMIC_RELAXED);
	cur_reexec_gate_skip_chain_mid     = __atomic_load_n(&kcov_shm->reexec_gate_skip_chain_mid,     __ATOMIC_RELAXED);
	cur_reexec_gate_skip_no_new_cmp    = __atomic_load_n(&kcov_shm->reexec_gate_skip_no_new_cmp,    __ATOMIC_RELAXED);
	cur_reexec_gate_skip_no_pending    = __atomic_load_n(&kcov_shm->reexec_gate_skip_no_pending,    __ATOMIC_RELAXED);
	cur_reexec_gate_skip_rate          = __atomic_load_n(&kcov_shm->reexec_gate_skip_rate,          __ATOMIC_RELAXED);
	cur_reexec_gate_pass               = __atomic_load_n(&kcov_shm->reexec_gate_pass,               __ATOMIC_RELAXED);
	cur_cmp_parent_calls_enabled       = __atomic_load_n(&kcov_shm->cmp_parent_calls_enabled,       __ATOMIC_RELAXED);
	cur_cmp_parent_calls_control       = __atomic_load_n(&kcov_shm->cmp_parent_calls_control,       __ATOMIC_RELAXED);
	cur_cmp_parent_new_cmps_enabled    = __atomic_load_n(&kcov_shm->cmp_parent_new_cmps_enabled,    __ATOMIC_RELAXED);
	cur_cmp_parent_new_cmps_control    = __atomic_load_n(&kcov_shm->cmp_parent_new_cmps_control,    __ATOMIC_RELAXED);
	cur_save_reject_nonconst      = __atomic_load_n(&kcov_shm->cmp_hints_save_reject_nonconst,      __ATOMIC_RELAXED);
	cur_save_reject_uninteresting = __atomic_load_n(&kcov_shm->cmp_hints_save_reject_uninteresting, __ATOMIC_RELAXED);
	cur_save_reject_sentinel      = __atomic_load_n(&kcov_shm->cmp_hints_save_reject_sentinel,      __ATOMIC_RELAXED);
	cur_save_reject_dup           = __atomic_load_n(&kcov_shm->cmp_hints_save_reject_dup,           __ATOMIC_RELAXED);
	cur_save_reject_cap           = __atomic_load_n(&kcov_shm->cmp_hints_save_reject_cap,           __ATOMIC_RELAXED);
	{
		unsigned int cs;
		for (cs = 0; cs < CMP_HINT_CALLSITE_NR; cs++)
			cur_cmp_hint_callsite[cs] = __atomic_load_n(
				&kcov_shm->cmp_hint_callsite_injected[cs],
				__ATOMIC_RELAXED);
	}
	{
		unsigned int cs;
		for (cs = 0; cs < CMP_HINT_CALLSITE_NR; cs++) {
			cur_cmp_hint_callsite_pc_wins[cs] = __atomic_load_n(
				&kcov_shm->cmp_hint_callsite_pc_wins[cs],
				__ATOMIC_RELAXED);
			cur_cmp_hint_callsite_misses[cs] = __atomic_load_n(
				&kcov_shm->cmp_hint_callsite_misses[cs],
				__ATOMIC_RELAXED);
		}
	}
	{
		unsigned int cs;
		for (cs = 0; cs < PROP_INJECTED_CALLSITE_NR; cs++)
			cur_prop_injected_callsite[cs] = __atomic_load_n(
				&kcov_shm->propagation_injected_callsite[cs],
				__ATOMIC_RELAXED);
	}
	cur_cmp_hints_consumed             = __atomic_load_n(&kcov_shm->cmp_hints_consumed,             __ATOMIC_RELAXED);
	cur_cmp_hint_wins                  = __atomic_load_n(&kcov_shm->cmp_hint_wins,                  __ATOMIC_RELAXED);
	cur_cmp_hint_misses                = __atomic_load_n(&kcov_shm->cmp_hint_misses,                __ATOMIC_RELAXED);
	cur_cmp_hint_cmp_novelty_wins      = __atomic_load_n(&kcov_shm->cmp_hint_cmp_novelty_wins,      __ATOMIC_RELAXED);
	cur_cmp_hint_stash_overflow        = __atomic_load_n(&kcov_shm->cmp_hint_stash_overflow,        __ATOMIC_RELAXED);
	cur_cmp_hint_credit_entry_evicted  = __atomic_load_n(&kcov_shm->cmp_hint_credit_entry_evicted,  __ATOMIC_RELAXED);
	cur_cmp_recent_inserts             = __atomic_load_n(&kcov_shm->cmp_recent_inserts,             __ATOMIC_RELAXED);
	cur_cmp_recent_evicts              = __atomic_load_n(&kcov_shm->cmp_recent_evicts,              __ATOMIC_RELAXED);
	cur_cmp_recent_would_pick          = __atomic_load_n(&kcov_shm->cmp_recent_would_pick,          __ATOMIC_RELAXED);
	cur_cmp_recent_would_miss          = __atomic_load_n(&kcov_shm->cmp_recent_would_miss,          __ATOMIC_RELAXED);
	cur_cmp_recent_live_picks          = __atomic_load_n(&kcov_shm->cmp_recent_live_picks,          __ATOMIC_RELAXED);
	cur_cmp_inject_arm_a_baseline_fires = __atomic_load_n(&kcov_shm->cmp_inject_arm_a_baseline_fires, __ATOMIC_RELAXED);
	cur_cmp_inject_arm_b_baseline_fires = __atomic_load_n(&kcov_shm->cmp_inject_arm_b_baseline_fires, __ATOMIC_RELAXED);
	cur_cmp_inject_denom_diverged       = __atomic_load_n(&kcov_shm->cmp_inject_denom_diverged,       __ATOMIC_RELAXED);
	cur_cmp_inject_arm_a_children       = __atomic_load_n(&kcov_shm->cmp_inject_arm_a_children,       __ATOMIC_RELAXED);
	cur_cmp_inject_arm_b_children       = __atomic_load_n(&kcov_shm->cmp_inject_arm_b_children,       __ATOMIC_RELAXED);
	cur_prop_ring_argop_arm_b_fires     = __atomic_load_n(&kcov_shm->prop_ring_argop_arm_b_fires,     __ATOMIC_RELAXED);
	cur_prop_ring_argop_arm_a_children  = __atomic_load_n(&kcov_shm->prop_ring_argop_arm_a_children,  __ATOMIC_RELAXED);
	cur_prop_ring_argop_arm_b_children  = __atomic_load_n(&kcov_shm->prop_ring_argop_arm_b_children,  __ATOMIC_RELAXED);
	/* frontier_blend_samples lives in shm->stats (bumped per fire from
	 * both arms in lock-step), the cohort children counters live in
	 * kcov_shm (bumped once per child).  Read both here so the cohort
	 * dump row can be delta-gated on the fire counter, matching the
	 * prop_ring_argop template. */
	cur_frontier_blend_samples          = __atomic_load_n(&shm->stats.frontier.blend_samples,         __ATOMIC_RELAXED);
	cur_frontier_blend_arm_a_children   = __atomic_load_n(&kcov_shm->frontier_blend_arm_a_children,   __ATOMIC_RELAXED);
	cur_frontier_blend_arm_b_children   = __atomic_load_n(&kcov_shm->frontier_blend_arm_b_children,   __ATOMIC_RELAXED);
	cur_remote_adaptive_samples         = __atomic_load_n(&shm->stats.remote_adaptive_samples,        __ATOMIC_RELAXED);
	cur_remote_adaptive_would_demote    = __atomic_load_n(&shm->stats.remote_adaptive_would_demote,   __ATOMIC_RELAXED);
	cur_remote_adaptive_would_promote   = __atomic_load_n(&shm->stats.remote_adaptive_would_promote,  __ATOMIC_RELAXED);
	cur_remote_adaptive_would_force     = __atomic_load_n(&shm->stats.remote_adaptive_would_force,    __ATOMIC_RELAXED);
	cur_remote_adaptive_would_gate_promote = __atomic_load_n(&shm->stats.remote_adaptive_would_gate_promote, __ATOMIC_RELAXED);
	cur_remote_adaptive_agree           = __atomic_load_n(&shm->stats.remote_adaptive_agree,          __ATOMIC_RELAXED);
	cur_remote_adaptive_arm_a_children  = __atomic_load_n(&kcov_shm->remote_adaptive_arm_a_children,  __ATOMIC_RELAXED);
	cur_remote_adaptive_arm_b_children  = __atomic_load_n(&kcov_shm->remote_adaptive_arm_b_children,  __ATOMIC_RELAXED);
	cur_arg_meta_addr_with_meta            = __atomic_load_n(&shm->stats.arg.meta_addr_with_meta,            __ATOMIC_RELAXED);
	cur_arg_meta_addr_without_meta         = __atomic_load_n(&shm->stats.arg.meta_addr_without_meta,         __ATOMIC_RELAXED);
	cur_arg_meta_argtype_stale             = __atomic_load_n(&shm->stats.arg.meta_argtype_stale,             __ATOMIC_RELAXED);
	cur_arg_meta_scrub_would_destroy_in    = __atomic_load_n(&shm->stats.arg.meta_scrub_would_destroy_in,    __ATOMIC_RELAXED);
	cur_arg_meta_scrub_would_preserve_out  = __atomic_load_n(&shm->stats.arg.meta_scrub_would_preserve_out,  __ATOMIC_RELAXED);
	cur_blanket_address_scrub_slots_walked = __atomic_load_n(&shm->stats.blanket_address_scrub_slots_walked, __ATOMIC_RELAXED);
	/* SHADOW structure-aware picker A/B cohort + divergence counters live
	 * in minicorpus_shm rather than kcov_shm because the picker is a
	 * mutate_arg concern, not a kcov-cmp concern.  Guard the load so a
	 * degenerate run with kcov on but minicorpus unmapped does not chase
	 * a NULL pointer; the dump row's delta gate keeps a zero from
	 * polluting the kcov-cmp window output. */
	if (minicorpus_shm != NULL) {
		cur_mut_structured_shadow_samples     = __atomic_load_n(&minicorpus_shm->mut_structured_shadow_samples,     __ATOMIC_RELAXED);
		cur_mut_structured_shadow_divergences = __atomic_load_n(&minicorpus_shm->mut_structured_shadow_divergences, __ATOMIC_RELAXED);
		cur_mut_structured_arm_a_children     = __atomic_load_n(&minicorpus_shm->mut_structured_arm_a_children,     __ATOMIC_RELAXED);
		cur_mut_structured_arm_b_children     = __atomic_load_n(&minicorpus_shm->mut_structured_arm_b_children,     __ATOMIC_RELAXED);
	} else {
		cur_mut_structured_shadow_samples     = 0;
		cur_mut_structured_shadow_divergences = 0;
		cur_mut_structured_arm_a_children     = 0;
		cur_mut_structured_arm_b_children     = 0;
	}

	/* First call: arm the window so any pre-existing counts carried
	 * over from earlier in the run are not mis-attributed to the
	 * first window, mirroring periodic_counter_rates_dump. */
	if (last_dump.tv_sec == 0) {
		last_dump = now;
		prev_records       = cur_records;
		prev_truncated     = cur_truncated;
		prev_bloom_skipped = cur_bloom_skipped;
		prev_strip_skipped = cur_strip_skipped;
		prev_unique        = cur_unique;
		prev_try_get_attempts = cur_try_get_attempts;
		prev_try_get_returned = cur_try_get_returned;
		prev_injected         = cur_injected;
		prev_prop_injected    = cur_prop_injected;
		prev_chaos_suppressed = cur_chaos_suppressed;
		prev_count_oob        = cur_count_oob;
		prev_canary_lock_post = cur_canary_lock_post;
		prev_canary_pre       = cur_canary_pre;
		prev_canary_post      = cur_canary_post;
		prev_reexec_attempts                = cur_reexec_attempts;
		prev_reexec_attempts_with_new_cmp   = cur_reexec_attempts_with_new_cmp;
		prev_reexec_attribution_found       = cur_reexec_attribution_found;
		prev_reexec_attribution_ambiguous   = cur_reexec_attribution_ambiguous;
		prev_reexec_attribution_width_match = cur_reexec_attribution_width_match;
		prev_reexec_new_cmps_total          = cur_reexec_new_cmps_total;
		prev_reexec_new_edges_total         = cur_reexec_new_edges_total;
		prev_reexec_attempts_by_arm[0]      = cur_reexec_attempts_by_arm[0];
		prev_reexec_attempts_by_arm[1]      = cur_reexec_attempts_by_arm[1];
		prev_reexec_new_cmps_by_arm[0]      = cur_reexec_new_cmps_by_arm[0];
		prev_reexec_new_cmps_by_arm[1]      = cur_reexec_new_cmps_by_arm[1];
		prev_reexec_new_edges_by_arm[0]     = cur_reexec_new_edges_by_arm[0];
		prev_reexec_new_edges_by_arm[1]     = cur_reexec_new_edges_by_arm[1];
		prev_reexec_skipped_destructive     = cur_reexec_skipped_destructive;
		prev_reexec_skipped_validate_silent = cur_reexec_skipped_validate_silent;
		prev_reexec_window_cap_hit          = cur_reexec_window_cap_hit;
		prev_reexec_pending_dropped         = cur_reexec_pending_dropped;
		prev_reexec_gate_skip_in_reexec     = cur_reexec_gate_skip_in_reexec;
		prev_reexec_gate_skip_disabled      = cur_reexec_gate_skip_disabled;
		prev_reexec_gate_skip_mode          = cur_reexec_gate_skip_mode;
		prev_reexec_gate_skip_chain_mid     = cur_reexec_gate_skip_chain_mid;
		prev_reexec_gate_skip_no_new_cmp    = cur_reexec_gate_skip_no_new_cmp;
		prev_reexec_gate_skip_no_pending    = cur_reexec_gate_skip_no_pending;
		prev_reexec_gate_skip_rate          = cur_reexec_gate_skip_rate;
		prev_reexec_gate_pass               = cur_reexec_gate_pass;
		prev_cmp_parent_calls_enabled       = cur_cmp_parent_calls_enabled;
		prev_cmp_parent_calls_control       = cur_cmp_parent_calls_control;
		prev_cmp_parent_new_cmps_enabled    = cur_cmp_parent_new_cmps_enabled;
		prev_cmp_parent_new_cmps_control    = cur_cmp_parent_new_cmps_control;
		prev_save_reject_nonconst      = cur_save_reject_nonconst;
		prev_save_reject_uninteresting = cur_save_reject_uninteresting;
		prev_save_reject_sentinel      = cur_save_reject_sentinel;
		prev_save_reject_dup           = cur_save_reject_dup;
		prev_save_reject_cap           = cur_save_reject_cap;
		{
			unsigned int cs;
			for (cs = 0; cs < CMP_HINT_CALLSITE_NR; cs++) {
				prev_cmp_hint_callsite[cs] = cur_cmp_hint_callsite[cs];
				prev_cmp_hint_callsite_pc_wins[cs] =
					cur_cmp_hint_callsite_pc_wins[cs];
				prev_cmp_hint_callsite_misses[cs] =
					cur_cmp_hint_callsite_misses[cs];
			}
		}
		{
			unsigned int cs;
			for (cs = 0; cs < PROP_INJECTED_CALLSITE_NR; cs++)
				prev_prop_injected_callsite[cs] = cur_prop_injected_callsite[cs];
		}
		prev_cmp_hints_consumed             = cur_cmp_hints_consumed;
		prev_cmp_hint_wins                  = cur_cmp_hint_wins;
		prev_cmp_hint_misses                = cur_cmp_hint_misses;
		prev_cmp_hint_cmp_novelty_wins      = cur_cmp_hint_cmp_novelty_wins;
		prev_cmp_hint_stash_overflow        = cur_cmp_hint_stash_overflow;
		prev_cmp_hint_credit_entry_evicted  = cur_cmp_hint_credit_entry_evicted;
		prev_cmp_recent_inserts             = cur_cmp_recent_inserts;
		prev_cmp_recent_evicts              = cur_cmp_recent_evicts;
		prev_cmp_recent_would_pick          = cur_cmp_recent_would_pick;
		prev_cmp_recent_would_miss          = cur_cmp_recent_would_miss;
		prev_cmp_recent_live_picks          = cur_cmp_recent_live_picks;
		prev_cmp_inject_arm_a_baseline_fires = cur_cmp_inject_arm_a_baseline_fires;
		prev_cmp_inject_arm_b_baseline_fires = cur_cmp_inject_arm_b_baseline_fires;
		prev_cmp_inject_denom_diverged       = cur_cmp_inject_denom_diverged;
		prev_prop_ring_argop_arm_b_fires     = cur_prop_ring_argop_arm_b_fires;
		prev_frontier_blend_samples          = cur_frontier_blend_samples;
		prev_remote_adaptive_samples         = cur_remote_adaptive_samples;
		prev_mut_structured_shadow_divergences = cur_mut_structured_shadow_divergences;
		return;
	}

	elapsed = now.tv_sec - last_dump.tv_sec;
	if (elapsed < DEFENSE_DUMP_INTERVAL_SEC)
		return;

	delta_records       = sat_sub_ul(cur_records,       prev_records);
	delta_truncated     = sat_sub_ul(cur_truncated,     prev_truncated);
	delta_bloom_skipped = sat_sub_ul(cur_bloom_skipped, prev_bloom_skipped);
	delta_strip_skipped = sat_sub_ul(cur_strip_skipped, prev_strip_skipped);
	delta_unique        = sat_sub_ul(cur_unique,        prev_unique);
	delta_try_get_attempts = sat_sub_ul(cur_try_get_attempts, prev_try_get_attempts);
	delta_try_get_returned = sat_sub_ul(cur_try_get_returned, prev_try_get_returned);
	delta_injected         = sat_sub_ul(cur_injected,         prev_injected);
	delta_prop_injected    = sat_sub_ul(cur_prop_injected,    prev_prop_injected);
	delta_chaos_suppressed = sat_sub_ul(cur_chaos_suppressed, prev_chaos_suppressed);
	delta_count_oob        = sat_sub_ul(cur_count_oob,        prev_count_oob);
	delta_canary_lock_post = sat_sub_ul(cur_canary_lock_post, prev_canary_lock_post);
	delta_canary_pre       = sat_sub_ul(cur_canary_pre,       prev_canary_pre);
	delta_canary_post      = sat_sub_ul(cur_canary_post,      prev_canary_post);
	delta_reexec_attempts                = sat_sub_ul(cur_reexec_attempts,                prev_reexec_attempts);
	delta_reexec_attempts_with_new_cmp   = sat_sub_ul(cur_reexec_attempts_with_new_cmp,   prev_reexec_attempts_with_new_cmp);
	delta_reexec_attribution_found       = sat_sub_ul(cur_reexec_attribution_found,       prev_reexec_attribution_found);
	delta_reexec_attribution_ambiguous   = sat_sub_ul(cur_reexec_attribution_ambiguous,   prev_reexec_attribution_ambiguous);
	delta_reexec_attribution_width_match = sat_sub_ul(cur_reexec_attribution_width_match, prev_reexec_attribution_width_match);
	delta_reexec_new_cmps_total          = sat_sub_ul(cur_reexec_new_cmps_total,          prev_reexec_new_cmps_total);
	delta_reexec_new_edges_total         = sat_sub_ul(cur_reexec_new_edges_total,         prev_reexec_new_edges_total);
	delta_reexec_attempts_by_arm[0]      = sat_sub_ul(cur_reexec_attempts_by_arm[0],      prev_reexec_attempts_by_arm[0]);
	delta_reexec_attempts_by_arm[1]      = sat_sub_ul(cur_reexec_attempts_by_arm[1],      prev_reexec_attempts_by_arm[1]);
	delta_reexec_new_cmps_by_arm[0]      = sat_sub_ul(cur_reexec_new_cmps_by_arm[0],      prev_reexec_new_cmps_by_arm[0]);
	delta_reexec_new_cmps_by_arm[1]      = sat_sub_ul(cur_reexec_new_cmps_by_arm[1],      prev_reexec_new_cmps_by_arm[1]);
	delta_reexec_new_edges_by_arm[0]     = sat_sub_ul(cur_reexec_new_edges_by_arm[0],     prev_reexec_new_edges_by_arm[0]);
	delta_reexec_new_edges_by_arm[1]     = sat_sub_ul(cur_reexec_new_edges_by_arm[1],     prev_reexec_new_edges_by_arm[1]);
	delta_reexec_skipped_destructive     = sat_sub_ul(cur_reexec_skipped_destructive,     prev_reexec_skipped_destructive);
	delta_reexec_skipped_validate_silent = sat_sub_ul(cur_reexec_skipped_validate_silent, prev_reexec_skipped_validate_silent);
	delta_reexec_window_cap_hit          = sat_sub_ul(cur_reexec_window_cap_hit,          prev_reexec_window_cap_hit);
	delta_reexec_pending_dropped         = sat_sub_ul(cur_reexec_pending_dropped,         prev_reexec_pending_dropped);
	delta_reexec_gate_skip_in_reexec     = sat_sub_ul(cur_reexec_gate_skip_in_reexec,     prev_reexec_gate_skip_in_reexec);
	delta_reexec_gate_skip_disabled      = sat_sub_ul(cur_reexec_gate_skip_disabled,      prev_reexec_gate_skip_disabled);
	delta_reexec_gate_skip_mode          = sat_sub_ul(cur_reexec_gate_skip_mode,          prev_reexec_gate_skip_mode);
	delta_reexec_gate_skip_chain_mid     = sat_sub_ul(cur_reexec_gate_skip_chain_mid,     prev_reexec_gate_skip_chain_mid);
	delta_reexec_gate_skip_no_new_cmp    = sat_sub_ul(cur_reexec_gate_skip_no_new_cmp,    prev_reexec_gate_skip_no_new_cmp);
	delta_reexec_gate_skip_no_pending    = sat_sub_ul(cur_reexec_gate_skip_no_pending,    prev_reexec_gate_skip_no_pending);
	delta_reexec_gate_skip_rate          = sat_sub_ul(cur_reexec_gate_skip_rate,          prev_reexec_gate_skip_rate);
	delta_reexec_gate_pass               = sat_sub_ul(cur_reexec_gate_pass,               prev_reexec_gate_pass);
	delta_cmp_parent_calls_enabled       = sat_sub_ul(cur_cmp_parent_calls_enabled,       prev_cmp_parent_calls_enabled);
	delta_cmp_parent_calls_control       = sat_sub_ul(cur_cmp_parent_calls_control,       prev_cmp_parent_calls_control);
	delta_cmp_parent_new_cmps_enabled    = sat_sub_ul(cur_cmp_parent_new_cmps_enabled,    prev_cmp_parent_new_cmps_enabled);
	delta_cmp_parent_new_cmps_control    = sat_sub_ul(cur_cmp_parent_new_cmps_control,    prev_cmp_parent_new_cmps_control);
	delta_save_reject_nonconst      = sat_sub_ul(cur_save_reject_nonconst,      prev_save_reject_nonconst);
	delta_save_reject_uninteresting = sat_sub_ul(cur_save_reject_uninteresting, prev_save_reject_uninteresting);
	delta_save_reject_sentinel      = sat_sub_ul(cur_save_reject_sentinel,      prev_save_reject_sentinel);
	delta_save_reject_dup           = sat_sub_ul(cur_save_reject_dup,           prev_save_reject_dup);
	delta_save_reject_cap           = sat_sub_ul(cur_save_reject_cap,           prev_save_reject_cap);
	{
		unsigned int cs;
		for (cs = 0; cs < CMP_HINT_CALLSITE_NR; cs++) {
			delta_cmp_hint_callsite[cs] =
				sat_sub_ul(cur_cmp_hint_callsite[cs], prev_cmp_hint_callsite[cs]);
			if (delta_cmp_hint_callsite[cs] != 0)
				any_callsite_delta = true;
			delta_cmp_hint_callsite_pc_wins[cs] =
				sat_sub_ul(cur_cmp_hint_callsite_pc_wins[cs],
					   prev_cmp_hint_callsite_pc_wins[cs]);
			delta_cmp_hint_callsite_misses[cs] =
				sat_sub_ul(cur_cmp_hint_callsite_misses[cs],
					   prev_cmp_hint_callsite_misses[cs]);
			if (delta_cmp_hint_callsite_pc_wins[cs] != 0 ||
			    delta_cmp_hint_callsite_misses[cs] != 0)
				any_callsite_wins_delta = true;
		}
	}
	{
		unsigned int cs;
		for (cs = 0; cs < PROP_INJECTED_CALLSITE_NR; cs++) {
			delta_prop_injected_callsite[cs] =
				sat_sub_ul(cur_prop_injected_callsite[cs], prev_prop_injected_callsite[cs]);
			if (delta_prop_injected_callsite[cs] != 0)
				any_prop_callsite_delta = true;
		}
	}
	delta_cmp_hints_consumed             = sat_sub_ul(cur_cmp_hints_consumed,             prev_cmp_hints_consumed);
	delta_cmp_hint_wins                  = sat_sub_ul(cur_cmp_hint_wins,                  prev_cmp_hint_wins);
	delta_cmp_hint_misses                = sat_sub_ul(cur_cmp_hint_misses,                prev_cmp_hint_misses);
	delta_cmp_hint_cmp_novelty_wins      = sat_sub_ul(cur_cmp_hint_cmp_novelty_wins,      prev_cmp_hint_cmp_novelty_wins);
	delta_cmp_hint_stash_overflow        = sat_sub_ul(cur_cmp_hint_stash_overflow,        prev_cmp_hint_stash_overflow);
	delta_cmp_hint_credit_entry_evicted  = sat_sub_ul(cur_cmp_hint_credit_entry_evicted,  prev_cmp_hint_credit_entry_evicted);
	delta_cmp_recent_inserts             = sat_sub_ul(cur_cmp_recent_inserts,             prev_cmp_recent_inserts);
	delta_cmp_recent_evicts              = sat_sub_ul(cur_cmp_recent_evicts,              prev_cmp_recent_evicts);
	delta_cmp_recent_would_pick          = sat_sub_ul(cur_cmp_recent_would_pick,          prev_cmp_recent_would_pick);
	delta_cmp_recent_would_miss          = sat_sub_ul(cur_cmp_recent_would_miss,          prev_cmp_recent_would_miss);
	delta_cmp_recent_live_picks          = sat_sub_ul(cur_cmp_recent_live_picks,          prev_cmp_recent_live_picks);
	delta_cmp_inject_arm_a_baseline_fires = sat_sub_ul(cur_cmp_inject_arm_a_baseline_fires, prev_cmp_inject_arm_a_baseline_fires);
	delta_cmp_inject_arm_b_baseline_fires = sat_sub_ul(cur_cmp_inject_arm_b_baseline_fires, prev_cmp_inject_arm_b_baseline_fires);
	delta_cmp_inject_denom_diverged       = sat_sub_ul(cur_cmp_inject_denom_diverged,       prev_cmp_inject_denom_diverged);
	delta_prop_ring_argop_arm_b_fires     = sat_sub_ul(cur_prop_ring_argop_arm_b_fires,     prev_prop_ring_argop_arm_b_fires);
	delta_frontier_blend_samples          = sat_sub_ul(cur_frontier_blend_samples,          prev_frontier_blend_samples);
	delta_remote_adaptive_samples         = sat_sub_ul(cur_remote_adaptive_samples,         prev_remote_adaptive_samples);
	delta_mut_structured_shadow_divergences = sat_sub_ul(cur_mut_structured_shadow_divergences, prev_mut_structured_shadow_divergences);

	if ((delta_records | delta_truncated | delta_bloom_skipped | delta_strip_skipped |
	     delta_unique | delta_try_get_attempts | delta_try_get_returned |
	     delta_injected | delta_prop_injected |
	     delta_chaos_suppressed | delta_count_oob |
	     delta_canary_lock_post |
	     delta_canary_pre | delta_canary_post |
	     delta_reexec_attempts | delta_reexec_attempts_with_new_cmp |
	     delta_reexec_attribution_found |
	     delta_reexec_attribution_ambiguous | delta_reexec_attribution_width_match |
	     delta_reexec_new_cmps_total |
	     delta_reexec_new_edges_total |
	     delta_reexec_attempts_by_arm[0] | delta_reexec_attempts_by_arm[1] |
	     delta_reexec_new_cmps_by_arm[0] | delta_reexec_new_cmps_by_arm[1] |
	     delta_reexec_new_edges_by_arm[0] | delta_reexec_new_edges_by_arm[1] |
	     delta_reexec_skipped_destructive | delta_reexec_skipped_validate_silent |
	     delta_reexec_window_cap_hit | delta_reexec_pending_dropped |
	     delta_reexec_gate_skip_in_reexec | delta_reexec_gate_skip_disabled |
	     delta_reexec_gate_skip_mode | delta_reexec_gate_skip_chain_mid |
	     delta_reexec_gate_skip_no_new_cmp | delta_reexec_gate_skip_no_pending |
	     delta_reexec_gate_skip_rate | delta_reexec_gate_pass |
	     delta_cmp_parent_calls_enabled | delta_cmp_parent_calls_control |
	     delta_cmp_parent_new_cmps_enabled | delta_cmp_parent_new_cmps_control |
	     delta_save_reject_nonconst | delta_save_reject_uninteresting |
	     delta_save_reject_sentinel | delta_save_reject_dup |
	     delta_save_reject_cap |
	     delta_cmp_hints_consumed | delta_cmp_hint_wins | delta_cmp_hint_misses |
	     delta_cmp_hint_cmp_novelty_wins | delta_cmp_hint_stash_overflow |
	     delta_cmp_hint_credit_entry_evicted |
	     delta_cmp_recent_inserts | delta_cmp_recent_evicts |
	     delta_cmp_recent_would_pick | delta_cmp_recent_would_miss |
	     delta_cmp_recent_live_picks |
	     delta_cmp_inject_arm_a_baseline_fires |
	     delta_cmp_inject_arm_b_baseline_fires |
	     delta_cmp_inject_denom_diverged |
	     delta_prop_ring_argop_arm_b_fires |
	     delta_remote_adaptive_samples |
	     delta_mut_structured_shadow_divergences) != 0 ||
	    any_callsite_delta || any_callsite_wins_delta ||
	    any_prop_callsite_delta) {
		stats_log_write("KCOV CMP stats over last %lds:\n", elapsed);

		kcov_cmp_rate_line(elapsed, "cmp_records_collected", delta_records, cur_records);
		kcov_cmp_rate_line(elapsed, "cmp_trace_truncated", delta_truncated, cur_truncated);
		kcov_cmp_rate_line(elapsed, "cmp_hints_bloom_skipped", delta_bloom_skipped, cur_bloom_skipped);
		kcov_cmp_rate_line(elapsed, "cmp_hints_strip_skipped", delta_strip_skipped, cur_strip_skipped);
		kcov_cmp_rate_line(elapsed, "cmp_hints_unique_inserts", delta_unique, cur_unique);
		kcov_cmp_rate_line(elapsed, "cmp_hints_save_reject_nonconst", delta_save_reject_nonconst, cur_save_reject_nonconst);
		kcov_cmp_rate_line(elapsed, "cmp_hints_save_reject_uninteresting", delta_save_reject_uninteresting, cur_save_reject_uninteresting);
		kcov_cmp_rate_line(elapsed, "cmp_hints_save_reject_sentinel", delta_save_reject_sentinel, cur_save_reject_sentinel);
		kcov_cmp_rate_line(elapsed, "cmp_hints_save_reject_dup", delta_save_reject_dup, cur_save_reject_dup);
		kcov_cmp_rate_line(elapsed, "cmp_hints_save_reject_cap", delta_save_reject_cap, cur_save_reject_cap);
		kcov_cmp_rate_line(elapsed, "cmp_hints_try_get_attempts", delta_try_get_attempts, cur_try_get_attempts);
		kcov_cmp_rate_line(elapsed, "cmp_hints_try_get_returned", delta_try_get_returned, cur_try_get_returned);
		kcov_cmp_rate_line(elapsed, "cmp_hints_injected", delta_injected, cur_injected);
		kcov_cmp_rate_line(elapsed, "propagation_injected", delta_prop_injected, cur_prop_injected);
		if (delta_chaos_suppressed) {
			unsigned long rate_milli = (delta_chaos_suppressed * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu, chaos_active=%d)\n",
					"cmp_hints_chaos_suppressed", delta_chaos_suppressed,
					rate_milli / 1000, rate_milli % 1000, cur_chaos_suppressed,
					cmp_hints_chaos_query() ? 1 : 0);
		}
		kcov_cmp_render_wild_write_delta(elapsed,
						 delta_count_oob, cur_count_oob,
						 delta_canary_lock_post, cur_canary_lock_post,
						 delta_canary_pre, cur_canary_pre,
						 delta_canary_post, cur_canary_post);
		kcov_cmp_rate_line(elapsed, "reexec_attempts", delta_reexec_attempts, cur_reexec_attempts);
		kcov_cmp_rate_line(elapsed, "reexec_attempts_with_new_cmp", delta_reexec_attempts_with_new_cmp, cur_reexec_attempts_with_new_cmp);
		kcov_cmp_rate_line(elapsed, "reexec_attribution_found", delta_reexec_attribution_found, cur_reexec_attribution_found);
		kcov_cmp_rate_line(elapsed, "reexec_attribution_ambiguous", delta_reexec_attribution_ambiguous, cur_reexec_attribution_ambiguous);
		kcov_cmp_rate_line(elapsed, "reexec_attribution_width_match", delta_reexec_attribution_width_match, cur_reexec_attribution_width_match);
		kcov_cmp_rate_line(elapsed, "reexec_new_cmps_total", delta_reexec_new_cmps_total, cur_reexec_new_cmps_total);
		kcov_cmp_rate_line(elapsed, "reexec_new_edges_total", delta_reexec_new_edges_total, cur_reexec_new_edges_total);
		/* Plateau-burst per-call drain-cap A/B cohort split.  Renders
		 * arm-A (control, drain-all baseline) and arm-B (measure,
		 * capped at REDQUEEN_REEXEC_BURST_DRAIN during plateau) side-
		 * by-side so the shadow success criterion
		 *   (edges/attempt B) >= (edges/attempt A)
		 * can be read directly off the periodic dump.  Attempts are
		 * the denominator across both novelty axes; the block only
		 * fires when at least one arm bumped an attempt this window
		 * to keep the render quiet under CMP-off / non-plateau runs. */
		if (delta_reexec_attempts_by_arm[0] |
		    delta_reexec_attempts_by_arm[1] |
		    delta_reexec_new_cmps_by_arm[0] |
		    delta_reexec_new_cmps_by_arm[1] |
		    delta_reexec_new_edges_by_arm[0] |
		    delta_reexec_new_edges_by_arm[1]) {
			stats_log_write("  reexec burst_drain_arm cohort (A=drain-all, B=drain<=%u during plateau):\n",
					REDQUEEN_REEXEC_BURST_DRAIN);
			stats_log_write("    %-20s A +%lu (total %lu)   B +%lu (total %lu)\n",
					"attempts_by_arm",
					delta_reexec_attempts_by_arm[0],
					cur_reexec_attempts_by_arm[0],
					delta_reexec_attempts_by_arm[1],
					cur_reexec_attempts_by_arm[1]);
			stats_log_write("    %-20s A +%lu (total %lu)   B +%lu (total %lu)\n",
					"new_cmps_by_arm",
					delta_reexec_new_cmps_by_arm[0],
					cur_reexec_new_cmps_by_arm[0],
					delta_reexec_new_cmps_by_arm[1],
					cur_reexec_new_cmps_by_arm[1]);
			stats_log_write("    %-20s A +%lu (total %lu)   B +%lu (total %lu)\n",
					"new_edges_by_arm",
					delta_reexec_new_edges_by_arm[0],
					cur_reexec_new_edges_by_arm[0],
					delta_reexec_new_edges_by_arm[1],
					cur_reexec_new_edges_by_arm[1]);
		}
		kcov_cmp_rate_line(elapsed, "reexec_skipped_destructive", delta_reexec_skipped_destructive, cur_reexec_skipped_destructive);
		kcov_cmp_rate_line(elapsed, "reexec_skipped_validate_silent", delta_reexec_skipped_validate_silent, cur_reexec_skipped_validate_silent);
		kcov_cmp_rate_line(elapsed, "reexec_window_cap_hit", delta_reexec_window_cap_hit, cur_reexec_window_cap_hit);
		kcov_cmp_rate_line(elapsed, "reexec_pending_dropped", delta_reexec_pending_dropped, cur_reexec_pending_dropped);
		kcov_cmp_render_reexec_skip_reason_breakdown(elapsed,
							     delta_reexec_gate_skip_in_reexec, cur_reexec_gate_skip_in_reexec,
							     delta_reexec_gate_skip_disabled, cur_reexec_gate_skip_disabled,
							     delta_reexec_gate_skip_mode, cur_reexec_gate_skip_mode,
							     delta_reexec_gate_skip_chain_mid, cur_reexec_gate_skip_chain_mid,
							     delta_reexec_gate_skip_no_new_cmp, cur_reexec_gate_skip_no_new_cmp,
							     delta_reexec_gate_skip_no_pending, cur_reexec_gate_skip_no_pending,
							     delta_reexec_gate_skip_rate, cur_reexec_gate_skip_rate,
							     delta_reexec_gate_pass, cur_reexec_gate_pass);
		kcov_cmp_rate_line(elapsed, "cmp_parent_calls_enabled", delta_cmp_parent_calls_enabled, cur_cmp_parent_calls_enabled);
		kcov_cmp_rate_line(elapsed, "cmp_parent_calls_control", delta_cmp_parent_calls_control, cur_cmp_parent_calls_control);
		kcov_cmp_rate_line(elapsed, "cmp_parent_new_cmps_enabled", delta_cmp_parent_new_cmps_enabled, cur_cmp_parent_new_cmps_enabled);
		kcov_cmp_rate_line(elapsed, "cmp_parent_new_cmps_control", delta_cmp_parent_new_cmps_control, cur_cmp_parent_new_cmps_control);
		if (any_callsite_delta || any_callsite_wins_delta) {
			static const char * const callsite_names[CMP_HINT_CALLSITE_NR] = {
				[CMP_HINT_CALLSITE_ARG_OP]          = "ARG_OP",
				[CMP_HINT_CALLSITE_ARG_LIST]        = "ARG_LIST",
				[CMP_HINT_CALLSITE_ARG_UNDEFINED]   = "ARG_UNDEFINED",
				[CMP_HINT_CALLSITE_ARG_STRUCT_SIZE] = "ARG_STRUCT_SIZE",
				[CMP_HINT_CALLSITE_STRUCT_FIELD]    = "STRUCT_FIELD",
				[CMP_HINT_CALLSITE_OTHER]           = "OTHER",
				[CMP_HINT_CALLSITE_ARG_RANGE]       = "ARG_RANGE",
			};
			unsigned int cs;

			if (any_callsite_delta) {
				stats_log_write("  cmp_hint_callsite_injected (per-callsite delta / cumulative):\n");
				for (cs = 0; cs < CMP_HINT_CALLSITE_NR; cs++) {
					if (delta_cmp_hint_callsite[cs] == 0 &&
					    cur_cmp_hint_callsite[cs] == 0)
						continue;
					stats_log_write("    %-20s +%lu  (total %lu)\n",
							callsite_names[cs],
							delta_cmp_hint_callsite[cs],
							cur_cmp_hint_callsite[cs]);
				}
			}
			/* PC-mode WIN/MISS partition by callsite -- sibling of
			 * the injected split above.  Field-pool pulls (stamped
			 * CMP_HINT_CALLSITE_NR) are not attributed here, so
			 * sum(pc_wins/misses) can be less than the flat
			 * cmp_hint_wins / cmp_hint_misses. */
			if (any_callsite_wins_delta) {
				stats_log_write("  cmp_hint_callsite_pc_wins/_misses (per-callsite PC-mode outcome delta / cumulative):\n");
				for (cs = 0; cs < CMP_HINT_CALLSITE_NR; cs++) {
					if (delta_cmp_hint_callsite_pc_wins[cs] == 0 &&
					    delta_cmp_hint_callsite_misses[cs] == 0 &&
					    cur_cmp_hint_callsite_pc_wins[cs] == 0 &&
					    cur_cmp_hint_callsite_misses[cs] == 0)
						continue;
					stats_log_write("    %-20s wins +%lu (total %lu)  misses +%lu (total %lu)\n",
							callsite_names[cs],
							delta_cmp_hint_callsite_pc_wins[cs],
							cur_cmp_hint_callsite_pc_wins[cs],
							delta_cmp_hint_callsite_misses[cs],
							cur_cmp_hint_callsite_misses[cs]);
				}
			}
		}
		if (any_prop_callsite_delta) {
			static const char * const prop_callsite_names[PROP_INJECTED_CALLSITE_NR] = {
				[PROP_INJECTED_CALLSITE_ARG_OP]        = "ARG_OP",
				[PROP_INJECTED_CALLSITE_ARG_UNDEFINED] = "ARG_UNDEFINED",
			};
			unsigned int cs;

			stats_log_write("  propagation_injected_callsite (per-callsite delta / cumulative):\n");
			for (cs = 0; cs < PROP_INJECTED_CALLSITE_NR; cs++) {
				if (delta_prop_injected_callsite[cs] == 0 &&
				    cur_prop_injected_callsite[cs] == 0)
					continue;
				stats_log_write("    %-20s +%lu  (total %lu)\n",
						prop_callsite_names[cs],
						delta_prop_injected_callsite[cs],
						cur_prop_injected_callsite[cs]);
			}
		}
		kcov_cmp_render_per_entry_feedback_scoring(elapsed,
							   delta_cmp_hints_consumed, cur_cmp_hints_consumed,
							   delta_cmp_hint_wins, cur_cmp_hint_wins,
							   delta_cmp_hint_misses, cur_cmp_hint_misses,
							   delta_cmp_hint_cmp_novelty_wins, cur_cmp_hint_cmp_novelty_wins,
							   delta_cmp_hint_stash_overflow, cur_cmp_hint_stash_overflow,
							   delta_cmp_hint_credit_entry_evicted, cur_cmp_hint_credit_entry_evicted);
		kcov_cmp_render_recent_cmp_pool_tier(elapsed,
						     delta_cmp_recent_inserts, cur_cmp_recent_inserts,
						     delta_cmp_recent_evicts, cur_cmp_recent_evicts,
						     delta_cmp_recent_would_pick, cur_cmp_recent_would_pick,
						     delta_cmp_recent_would_miss, cur_cmp_recent_would_miss,
						     delta_cmp_recent_live_picks, cur_cmp_recent_live_picks);
		kcov_cmp_render_ab_baseline_inject_denom(elapsed,
							 delta_cmp_inject_arm_a_baseline_fires, cur_cmp_inject_arm_a_baseline_fires,
							 delta_cmp_inject_arm_b_baseline_fires, cur_cmp_inject_arm_b_baseline_fires,
							 delta_cmp_inject_denom_diverged, cur_cmp_inject_denom_diverged,
							 cur_cmp_inject_arm_a_children,
							 cur_cmp_inject_arm_b_children);
		kcov_cmp_render_handle_arg_op_prop_ring_cohort(elapsed,
							       delta_prop_ring_argop_arm_b_fires,
							       cur_prop_ring_argop_arm_b_fires,
							       cur_prop_ring_argop_arm_a_children,
							       cur_prop_ring_argop_arm_b_children);
		kcov_cmp_render_frontier_cold_weight_blend_cohort(elapsed,
								  delta_frontier_blend_samples,
								  cur_frontier_blend_samples,
								  cur_frontier_blend_arm_a_children,
								  cur_frontier_blend_arm_b_children);
		kcov_cmp_render_adaptive_remote_kcov_cohort(elapsed,
							    delta_remote_adaptive_samples,
							    cur_remote_adaptive_samples,
							    cur_remote_adaptive_arm_a_children,
							    cur_remote_adaptive_arm_b_children,
							    cur_remote_adaptive_would_demote,
							    cur_remote_adaptive_would_promote,
							    cur_remote_adaptive_would_force,
							    cur_remote_adaptive_would_gate_promote,
							    cur_remote_adaptive_agree);
		kcov_cmp_render_per_arg_ownership_sidecar(cur_blanket_address_scrub_slots_walked,
							  cur_arg_meta_addr_with_meta,
							  cur_arg_meta_addr_without_meta,
							  cur_arg_meta_argtype_stale,
							  cur_arg_meta_scrub_would_destroy_in,
							  cur_arg_meta_scrub_would_preserve_out);
		kcov_cmp_render_structure_aware_picker_cohort(elapsed,
							      delta_mut_structured_shadow_divergences,
							      cur_mut_structured_shadow_divergences,
							      cur_mut_structured_shadow_samples,
							      cur_mut_structured_arm_a_children,
							      cur_mut_structured_arm_b_children);
	}

	kcov_cmp_render_hyp_shadow_stats_block(elapsed);

	kcov_cmp_render_hyp_would_pick_block(elapsed);

	kcov_cmp_render_childop_cmp_consume_shadow_block(elapsed);

	kcov_cmp_render_hyp_live_inject_block(elapsed);

	kcov_cmp_render_hyp_live_inject_reasons_block(elapsed);

	kcov_cmp_render_hyp_boundary_scorecard_block(elapsed);

	kcov_cmp_render_hyp_would_promote_demote_block(elapsed);

	kcov_cmp_render_hyp_score_bucket_block(elapsed);

	kcov_cmp_render_hyp_probe_class_hist_block(elapsed);

	kcov_cmp_render_hyp_per_hypothesis_aggregates_block(elapsed);

	/*
	 * Standalone grep-friendly cumulative lines for counters whose only
	 * stat output above is delta-gated (skipped at zero) and whose bare
	 * tokens recur in narrative -- JSON dumps, header comments, atomic
	 * fetch sites -- so `grep -c <counter>` against a long-running log
	 * counts narrative occurrences rather than the counter, the same
	 * triage trap post_handler_corrupt_ptr_cumulative was added to
	 * close.  Emit one line per dump window per counter (even at zero
	 * so trend tracking has a t=0 anchor) with a distinctive
	 * _cumulative suffix; operators can `grep <counter>_cumulative
	 * out.log | tail -1` for the current total or grep -c the suffix
	 * to count windows.  Placed outside the delta-gated block above so
	 * they fire every window regardless of cmp activity.
	 */
	output(0, "[main] cmp_hints_chaos_suppressed_cumulative=%lu\n",
	       cur_chaos_suppressed);
	output(0, "[main] propagation_injected_cumulative=%lu\n",
	       cur_prop_injected);

	kcov_cmp_render_modes_block();

	kcov_cmp_render_diag_errnos_block();

	kcov_cmp_render_pc_diag_block();

	kcov_cmp_observability_block_render(elapsed);
	kcov_redqueen_observability_block_render(elapsed);
	kcov_cmp_oldpool_vs_shadow_block_render(elapsed);
	kcov_cmp_render_pc_win_conversion_split_block(elapsed);
	kcov_cmp_hyp_saturation_block_render(elapsed);

	prev_records       = cur_records;
	prev_truncated     = cur_truncated;
	prev_bloom_skipped = cur_bloom_skipped;
	prev_strip_skipped = cur_strip_skipped;
	prev_unique        = cur_unique;
	prev_try_get_attempts = cur_try_get_attempts;
	prev_try_get_returned = cur_try_get_returned;
	prev_injected         = cur_injected;
	prev_prop_injected    = cur_prop_injected;
	prev_chaos_suppressed = cur_chaos_suppressed;
	prev_count_oob        = cur_count_oob;
	prev_canary_lock_post = cur_canary_lock_post;
	prev_canary_pre       = cur_canary_pre;
	prev_canary_post      = cur_canary_post;
	prev_reexec_attempts                = cur_reexec_attempts;
	prev_reexec_attempts_with_new_cmp   = cur_reexec_attempts_with_new_cmp;
	prev_reexec_attribution_found       = cur_reexec_attribution_found;
	prev_reexec_attribution_ambiguous   = cur_reexec_attribution_ambiguous;
	prev_reexec_attribution_width_match = cur_reexec_attribution_width_match;
	prev_reexec_new_cmps_total          = cur_reexec_new_cmps_total;
	prev_reexec_new_edges_total         = cur_reexec_new_edges_total;
	prev_reexec_attempts_by_arm[0]      = cur_reexec_attempts_by_arm[0];
	prev_reexec_attempts_by_arm[1]      = cur_reexec_attempts_by_arm[1];
	prev_reexec_new_cmps_by_arm[0]      = cur_reexec_new_cmps_by_arm[0];
	prev_reexec_new_cmps_by_arm[1]      = cur_reexec_new_cmps_by_arm[1];
	prev_reexec_new_edges_by_arm[0]     = cur_reexec_new_edges_by_arm[0];
	prev_reexec_new_edges_by_arm[1]     = cur_reexec_new_edges_by_arm[1];
	{
		unsigned int cs;
		for (cs = 0; cs < PROP_INJECTED_CALLSITE_NR; cs++)
			prev_prop_injected_callsite[cs] = cur_prop_injected_callsite[cs];
	}
	prev_reexec_skipped_destructive     = cur_reexec_skipped_destructive;
	prev_reexec_skipped_validate_silent = cur_reexec_skipped_validate_silent;
	prev_reexec_window_cap_hit          = cur_reexec_window_cap_hit;
	prev_reexec_pending_dropped         = cur_reexec_pending_dropped;
	prev_reexec_gate_skip_in_reexec     = cur_reexec_gate_skip_in_reexec;
	prev_reexec_gate_skip_disabled      = cur_reexec_gate_skip_disabled;
	prev_reexec_gate_skip_mode          = cur_reexec_gate_skip_mode;
	prev_reexec_gate_skip_chain_mid     = cur_reexec_gate_skip_chain_mid;
	prev_reexec_gate_skip_no_new_cmp    = cur_reexec_gate_skip_no_new_cmp;
	prev_reexec_gate_skip_no_pending    = cur_reexec_gate_skip_no_pending;
	prev_reexec_gate_skip_rate          = cur_reexec_gate_skip_rate;
	prev_reexec_gate_pass               = cur_reexec_gate_pass;
	prev_cmp_parent_calls_enabled       = cur_cmp_parent_calls_enabled;
	prev_cmp_parent_calls_control       = cur_cmp_parent_calls_control;
	prev_cmp_parent_new_cmps_enabled    = cur_cmp_parent_new_cmps_enabled;
	prev_cmp_parent_new_cmps_control    = cur_cmp_parent_new_cmps_control;
	prev_save_reject_nonconst      = cur_save_reject_nonconst;
	prev_save_reject_uninteresting = cur_save_reject_uninteresting;
	prev_save_reject_sentinel      = cur_save_reject_sentinel;
	prev_save_reject_dup           = cur_save_reject_dup;
	prev_save_reject_cap           = cur_save_reject_cap;
	{
		unsigned int cs;
		for (cs = 0; cs < CMP_HINT_CALLSITE_NR; cs++) {
			prev_cmp_hint_callsite[cs] = cur_cmp_hint_callsite[cs];
			prev_cmp_hint_callsite_pc_wins[cs] =
				cur_cmp_hint_callsite_pc_wins[cs];
			prev_cmp_hint_callsite_misses[cs] =
				cur_cmp_hint_callsite_misses[cs];
		}
	}
	prev_cmp_hints_consumed             = cur_cmp_hints_consumed;
	prev_cmp_hint_wins                  = cur_cmp_hint_wins;
	prev_cmp_hint_misses                = cur_cmp_hint_misses;
	prev_cmp_hint_cmp_novelty_wins      = cur_cmp_hint_cmp_novelty_wins;
	prev_cmp_hint_stash_overflow        = cur_cmp_hint_stash_overflow;
	prev_cmp_hint_credit_entry_evicted  = cur_cmp_hint_credit_entry_evicted;
	prev_cmp_recent_inserts             = cur_cmp_recent_inserts;
	prev_cmp_recent_evicts              = cur_cmp_recent_evicts;
	prev_cmp_recent_would_pick          = cur_cmp_recent_would_pick;
	prev_cmp_recent_would_miss          = cur_cmp_recent_would_miss;
	prev_cmp_recent_live_picks          = cur_cmp_recent_live_picks;
	prev_cmp_inject_arm_a_baseline_fires = cur_cmp_inject_arm_a_baseline_fires;
	prev_cmp_inject_arm_b_baseline_fires = cur_cmp_inject_arm_b_baseline_fires;
	prev_cmp_inject_denom_diverged       = cur_cmp_inject_denom_diverged;
	prev_prop_ring_argop_arm_b_fires     = cur_prop_ring_argop_arm_b_fires;
	prev_frontier_blend_samples          = cur_frontier_blend_samples;
	prev_remote_adaptive_samples         = cur_remote_adaptive_samples;
	prev_mut_structured_shadow_divergences = cur_mut_structured_shadow_divergences;
	last_dump = now;
}
