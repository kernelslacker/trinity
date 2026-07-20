
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

/* Per-pool top-N entry for top_syscalls_periodic_dump's stack-resident
 * insertion sort.  Holds the syscall's table index and the per-window
 * delta of its strategy-attributed new-edge counter. */
struct top_syscall_entry {
	unsigned int nr;
	unsigned long delta;
};


static void top_syscalls_emit_pool(const char *pool_name,
				   const unsigned long *cur,
				   const unsigned long *prev,
				   unsigned int nr_to_scan,
				   const struct syscalltable *table,
				   bool is32bit)
{
	struct top_syscall_entry top[TOP_SYSCALLS_DUMP_TOPN];
	unsigned int top_count = 0;
	unsigned long total = 0, top_sum = 0, share_pct;
	unsigned int i;
	int j;

	for (i = 0; i < nr_to_scan; i++) {
		unsigned long delta = sat_sub_ul(cur[i], prev[i]);

		if (delta == 0)
			continue;

		total += delta;

		/* Insertion sort, descending by delta, capped at TOP_N. */
		for (j = (int)top_count;
		     j > 0 && delta > top[j - 1].delta;
		     j--) {
			if (j < TOP_SYSCALLS_DUMP_TOPN)
				top[j] = top[j - 1];
		}
		if (j < TOP_SYSCALLS_DUMP_TOPN) {
			top[j].nr = i;
			top[j].delta = delta;
			if (top_count < TOP_SYSCALLS_DUMP_TOPN)
				top_count++;
		}
	}

	/* Skip the strategy block entirely when the pool contributed no
	 * new edges this window -- a "(0 total, top 5 = 0%)" line is
	 * noise, not signal. */
	if (total == 0)
		return;

	for (j = 0; j < (int)top_count; j++)
		top_sum += top[j].delta;
	share_pct = (top_sum * 100UL) / total;

	stats_log_write("  %s (%lu total, top %u = %lu%%):\n",
			pool_name, total, top_count, share_pct);

	for (j = 0; j < (int)top_count; j++) {
		const char *name = table ? print_syscall_name(top[j].nr, is32bit)
					 : "???";
		stats_log_write("    %-24s +%lu\n", name, top[j].delta);
	}
}

/* Per-syscall frontier-yield kill-list row.  Carries the four delta-tracked
 * F1 counters plus the two absolute snapshots (recent_weight and the
 * last-productive-window stamp) so the emitter can render one combined
 * table row per top entry without re-reading shm. */
struct frontier_yield_entry {
	unsigned int nr;
	unsigned long live_picks_delta;
	unsigned long silent_picks_delta;
	unsigned long wins_delta;
	unsigned long misses_delta;
	uint32_t recent_weight;
	unsigned long last_productive_window;
};

/* Companion to top_syscalls_emit_pool() for the F1 per-syscall frontier-
 * yield arrays.  Sorts the top-N by live_misses delta -- the headline kill-
 * list signal -- and emits one row per entry with the live/silent pick split,
 * the productive-wins delta, the live_misses delta, the current recent-ring
 * weight, and the age (in bandit windows) since the last productive win.
 * Zero-total-misses windows skip the row, mirroring the sibling emitter. */
static void top_syscalls_emit_frontier_yield(
		const unsigned long *cur_live_picks,
		const unsigned long *prev_live_picks,
		const unsigned long *cur_silent_picks,
		const unsigned long *prev_silent_picks,
		const unsigned long *cur_wins,
		const unsigned long *prev_wins,
		const unsigned long *cur_misses,
		const unsigned long *prev_misses,
		const uint32_t *recent_weight,
		const unsigned long *last_productive_window,
		unsigned long bandit_window_now,
		unsigned int nr_to_scan,
		const struct syscalltable *table,
		bool is32bit)
{
	struct frontier_yield_entry top[TOP_SYSCALLS_DUMP_TOPN];
	unsigned int top_count = 0;
	unsigned long total_misses = 0;
	unsigned int i;
	int j;

	for (i = 0; i < nr_to_scan; i++) {
		unsigned long live_d = sat_sub_ul(cur_live_picks[i], prev_live_picks[i]);
		unsigned long silent_d = sat_sub_ul(cur_silent_picks[i], prev_silent_picks[i]);
		unsigned long wins_d = sat_sub_ul(cur_wins[i], prev_wins[i]);
		unsigned long misses_d = sat_sub_ul(cur_misses[i], prev_misses[i]);

		if (misses_d == 0)
			continue;

		total_misses += misses_d;

		for (j = (int)top_count;
		     j > 0 && misses_d > top[j - 1].misses_delta;
		     j--) {
			if (j < TOP_SYSCALLS_DUMP_TOPN)
				top[j] = top[j - 1];
		}
		if (j < TOP_SYSCALLS_DUMP_TOPN) {
			top[j].nr = i;
			top[j].live_picks_delta = live_d;
			top[j].silent_picks_delta = silent_d;
			top[j].wins_delta = wins_d;
			top[j].misses_delta = misses_d;
			top[j].recent_weight = recent_weight[i];
			top[j].last_productive_window =
				last_productive_window[i];
			if (top_count < TOP_SYSCALLS_DUMP_TOPN)
				top_count++;
		}
	}

	if (total_misses == 0)
		return;

	stats_log_write("  frontier-yield kill-list (top %u by live_misses, "
			"%lu total live_misses):\n",
			top_count, total_misses);
	stats_log_write("    %-24s %8s %8s %8s %8s %8s %10s\n",
			"syscall", "live", "silent", "wins", "misses",
			"recent", "last_age");
	for (j = 0; j < (int)top_count; j++) {
		const char *name = table ? print_syscall_name(top[j].nr, is32bit)
					 : "???";

		/* last_productive_window == 0 means no productive win has ever
		 * been attributed to this slot (F1 zero-inits the array via
		 * shm); rendering "bandit_window_now - 0" as a giant age would
		 * mis-read as a stale-but-once-productive entry.  "never" is
		 * the actionable signal: entry has eaten frontier picks under
		 * the live regime and converted zero of them since boot. */
		if (top[j].last_productive_window == 0) {
			stats_log_write("    %-24s %8lu %8lu %8lu %8lu %8u %10s\n",
					name,
					top[j].live_picks_delta,
					top[j].silent_picks_delta,
					top[j].wins_delta,
					top[j].misses_delta,
					top[j].recent_weight,
					"never");
		} else {
			/* Saturating subtract: the F1 stamp is RELAXED and the
			 * window counter we read here is a separate RELAXED
			 * load, so an interleaving where the stamp lands from
			 * a later window than the bandit_window_now snapshot
			 * is observable; clamp at 0 rather than wrap to
			 * ULONG_MAX (mirrors the delta clamps above). */
			unsigned long age = (bandit_window_now >
					     top[j].last_productive_window)
				? bandit_window_now -
					top[j].last_productive_window
				: 0;
			stats_log_write("    %-24s %8lu %8lu %8lu %8lu %8u %10lu\n",
					name,
					top[j].live_picks_delta,
					top[j].silent_picks_delta,
					top[j].wins_delta,
					top[j].misses_delta,
					top[j].recent_weight,
					age);
		}
	}
}

static void top_syscalls_render_frontier_picks(
		const unsigned long *cur, const unsigned long *prev,
		long elapsed, unsigned int nr_to_scan,
		const struct syscalltable *table)
{
	/* Frontier-picker accept distribution: which syscalls ate the
	 * coverage-frontier picks this window.  Same top-N emitter as the
	 * edge pools above; an empty distribution (frontier arm never
	 * selected, or selected but accepted nothing) skips the row via the
	 * helper's zero-total gate. */
	stats_log_write("Top %u syscalls by frontier picks in last %lds:\n",
			TOP_SYSCALLS_DUMP_TOPN, elapsed);
	top_syscalls_emit_pool("frontier", cur, prev, nr_to_scan, table, false);
}

static void top_syscalls_render_frontier_yield(
		const unsigned long *cur_live_picks,
		const unsigned long *prev_live_picks,
		const unsigned long *cur_silent_picks,
		const unsigned long *prev_silent_picks,
		const unsigned long *cur_wins,
		const unsigned long *prev_wins,
		const unsigned long *cur_live_misses,
		const unsigned long *prev_live_misses,
		const uint32_t *cur_recent_weight,
		const unsigned long *cur_last_productive,
		long elapsed, unsigned int nr_to_scan,
		const struct syscalltable *table)
{
	unsigned long bandit_window_now;

	/* Per-syscall frontier yield (kill-list feedstock).  Surfaces the
	 * regime split (live vs silent pick deltas), productive wins and
	 * live_misses deltas, the current recent-ring weight, and the age
	 * since the last productive win for the top-N syscalls by live_miss
	 * delta.  Render-only over F1's per-syscall counters; the helper
	 * gates on total_misses == 0 so a window where the live regime never
	 * wasted a pick collapses to no row. */
	bandit_window_now = __atomic_load_n(&shm->bandit_window_count,
					    __ATOMIC_RELAXED);
	stats_log_write("Per-syscall frontier yield in last %lds:\n", elapsed);
	top_syscalls_emit_frontier_yield(
			cur_live_picks, prev_live_picks,
			cur_silent_picks, prev_silent_picks,
			cur_wins, prev_wins,
			cur_live_misses, prev_live_misses,
			cur_recent_weight,
			cur_last_productive,
			bandit_window_now,
			nr_to_scan, table, false);
}

static void top_syscalls_render_rq(
		const unsigned long *cur_saves,
		const unsigned long *prev_saves,
		const unsigned long *cur_wins,
		const unsigned long *prev_wins,
		long elapsed, unsigned int nr_to_scan,
		const struct syscalltable *table)
{
	/* RedQueen-source corpus saves vs the PC-edge wins those saves
	 * later produce, per-syscall.  The two top-Ns answer the
	 * harvest->edge bottleneck question: which syscalls are RedQueen
	 * harvesting args for, and which of those convert downstream to
	 * new PC-bucket edges once a corpus replay picks them up.  The
	 * helper's zero-total gate skips each row when its pool is empty
	 * (re-exec disabled, or enabled but no corpus replay landed on an
	 * rq-sourced entry that flipped a new edge this window). */
	stats_log_write("Top %u syscalls by RedQueen-sourced saves "
			"in last %lds:\n",
			TOP_SYSCALLS_DUMP_TOPN, elapsed);
	top_syscalls_emit_pool("rq-saves", cur_saves, prev_saves,
			       nr_to_scan, table, false);
	stats_log_write("Top %u syscalls by PC-edge wins from "
			"RedQueen-sourced saves in last %lds:\n",
			TOP_SYSCALLS_DUMP_TOPN, elapsed);
	top_syscalls_emit_pool("rq-pcedge-wins", cur_wins, prev_wins,
			       nr_to_scan, table, false);
}

static void top_syscalls_render_warm_reserve(
		const unsigned long *cur, const unsigned long *prev,
		long elapsed, unsigned int nr_to_scan,
		const struct syscalltable *table)
{
	/* SHADOW deep-but-warm candidate accounting (see the warm_reserve_
	 * candidates* comment in include/stats.h for the predicate).  Same
	 * top-N shape and zero-total skip as the pools above; an empty
	 * distribution (no syscall fired the deep-but-warm predicate this
	 * window) collapses to no row via the emitter's gate. */
	stats_log_write("Top %u syscalls by deep-but-warm candidates "
			"in last %lds:\n",
			TOP_SYSCALLS_DUMP_TOPN, elapsed);
	top_syscalls_emit_pool("warm-reserve", cur, prev,
			       nr_to_scan, table, false);
}

static void top_syscalls_render_warm_reserve_plateau(
		const unsigned long *cur, const unsigned long *prev,
		long elapsed, unsigned int nr_to_scan,
		const struct syscalltable *table)
{
	/* SHADOW would-replay-demand accounting -- intersection of the
	 * deep-but-warm predicate with the CMP_RISING_PC_FLAT plateau
	 * window (see warm_reserve_during_plateau* in include/stats.h).
	 * Same top-N shape and zero-total skip as the warm-reserve row
	 * above; a window without a plateau, or a plateau window without
	 * any deep-but-warm fires, collapses to no row. */
	stats_log_write("Top %u syscalls by deep-but-warm candidates "
			"during plateau in last %lds:\n",
			TOP_SYSCALLS_DUMP_TOPN, elapsed);
	top_syscalls_emit_pool("warm-reserve-plateau", cur, prev,
			       nr_to_scan, table, false);
}

void __cold top_syscalls_periodic_dump(void)
{
	static unsigned long prev_bandit[MAX_NR_SYSCALL];
	static unsigned long prev_explorer[MAX_NR_SYSCALL];
	static unsigned long prev_frontier_picks[MAX_NR_SYSCALL];
	static unsigned long prev_frontier_live_picks[MAX_NR_SYSCALL];
	static unsigned long prev_frontier_silent_picks[MAX_NR_SYSCALL];
	static unsigned long prev_frontier_wins[MAX_NR_SYSCALL];
	static unsigned long prev_frontier_live_misses[MAX_NR_SYSCALL];
	static unsigned long prev_rq_saves[MAX_NR_SYSCALL];
	static unsigned long prev_rq_wins[MAX_NR_SYSCALL];
	static unsigned long prev_warm_reserve[MAX_NR_SYSCALL];
	static unsigned long prev_warm_reserve_plateau[MAX_NR_SYSCALL];
	static struct timespec last_dump;
	unsigned long cur_bandit[MAX_NR_SYSCALL];
	unsigned long cur_explorer[MAX_NR_SYSCALL];
	unsigned long cur_frontier_picks[MAX_NR_SYSCALL];
	unsigned long cur_frontier_live_picks[MAX_NR_SYSCALL];
	unsigned long cur_frontier_silent_picks[MAX_NR_SYSCALL];
	unsigned long cur_frontier_wins[MAX_NR_SYSCALL];
	unsigned long cur_frontier_live_misses[MAX_NR_SYSCALL];
	unsigned long cur_frontier_last_productive[MAX_NR_SYSCALL];
	uint32_t cur_frontier_recent_weight[MAX_NR_SYSCALL];
	unsigned long cur_rq_saves[MAX_NR_SYSCALL];
	unsigned long cur_rq_wins[MAX_NR_SYSCALL];
	unsigned long cur_warm_reserve[MAX_NR_SYSCALL];
	unsigned long cur_warm_reserve_plateau[MAX_NR_SYSCALL];
	struct timespec now;
	long elapsed;
	unsigned int nr_to_scan;
	const struct syscalltable *table;
	unsigned int i;

	clock_gettime(CLOCK_MONOTONIC, &now);

	/* First call: arm the window so any pre-existing counts carried
	 * over from earlier in the run are not mis-attributed to the
	 * first window, mirroring periodic_counter_rates_dump. */
	if (last_dump.tv_sec == 0) {
		last_dump = now;
		for (i = 0; i < MAX_NR_SYSCALL; i++) {
			prev_bandit[i]   = __atomic_load_n(
				&shm->stats.edges_per_syscall_bandit[i],
				__ATOMIC_RELAXED);
			prev_explorer[i] = __atomic_load_n(
				&shm->stats.edges_per_syscall_explorer[i],
				__ATOMIC_RELAXED);
			prev_frontier_picks[i] = __atomic_load_n(
				&shm->stats.frontier.per_syscall.picks_per_syscall[i],
				__ATOMIC_RELAXED);
			prev_frontier_live_picks[i] = __atomic_load_n(
				&shm->stats.frontier.per_syscall.live_picks_per_syscall[i],
				__ATOMIC_RELAXED);
			prev_frontier_silent_picks[i] = __atomic_load_n(
				&shm->stats.frontier.per_syscall.silent_picks_per_syscall[i],
				__ATOMIC_RELAXED);
			prev_frontier_wins[i] = __atomic_load_n(
				&shm->stats.frontier.per_syscall.productive_wins_per_syscall[i],
				__ATOMIC_RELAXED);
			prev_frontier_live_misses[i] = __atomic_load_n(
				&shm->stats.frontier.per_syscall.live_misses_per_syscall[i],
				__ATOMIC_RELAXED);
			prev_rq_saves[i] = __atomic_load_n(
				&shm->stats.pc_edge_source.rq_saves[i],
				__ATOMIC_RELAXED);
			prev_rq_wins[i] = __atomic_load_n(
				&shm->stats.pc_edge_source.rq_pcedge_wins[i],
				__ATOMIC_RELAXED);
			prev_warm_reserve[i] = __atomic_load_n(
				&shm->stats.warm_reserve_candidates[i],
				__ATOMIC_RELAXED);
			prev_warm_reserve_plateau[i] = __atomic_load_n(
				&shm->stats.warm_reserve_during_plateau[i],
				__ATOMIC_RELAXED);
		}
		return;
	}

	elapsed = now.tv_sec - last_dump.tv_sec;
	if (elapsed < DEFENSE_DUMP_INTERVAL_SEC)
		return;

	for (i = 0; i < MAX_NR_SYSCALL; i++) {
		cur_bandit[i]   = __atomic_load_n(
			&shm->stats.edges_per_syscall_bandit[i],
			__ATOMIC_RELAXED);
		cur_explorer[i] = __atomic_load_n(
			&shm->stats.edges_per_syscall_explorer[i],
			__ATOMIC_RELAXED);
		cur_frontier_picks[i] = __atomic_load_n(
			&shm->stats.frontier.per_syscall.picks_per_syscall[i],
			__ATOMIC_RELAXED);
		cur_frontier_live_picks[i] = __atomic_load_n(
			&shm->stats.frontier.per_syscall.live_picks_per_syscall[i],
			__ATOMIC_RELAXED);
		cur_frontier_silent_picks[i] = __atomic_load_n(
			&shm->stats.frontier.per_syscall.silent_picks_per_syscall[i],
			__ATOMIC_RELAXED);
		cur_frontier_wins[i] = __atomic_load_n(
			&shm->stats.frontier.per_syscall.productive_wins_per_syscall[i],
			__ATOMIC_RELAXED);
		cur_frontier_live_misses[i] = __atomic_load_n(
			&shm->stats.frontier.per_syscall.live_misses_per_syscall[i],
			__ATOMIC_RELAXED);
		cur_frontier_last_productive[i] = __atomic_load_n(
			&shm->stats.frontier.per_syscall.last_productive_window_per_syscall[i],
			__ATOMIC_RELAXED);
		cur_frontier_recent_weight[i] = __atomic_load_n(
			&shm->frontier_recent_count_cached[i],
			__ATOMIC_RELAXED);
		cur_rq_saves[i] = __atomic_load_n(
			&shm->stats.pc_edge_source.rq_saves[i],
			__ATOMIC_RELAXED);
		cur_rq_wins[i] = __atomic_load_n(
			&shm->stats.pc_edge_source.rq_pcedge_wins[i],
			__ATOMIC_RELAXED);
		cur_warm_reserve[i] = __atomic_load_n(
			&shm->stats.warm_reserve_candidates[i],
			__ATOMIC_RELAXED);
		cur_warm_reserve_plateau[i] = __atomic_load_n(
			&shm->stats.warm_reserve_during_plateau[i],
			__ATOMIC_RELAXED);
	}

	/* Match the same biarch table-scan choice the existing per-syscall
	 * top-N path in dump_stats uses: under biarch only the 64-bit table
	 * is iterated (32-bit nrs collide with 64-bit ones in the same
	 * index space and would shadow them in the display). */
	if (biarch) {
		nr_to_scan = max_nr_64bit_syscalls;
		table = syscalls_64bit;
	} else {
		nr_to_scan = max_nr_syscalls;
		table = syscalls;
	}
	if (nr_to_scan > MAX_NR_SYSCALL)
		nr_to_scan = MAX_NR_SYSCALL;

	stats_log_write("Top %u syscalls by new edges in last %lds:\n",
			TOP_SYSCALLS_DUMP_TOPN, elapsed);
	top_syscalls_emit_pool("bandit", cur_bandit, prev_bandit,
			       nr_to_scan, table, false);
	top_syscalls_emit_pool("explorer", cur_explorer, prev_explorer,
			       nr_to_scan, table, false);

	top_syscalls_render_frontier_picks(cur_frontier_picks,
					   prev_frontier_picks,
					   elapsed, nr_to_scan, table);

	top_syscalls_render_frontier_yield(
			cur_frontier_live_picks, prev_frontier_live_picks,
			cur_frontier_silent_picks, prev_frontier_silent_picks,
			cur_frontier_wins, prev_frontier_wins,
			cur_frontier_live_misses, prev_frontier_live_misses,
			cur_frontier_recent_weight,
			cur_frontier_last_productive,
			elapsed, nr_to_scan, table);

	top_syscalls_render_rq(cur_rq_saves, prev_rq_saves,
			       cur_rq_wins, prev_rq_wins,
			       elapsed, nr_to_scan, table);

	top_syscalls_render_warm_reserve(cur_warm_reserve, prev_warm_reserve,
					 elapsed, nr_to_scan, table);

	top_syscalls_render_warm_reserve_plateau(cur_warm_reserve_plateau,
						 prev_warm_reserve_plateau,
						 elapsed, nr_to_scan, table);

	memcpy(prev_bandit,   cur_bandit,   sizeof(prev_bandit));
	memcpy(prev_explorer, cur_explorer, sizeof(prev_explorer));
	memcpy(prev_frontier_picks, cur_frontier_picks,
	       sizeof(prev_frontier_picks));
	memcpy(prev_frontier_live_picks, cur_frontier_live_picks,
	       sizeof(prev_frontier_live_picks));
	memcpy(prev_frontier_silent_picks, cur_frontier_silent_picks,
	       sizeof(prev_frontier_silent_picks));
	memcpy(prev_frontier_wins, cur_frontier_wins,
	       sizeof(prev_frontier_wins));
	memcpy(prev_frontier_live_misses, cur_frontier_live_misses,
	       sizeof(prev_frontier_live_misses));
	memcpy(prev_rq_saves, cur_rq_saves, sizeof(prev_rq_saves));
	memcpy(prev_rq_wins,  cur_rq_wins,  sizeof(prev_rq_wins));
	memcpy(prev_warm_reserve, cur_warm_reserve,
	       sizeof(prev_warm_reserve));
	memcpy(prev_warm_reserve_plateau, cur_warm_reserve_plateau,
	       sizeof(prev_warm_reserve_plateau));

	last_dump = now;
}
