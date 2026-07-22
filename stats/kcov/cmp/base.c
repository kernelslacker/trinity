/*
 * Scalar CMP pipeline rows and shared rate-line helper.
 *
 * kcov_cmp_rate_line() is the shared periodic "name +delta (rate/s, total)"
 * emitter used by every render block in stats/kcov/cmp/.  Zero-delta rows
 * stay silent so unarmed windows and idle counters never appear in the dump.
 * Keep the format string identical: this is an output-contract row consumed
 * by grep-safe scans over stats.log.
 *
 * kcov_cmp_observability_block_render() renders the per-window scalar
 * CMP-rich syscalls table.  kcov_cmp_render_wild_write_delta() renders the
 * wild-write corruption-channel rows.  Both are called only from
 * kcov_cmp_stats_periodic_dump() in stats/kcov/cmp/periodic.c and stay in
 * this TU because they carry the shared kcov_cmp_rate_line() dependency and
 * the top-N scalar layout for the base CMP pipeline.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <sys/utsname.h>
#include <stdio.h>
#include "arch.h"
#include "child-api.h"
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

/*
 * observability table: top syscalls by per-window
 * cmp-insert delta, with the matching injected / hint_pc_wins / edge
 * deltas in adjacent columns so the operator can read the conversion
 * funnel without grepping a flat key/value dump.  The "CMP-rich but
 * unconverted" diagnostic signature is high cmp+ and injected+ with low
 * pc-wins+ and edge+ -- the row format puts those four numbers
 * side-by-side so the visual scan is single-line per syscall.
 *
 * Window snapshots live in function-static arrays (MAX_NR_SYSCALL of
 * unsigned long apiece, ~32 KiB total BSS in this TU) rather than in
 * kcov_shm: the dump consumer is single-owner (the parent's periodic
 * tick), so a per-tick window state in shm would just duplicate state
 * without adding any cross-process value, and the BSS cost is paid
 * once per process, not per child.  The existing per_syscall_*_previous
 * arrays in kcov_shm are consumed by dump_stats() at run shutdown and
 * by the JSON dump, with no defined update cadence; reusing them here
 * would silently desync the window deltas.
 */
void kcov_cmp_observability_block_render(long elapsed __unused__)
{
	static unsigned long prev_cmp_inserts[MAX_NR_SYSCALL];
	static unsigned long prev_cmp_injected[MAX_NR_SYSCALL];
	static unsigned long prev_pc_wins[MAX_NR_SYSCALL];
	static unsigned long prev_edges[MAX_NR_SYSCALL];
	static unsigned long prev_reject_cap[MAX_NR_SYSCALL];
	static bool armed;
	unsigned int top_nr[10];
	unsigned long top_cmp[10];
	unsigned long top_injected[10];
	unsigned long top_pc_wins[10];
	unsigned long top_edges[10];
	unsigned long top_reject_cap[10];
	unsigned int top_count = 0;
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

	memset(top_cmp, 0, sizeof(top_cmp));
	memset(top_injected, 0, sizeof(top_injected));
	memset(top_pc_wins, 0, sizeof(top_pc_wins));
	memset(top_edges, 0, sizeof(top_edges));
	memset(top_reject_cap, 0, sizeof(top_reject_cap));

	for (i = 0; i < nr_syscalls_to_scan; i++) {
		unsigned long cur_inserts = __atomic_load_n(
			&kcov_shm->per_syscall_cmp.per_syscall_cmp_inserts[i], __ATOMIC_RELAXED);
		unsigned long cur_injected = __atomic_load_n(
			&kcov_shm->cmp_hint_ps.per_syscall_cmp_injected[i], __ATOMIC_RELAXED);
		unsigned long cur_pc_wins = __atomic_load_n(
			&kcov_shm->cmp_hint_ps.per_syscall_cmp_hint_pc_wins[i], __ATOMIC_RELAXED);
		unsigned long cur_edges = per_syscall_edges_total(i);
		unsigned long cur_reject_cap = __atomic_load_n(
			&kcov_shm->hint_tier.per_syscall_cmp_reject_cap[i], __ATOMIC_RELAXED);
		unsigned long delta_inserts;
		unsigned long delta_injected;
		unsigned long delta_pc_wins;
		unsigned long delta_edges;
		unsigned long delta_reject_cap;
		unsigned int k;

		/* First window: arm the snapshot and skip emit so any
		 * pre-existing cumulative counts (warm-start / prior epoch)
		 * are not mis-attributed to the first dump window. */
		if (!armed) {
			prev_cmp_inserts[i] = cur_inserts;
			prev_cmp_injected[i] = cur_injected;
			prev_pc_wins[i] = cur_pc_wins;
			prev_edges[i] = cur_edges;
			prev_reject_cap[i] = cur_reject_cap;
			continue;
		}

		/* Guarded unsigned subtraction.  Counters are monotonic in
		 * the steady-state case but a cmp-hints warm-start that
		 * lands between two dumps can publish a lower value; clamp
		 * to zero so a one-shot warm-start doesn't underflow into a
		 * ~ULONG_MAX delta the topn picker would pin to slot 0. */
		delta_inserts    = sat_sub_ul(cur_inserts,    prev_cmp_inserts[i]);
		delta_injected   = sat_sub_ul(cur_injected,   prev_cmp_injected[i]);
		delta_pc_wins    = sat_sub_ul(cur_pc_wins,    prev_pc_wins[i]);
		delta_edges      = sat_sub_ul(cur_edges,      prev_edges[i]);
		delta_reject_cap = sat_sub_ul(cur_reject_cap, prev_reject_cap[i]);

		prev_cmp_inserts[i] = cur_inserts;
		prev_cmp_injected[i] = cur_injected;
		prev_pc_wins[i] = cur_pc_wins;
		prev_edges[i] = cur_edges;
		prev_reject_cap[i] = cur_reject_cap;

		if (delta_inserts == 0)
			continue;

		/* Rank by cmp_inserts delta: that's the producer-side
		 * "kernel emitted distinct CMP signal for this syscall"
		 * column, which is the one the PHASE-0 hold cares about.
		 * Insertion sort on the arrays in lock-step so the
		 * top-N rows stay aligned across columns.  reject_cap+
		 * rides alongside inserts+ so the (reject_cap / inserts)
		 * ratio reads out per row: ~0 across the top-20 means the
		 * per-syscall pool is novelty-starved and widening the cap
		 * will not help; high means cap-bound and expansion should. */
		for (j = top_count; j > 0 && delta_inserts > top_cmp[j - 1]; j--) {
			if (j < 10) {
				top_cmp[j]        = top_cmp[j - 1];
				top_injected[j]   = top_injected[j - 1];
				top_pc_wins[j]    = top_pc_wins[j - 1];
				top_edges[j]      = top_edges[j - 1];
				top_reject_cap[j] = top_reject_cap[j - 1];
				top_nr[j]         = top_nr[j - 1];
			}
		}
		k = j;
		if (k < 10) {
			top_cmp[k]        = delta_inserts;
			top_injected[k]   = delta_injected;
			top_pc_wins[k]    = delta_pc_wins;
			top_edges[k]      = delta_edges;
			top_reject_cap[k] = delta_reject_cap;
			top_nr[k]         = i;
			if (top_count < 10)
				top_count++;
		}
	}

	if (!armed) {
		armed = true;
		return;
	}

	if (top_count == 0)
		return;

	stats_log_write("KCOV CMP-rich syscalls (top by per-window cmp_inserts delta):\n");
	stats_log_write("  %-24s %10s %10s %10s %10s %10s\n",
			"syscall", "cmp+", "injected+", "pc-wins+", "edge+",
			"rejcap+");
	for (j = 0; j < top_count; j++) {
		struct syscallentry *entry = table[top_nr[j]].entry;
		const char *name = entry ? entry->name : "???";

		stats_log_write("  %-24s %10lu %10lu %10lu %10lu %10lu\n",
				name, top_cmp[j], top_injected[j],
				top_pc_wins[j], top_edges[j],
				top_reject_cap[j]);
	}
}
void kcov_cmp_render_wild_write_delta(long elapsed,
					     unsigned long delta_count_oob, unsigned long cur_count_oob,
					     unsigned long delta_canary_lock_post, unsigned long cur_canary_lock_post,
					     unsigned long delta_canary_pre, unsigned long cur_canary_pre,
					     unsigned long delta_canary_post, unsigned long cur_canary_post)
{
	/* Wild-write detection: any non-zero delta is news, and the
	 * 0/s rate noise of a one-shot stomp is fine -- the canary
	 * counters surface a real corruption channel, not a hot-path
	 * statistic, so the same row format is used as the rest. */
	kcov_cmp_rate_line(elapsed, "cmp_hints_count_oob", delta_count_oob, cur_count_oob);
	kcov_cmp_rate_line(elapsed, "cmp_hints_canary_lock_post_corrupt", delta_canary_lock_post, cur_canary_lock_post);
	kcov_cmp_rate_line(elapsed, "cmp_hints_canary_pre_corrupt", delta_canary_pre, cur_canary_pre);
	kcov_cmp_rate_line(elapsed, "cmp_hints_canary_post_corrupt", delta_canary_post, cur_canary_post);
}
