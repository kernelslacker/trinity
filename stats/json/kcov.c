/*
 * KCOV JSON emitters for --stats-json.  Includes the two helpers
 * that also snapshot previous-window state (transition top-N and
 * per-syscall edges); they intentionally live with the rest of
 * the KCOV JSON so the side effect stays local to a KCOV read of
 * this file.
 */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "cmp_hints.h"
#include "kcov.h"
#include "stats-internal.h"
#include "stats/json/internal.h"
#include "stats_ring.h"
#include "syscall.h"
#include "tables.h"

static void json_emit_kcov_counters(void)
{
	unsigned long kc_edges, kc_pcs, kc_calls, kc_remote;
	unsigned long kc_cmp_records, kc_cmp_trunc, kc_cmp_bloom_skipped, kc_cmp_unique;
	unsigned long kc_cmp_strip_skipped;
	unsigned long kc_cmp_save_reject_nonconst;
	unsigned long kc_cmp_save_reject_uninteresting;
	unsigned long kc_cmp_save_reject_sentinel;
	unsigned long kc_cmp_save_reject_dup;
	unsigned long kc_cmp_save_reject_cap;
	/* PC-win conversion split by source-path.  cmp_hint_wins is
	 * per-DISPATCH; the split numerators (cmp_hint_pc_wins_by_pool[]
	 * summed for the flat-replay arm, cmp_hyp_pc_wins[/_by_kind] for
	 * the typed-hyp LIVE arm) are per-STASH-ENTRY.  The per-entry
	 * basis is the correct attribution granularity; flat_wins +
	 * typed_wins is NOT expected to equal cmp_hint_wins. */
	unsigned long kc_cmp_hint_wins;
	unsigned long kc_cmp_hints_injected;
	unsigned long kc_cmp_hyp_pc_wins;
	unsigned long kc_cmp_hyp_live_injected;
	unsigned long kc_cmp_hint_pc_wins_by_pool[CMP_HINT_POOL_KIND_NR];
	unsigned long kc_cmp_hyp_pc_wins_by_kind[CMP_HYP_KIND_NR];
	unsigned long kc_cmp_hyp_live_injected_by_kind[CMP_HYP_KIND_NR];
	unsigned int i;

	kc_edges  = __atomic_load_n(&kcov_shm->edges_found,  __ATOMIC_RELAXED);
	/* Dump path reads total_pcs / total_calls / remote_calls from
	 * parent_stats (per-child stats_ring feeds it). kcov_shm->total_calls
	 * is retained solely as the stamp source for last_edge_at[] /
	 * last_efault_at[]; the kcov_shm total_pcs and remote_calls slots
	 * have no stamp-role consumer and are not bumped. */
	kc_pcs    = parent_stats.total_pcs;
	kc_calls  = parent_stats.total_calls;
	kc_remote = parent_stats.remote_calls;
	kc_cmp_records = __atomic_load_n(&kcov_shm->cmp_records_collected,
		__ATOMIC_RELAXED);
	kc_cmp_trunc = __atomic_load_n(&kcov_shm->cmp_trace_truncated,
		__ATOMIC_RELAXED);
	kc_cmp_bloom_skipped = __atomic_load_n(&kcov_shm->cmp_hints_bloom_skipped,
		__ATOMIC_RELAXED);
	kc_cmp_strip_skipped = __atomic_load_n(&kcov_shm->cmp_hints_strip_skipped,
		__ATOMIC_RELAXED);
	kc_cmp_unique = __atomic_load_n(&kcov_shm->cmp_hints_unique_inserts,
		__ATOMIC_RELAXED);
	kc_cmp_save_reject_nonconst = __atomic_load_n(
		&kcov_shm->cmp_hints_save_reject_nonconst, __ATOMIC_RELAXED);
	kc_cmp_save_reject_uninteresting = __atomic_load_n(
		&kcov_shm->cmp_hints_save_reject_uninteresting, __ATOMIC_RELAXED);
	kc_cmp_save_reject_sentinel = __atomic_load_n(
		&kcov_shm->cmp_hints_save_reject_sentinel, __ATOMIC_RELAXED);
	kc_cmp_save_reject_dup = __atomic_load_n(
		&kcov_shm->cmp_hints_save_reject_dup, __ATOMIC_RELAXED);
	kc_cmp_save_reject_cap = __atomic_load_n(
		&kcov_shm->cmp_hints_save_reject_cap, __ATOMIC_RELAXED);
	kc_cmp_hint_wins = __atomic_load_n(&kcov_shm->cmp_hint_wins,
					   __ATOMIC_RELAXED);
	kc_cmp_hints_injected = __atomic_load_n(&kcov_shm->cmp_hints_injected,
						__ATOMIC_RELAXED);
	kc_cmp_hyp_pc_wins = __atomic_load_n(&kcov_shm->cmp_hyp_pc_wins,
					     __ATOMIC_RELAXED);
	kc_cmp_hyp_live_injected = __atomic_load_n(
		&kcov_shm->cmp_hyp_live_injected, __ATOMIC_RELAXED);
	for (i = 0; i < CMP_HINT_POOL_KIND_NR; i++)
		kc_cmp_hint_pc_wins_by_pool[i] = __atomic_load_n(
			&kcov_shm->cmp_hint_pc_wins_by_pool[i],
			__ATOMIC_RELAXED);
	for (i = 0; i < CMP_HYP_KIND_NR; i++) {
		kc_cmp_hyp_pc_wins_by_kind[i] = __atomic_load_n(
			&kcov_shm->cmp_hyp_pc_wins_by_kind[i],
			__ATOMIC_RELAXED);
		kc_cmp_hyp_live_injected_by_kind[i] = __atomic_load_n(
			&kcov_shm->cmp_hyp_live_injected_by_kind[i],
			__ATOMIC_RELAXED);
	}

	printf(",\"kcov\":{\"unique_edges\":%lu,\"total_pcs\":%lu,"
		"\"total_calls\":%lu,\"remote_calls\":%lu,"
		"\"cmp_records_collected\":%lu,\"cmp_trace_truncated\":%lu,"
		"\"cmp_hints_bloom_skipped\":%lu,\"cmp_hints_strip_skipped\":%lu,"
		"\"cmp_hints_unique_inserts\":%lu,"
		"\"cmp_hints_save_reject_nonconst\":%lu,"
		"\"cmp_hints_save_reject_uninteresting\":%lu,"
		"\"cmp_hints_save_reject_sentinel\":%lu,"
		"\"cmp_hints_save_reject_dup\":%lu,"
		"\"cmp_hints_save_reject_cap\":%lu,"
		"\"cmp_hint_wins\":%lu,\"cmp_hints_injected\":%lu,"
		"\"cmp_hyp_pc_wins\":%lu,\"cmp_hyp_live_injected\":%lu",
		kc_edges, kc_pcs, kc_calls, kc_remote,
		kc_cmp_records, kc_cmp_trunc, kc_cmp_bloom_skipped,
		kc_cmp_strip_skipped, kc_cmp_unique,
		kc_cmp_save_reject_nonconst, kc_cmp_save_reject_uninteresting,
		kc_cmp_save_reject_sentinel, kc_cmp_save_reject_dup,
		kc_cmp_save_reject_cap,
		kc_cmp_hint_wins, kc_cmp_hints_injected,
		kc_cmp_hyp_pc_wins, kc_cmp_hyp_live_injected);
	fputs(",\"cmp_hint_pc_wins_by_pool\":[", stdout);
	for (i = 0; i < CMP_HINT_POOL_KIND_NR; i++)
		printf("%s%lu", i ? "," : "", kc_cmp_hint_pc_wins_by_pool[i]);
	fputs("],\"cmp_hyp_pc_wins_by_kind\":[", stdout);
	for (i = 0; i < CMP_HYP_KIND_NR; i++)
		printf("%s%lu", i ? "," : "", kc_cmp_hyp_pc_wins_by_kind[i]);
	fputs("],\"cmp_hyp_live_injected_by_kind\":[", stdout);
	for (i = 0; i < CMP_HYP_KIND_NR; i++)
		printf("%s%lu", i ? "," : "", kc_cmp_hyp_live_injected_by_kind[i]);
	fputc(']', stdout);
}

/* Shadow transition-coverage globals.  Emitted unconditionally
 * so consumers can rely on a stable schema; both fields are 0
 * when the mode is OFF (the per-PC hash never runs and the
 * shared counters stay at their post-memset zero). */
static void json_emit_kcov_transition_globals(void)
{
	unsigned long kc_tedges = __atomic_load_n(
		&kcov_shm->transition_edges_found,
		__ATOMIC_RELAXED);
	unsigned long kc_tdistinct = __atomic_load_n(
		&kcov_shm->transition_distinct_edges,
		__ATOMIC_RELAXED);

	printf(",\"transition_edges_found\":%lu,"
		"\"transition_distinct_edges\":%lu",
		kc_tedges, kc_tdistinct);
}

static void json_emit_kcov_topn(const struct syscalltable *table,
				unsigned int nr_syscalls_to_scan)
{
	unsigned int i, j;
	unsigned int top_nr[10];
	unsigned long top_edges[10];
	unsigned int top_count = 0;
	unsigned int delta_nr[10];
	unsigned long delta_edges[10];
	unsigned int delta_count = 0;

	memset(top_edges, 0, sizeof(top_edges));
	memset(delta_edges, 0, sizeof(delta_edges));

	for (i = 0; i < nr_syscalls_to_scan; i++) {
		unsigned long edges = per_syscall_edges_total(i);
		unsigned long prev  = per_syscall_edges_previous_total(i);
		unsigned long delta = sat_sub_ul(edges, prev);

		if (edges > 0)
			topn_push(top_edges, top_nr, &top_count, 10, edges, i);

		if (delta > 0)
			topn_push(delta_edges, delta_nr, &delta_count, 10, delta, i);
	}

	fputs(",\"top_syscalls\":[", stdout);
	for (j = 0; j < top_count; j++) {
		struct syscallentry *entry = table[top_nr[j]].entry;

		if (j > 0)
			putchar(',');
		fputs("{\"name\":", stdout);
		json_emit_string(entry ? entry->name : "???");
		printf(",\"edges\":%lu}", top_edges[j]);
	}
	putchar(']');

	fputs(",\"top_recent_growth\":[", stdout);
	for (j = 0; j < delta_count; j++) {
		struct syscallentry *entry = table[delta_nr[j]].entry;

		if (j > 0)
			putchar(',');
		fputs("{\"name\":", stdout);
		json_emit_string(entry ? entry->name : "???");
		printf(",\"delta\":%lu}", delta_edges[j]);
	}
	putchar(']');
}

/* Shadow transition-coverage top-N: cumulative by real
 * transition-slot count, and per-interval growth by call-count
 * delta.  Mirrors the PC top_syscalls / top_recent_growth blocks
 * directly above so the two signals share the JSON shape.  Both
 * arrays come out empty when the mode is OFF since the per-
 * syscall counters never get bumped. */
static void json_emit_kcov_transition_topn(const struct syscalltable *table,
					   unsigned int nr_syscalls_to_scan)
{
	unsigned int i, j;
	unsigned int tr_top_nr[10];
	unsigned long tr_top_edges[10];
	unsigned int tr_top_count = 0;
	unsigned int tr_delta_nr[10];
	unsigned long tr_delta_edges[10];
	unsigned int tr_delta_count = 0;

	memset(tr_top_edges, 0, sizeof(tr_top_edges));
	memset(tr_delta_edges, 0, sizeof(tr_delta_edges));
	for (i = 0; i < nr_syscalls_to_scan; i++) {
		unsigned long real = __atomic_load_n(
			&kcov_shm->per_syscall_transition_edges_real[i],
			__ATOMIC_RELAXED);
		unsigned long curr = __atomic_load_n(
			&kcov_shm->per_syscall_transition_edges[i],
			__ATOMIC_RELAXED);
		unsigned long prev = kcov_shm->per_syscall_transition_edges_previous[i];
		unsigned long delta = sat_sub_ul(curr, prev);

		if (real > 0)
			topn_push(tr_top_edges, tr_top_nr,
				  &tr_top_count, 10, real, i);
		if (delta > 0)
			topn_push(tr_delta_edges, tr_delta_nr,
				  &tr_delta_count, 10, delta, i);
	}

	fputs(",\"top_transition_syscalls\":[", stdout);
	for (j = 0; j < tr_top_count; j++) {
		struct syscallentry *entry = table[tr_top_nr[j]].entry;

		if (j > 0)
			putchar(',');
		fputs("{\"name\":", stdout);
		json_emit_string(entry ? entry->name : "???");
		printf(",\"transitions\":%lu}",
		       tr_top_edges[j]);
	}
	putchar(']');

	fputs(",\"top_transition_recent_growth\":[", stdout);
	for (j = 0; j < tr_delta_count; j++) {
		struct syscallentry *entry = table[tr_delta_nr[j]].entry;

		if (j > 0)
			putchar(',');
		fputs("{\"name\":", stdout);
		json_emit_string(entry ? entry->name : "???");
		printf(",\"delta\":%lu}", tr_delta_edges[j]);
	}
	putchar(']');

	for (i = 0; i < nr_syscalls_to_scan; i++)
		kcov_shm->per_syscall_transition_edges_previous[i] =
			__atomic_load_n(
				&kcov_shm->per_syscall_transition_edges[i],
				__ATOMIC_RELAXED);
}

static void json_emit_kcov_cold_syscalls(const struct syscalltable *table,
					 unsigned int nr_syscalls_to_scan)
{
	unsigned int i;
	bool first_cold = true;

	fputs(",\"cold_syscalls\":[", stdout);
	for (i = 0; i < nr_syscalls_to_scan; i++) {
		unsigned long slot_edges = per_syscall_edges_total(i);
		struct syscallentry *entry;

		if (slot_edges == 0)
			continue;
		if (!kcov_syscall_is_cold(i))
			continue;

		entry = table[i].entry;
		if (!first_cold)
			putchar(',');
		fputs("{\"name\":", stdout);
		json_emit_string(entry ? entry->name : "???");
		printf(",\"edges\":%lu,\"last_edge_at\":%lu}",
			slot_edges, kcov_shm->last_edge_at[i]);
		first_cold = false;
	}
	putchar(']');
}

/* Snapshot current counts for the next interval, matching text path. */
static void json_emit_kcov_snapshot_previous(unsigned int nr_syscalls_to_scan)
{
	unsigned int i;

	for (i = 0; i < nr_syscalls_to_scan; i++) {
		kcov_shm->per_syscall_edges_previous[i][0] =
			__atomic_load_n(&kcov_shm->per_syscall_edges[i][0],
					__ATOMIC_RELAXED);
		kcov_shm->per_syscall_edges_previous[i][1] =
			__atomic_load_n(&kcov_shm->per_syscall_edges[i][1],
					__ATOMIC_RELAXED);
	}
}

void json_emit_kcov_section(void)
{
	const struct syscalltable *table;
	unsigned int nr_syscalls_to_scan;

	if (kcov_shm == NULL) {
		fputs(",\"kcov\":null", stdout);
		return;
	}

	nr_syscalls_to_scan = biarch ? max_nr_64bit_syscalls : max_nr_syscalls;
	if (nr_syscalls_to_scan > MAX_NR_SYSCALL)
		nr_syscalls_to_scan = MAX_NR_SYSCALL;
	table = biarch ? syscalls_64bit : syscalls;

	json_emit_kcov_counters();
	json_emit_kcov_transition_globals();
	json_emit_kcov_topn(table, nr_syscalls_to_scan);
	json_emit_kcov_transition_topn(table, nr_syscalls_to_scan);
	json_emit_kcov_cold_syscalls(table, nr_syscalls_to_scan);
	json_emit_kcov_snapshot_previous(nr_syscalls_to_scan);

	putchar('}');
}
