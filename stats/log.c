/*
 * --stats-log-file and --stats-timeseries backing.
 *
 * Carved verbatim out of stats.c.  Contains the two file-handle
 * lifecycles and their write-path helpers: stats_log_open,
 * stats_log_close, stats_log_write, and stats_log_drop_in_child for
 * the human-readable dump log; stats_timeseries_open,
 * stats_timeseries_close, stats_timeseries_emit_window, and
 * stats_timeseries_drop_in_child for the per-window per-syscall CSV
 * timeseries.  The file-static state (stats_log_fp,
 * stats_timeseries_fp, and the prev-window edges snapshot
 * stats_ts_prev_per_syscall_edges) stays private to this TU -- only
 * this cluster's helpers ever touch it.
 *
 * All the exported entry points here are already declared in
 * include/stats.h so nothing new is added to stats-internal.h.
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
#include "strategy.h"
#include "syscall.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"
#include "utils.h"
#include "version.h"

/*
 * --stats-log-file backing.  The file is opened in append mode at startup
 * (so multiple runs into the same file accrue history rather than clobber
 * each other) and closed at shutdown.  Each open/close writes a single
 * header/footer marker line so the log is self-delimiting; per-line wall
 * clocks would just bloat the dump output -- the dump's own [main] prefix
 * and the open marker's ISO timestamp let the reader anchor entries.
 */
static FILE *stats_log_fp = NULL;

#define STATS_LOG_TS_BUFSIZE	48
#define STATS_LOG_LINE_BUFSIZE	1024

static void stats_log_iso_timestamp(char *buf, size_t buflen)
{
	time_t now = time(NULL);
	struct tm tmv;

	if (gmtime_r(&now, &tmv) == NULL) {
		snprintf(buf, buflen, "?");
		return;
	}
	if (strftime(buf, buflen, "%Y-%m-%dT%H:%M:%SZ", &tmv) == 0)
		snprintf(buf, buflen, "?");
}

void stats_log_open(const char *path)
{
	char ts[STATS_LOG_TS_BUFSIZE];

	if (path == NULL || *path == '\0')
		return;

	stats_log_fp = fopen(path, "a");
	if (stats_log_fp == NULL) {
		outputerr("failed to open stats log file %s: %s\n",
			  path, strerror(errno));
		return;
	}

	stats_log_iso_timestamp(ts, sizeof(ts));
	fprintf(stats_log_fp,
		"\n=== trinity stats log opened at %s pid=%d ===\n",
		ts, (int)mypid());
	fflush(stats_log_fp);
}

void stats_log_close(void)
{
	char ts[STATS_LOG_TS_BUFSIZE];

	if (stats_log_fp == NULL)
		return;

	stats_log_iso_timestamp(ts, sizeof(ts));
	fprintf(stats_log_fp,
		"=== trinity stats log closed at %s ===\n", ts);
	fclose(stats_log_fp);
	stats_log_fp = NULL;
}

/*
 * Per-syscall timeseries log (--stats side-effect).
 *
 * When --stats is passed, append one JSON-Lines record per print_stats()
 * window to stats-timeseries-<epoch>.jsonl in the operator's launch CWD
 * (opened from main_init() before change_tmp_dir(), mirroring the
 * --stats-log-file path-resolution rule).  Each line carries the
 * current op_count, the parent's distinct-edge total, and a per-syscall
 * {nr,edges,calls} array over enabled syscalls.  The per-syscall
 * "edges" field is bucket_bits_real (the same real edge metric the
 * full --stats dump reports per syscall), not the productive-call
 * counter -- those are exposed separately as "calls".  No flag of its
 * own -- the operator gets it whenever they ask for --stats.
 *
 * Same fd-leak hazard as stats_log_*: fopen() leaves an ordinary
 * non-CLOEXEC fd in the table; fork() shares it; the syscall fuzzer in
 * the child can reach it numerically.  stats_timeseries_drop_in_child()
 * is called alongside stats_log_drop_in_child() from every fork()'d
 * child entry point.
 */
static FILE *stats_timeseries_fp = NULL;

void stats_timeseries_open(void)
{
	char path[64];
	time_t now;

	if (show_stats == false)
		return;

	now = time(NULL);
	snprintf(path, sizeof(path),
		 "stats-timeseries-%lld.jsonl", (long long)now);

	stats_timeseries_fp = fopen(path, "a");
	if (stats_timeseries_fp == NULL) {
		outputerr("failed to open stats timeseries file %s: %s\n",
			  path, strerror(errno));
		return;
	}
}

void stats_timeseries_close(void)
{
	if (stats_timeseries_fp == NULL)
		return;
	fclose(stats_timeseries_fp);
	stats_timeseries_fp = NULL;
}

void stats_timeseries_drop_in_child(void)
{
	if (stats_timeseries_fp == NULL)
		return;
	close(fileno(stats_timeseries_fp));
	stats_timeseries_fp = NULL;
}

/* Rewind-guarded window delta over a monotonic counter.  Common shape
 * repeated for every _gained / _delta field the emit surfaces: current
 * minus previously snapshotted, snapshot the current into prev, guard
 * against a rewound source counter (bounded shm counter, resume-from-
 * checkpoint, etc.) so we never emit a wrap-around negative-as-huge
 * delta. */
static unsigned long stats_ts_window_delta(unsigned long cur,
					   unsigned long *prev)
{
	unsigned long delta = sat_sub_ul(cur, *prev);

	*prev = cur;
	return delta;
}

/* Previous window's per-syscall counters, per (nr, arch), for the
 * per-syscall _gained deltas.  Zero-initialised, so the first window's
 * delta equals the level (matching the top-level edges_gained_this_
 * window convention).  Sized by MAX_NR_SYSCALL rather than the active
 * count because entry->number is the stable numeric key we index by.
 *
 * bucket_bits_real (edges) IS arch-split at the shm side
 * (per_syscall_diag[nr][arch_ix].bucket_bits_real) so its prev array
 * carries the arch dim naturally.  The remaining counters are per-nr
 * only at the shm side (local_pc_edge_count[nr] etc), but the prev
 * array still carries the arch dim: in biarch mode the same nr
 * appears twice (once per table walk) and both entries need to see
 * the same delta.  Snapshotting per-arch lets each walk read a fresh
 * prev (last window's same-arch snapshot) and emit an identical
 * delta without a deferred commit pass.  MAX_NR_SYSCALL * 4 fields *
 * 2 arch * sizeof(unsigned long) = 64 KiB total, all static in the
 * parent process. */
static unsigned long stats_ts_prev_per_syscall_edges[MAX_NR_SYSCALL][2];
static unsigned long stats_ts_prev_per_syscall_local_edges[MAX_NR_SYSCALL][2];
static unsigned long stats_ts_prev_per_syscall_remote_edges[MAX_NR_SYSCALL][2];
static unsigned long stats_ts_prev_per_syscall_cmp_injected[MAX_NR_SYSCALL][2];
static unsigned long stats_ts_prev_per_syscall_cmp_hint_pc_wins[MAX_NR_SYSCALL][2];
/* Typed-inject partition of cmp_injected.  Sourced from parent_stats
 * (stats_ring drain target) rather than kcov_shm -- the counter lives
 * outside the wild-write attack surface, same discipline as
 * per_syscall_cmp_returned/_attempts.  Same [arch] dim as the sibling
 * per-syscall prev arrays so biarch mode's two table walks each read a
 * fresh same-arch prev without a deferred commit. */
static unsigned long stats_ts_prev_per_syscall_cmp_hyp_live_injected[MAX_NR_SYSCALL][2];

/* Previous window's per-childop counters for the by_childop attribution
 * block.  Same rewind-guarded delta shape as the per-syscall prev arrays
 * but indexed by enum child_op_type -- lets a coverage-window consumer
 * answer "which childop drove this window's edge jump?" for the wide
 * class of windows where per-syscall deltas came back zero because the
 * wins came from alt-op dispatches (recipe_runner / genetlink_fuzzer /
 * futex_storm / af_unix_scm_rights_gc_churn / pagecache_canary_check /
 * perf_chains / fs_lifecycle).  Sized by NR_CHILD_OP_TYPES; parent-
 * static like the syscall arrays. */
static unsigned long stats_ts_prev_childop_edges_discovered[NR_CHILD_OP_TYPES];
static unsigned long stats_ts_prev_childop_edges_clean[NR_CHILD_OP_TYPES];
static unsigned long stats_ts_prev_childop_calls_with_edges[NR_CHILD_OP_TYPES];
static unsigned long stats_ts_prev_childop_invocations[NR_CHILD_OP_TYPES];
static unsigned long stats_ts_prev_childop_would_promote[NR_CHILD_OP_TYPES];
static unsigned long stats_ts_prev_childop_would_demote[NR_CHILD_OP_TYPES];

/* Walk one syscall table and emit
 * {"nr":N,"arch":"64","name":"read","edges":E,"edges_gained":G,
 *  "kcov_calls":K,"attempted_calls":A,
 *  "local_edges":L,"local_edges_gained":LG,"remote_edges":R,
 *  "remote_edges_gained":RG,"cmp_injected":CI,"cmp_injected_gained":CIG,
 *  "cmp_hint_pc_wins":CW,"cmp_hint_pc_wins_gained":CWG,
 *  "cmp_hyp_live_injected":HI,"cmp_hyp_live_injected_gained":HIG}
 * entries for each enabled slot whose entry pointer is non-NULL.
 * *first tracks whether the next entry needs a leading comma so the
 * caller can chain the 32-bit and 64-bit tables into a single array
 * literal.  do32 selects the arch dim into per_syscall_diag[][],
 * matching the kcov_diag_emit_block() convention (false=64-bit,
 * true=32-bit).
 *
 * arch and name are emitted per row so a run-analysis consumer
 * grouping by nr does not silently merge biarch's 32-bit and 64-bit
 * halves (both tables index into the same nr keyspace, so a naive
 * group-by-nr collapses ~204 pairs into one).  arch is the string
 * "32" or "64" -- readable without a legend and stable across
 * archs where do32 is a boolean anyway; name comes straight from
 * entry->name so a plateau consumer does not need to link against
 * the syscall tables to label the row.
 *
 * kcov_calls and attempted_calls are named explicitly (replacing the
 * ambiguous "calls" this used to emit as entry->attempted) because
 * they measure different denominators: kcov_calls is the KCOV-bracketed
 * count kcov_collect() bumps into per_syscall_calls[], while
 * attempted_calls is the entry->attempted dispatch count -- larger,
 * covering EXTRA_FORK / validator-rejected / dry-run paths where the
 * kcov bracket never runs.  Callers comparing ratios across the two
 * tripped over shared naming before.
 *
 * edges_gained is the per-syscall analogue of the top-level
 * edges_gained_this_window: current edges minus the same slot's edges
 * at the previous window emit.  Kept alongside the cumulative edges,
 * not in place of it, so consumers that were reading edges keep working
 * and per-slot plateaus are legible without differencing consecutive
 * lines.  Also updates the prev array in-place before returning.
 *
 * local_edges / remote_edges partition the per-syscall fresh-edge
 * count by kcov collection mode (local PC vs KCOV_MODE_REMOTE) so a
 * run-analysis consumer can tell whether a syscall's late-window edge
 * burst came from synchronously sampled local coverage or from the
 * remote-sample path -- the "was this the remote path finally paying
 * off, or the local path just now waking up" attribution that pairs
 * with the syscall's edges_gained.  cmp_injected / cmp_hint_pc_wins
 * partition per-syscall CMP-hint conversion (targets committed to the
 * syscall's arg surface vs the subset of those hints that drove new
 * PC coverage on that call), so the CMP-targeting decision can be
 * routed on real per-syscall conversion rate rather than the flat
 * cmp_hints_injected total.  cmp_hyp_live_injected is the typed-inject
 * (hypothesis-store) subset of cmp_injected: joining it with
 * local_edges / remote_edges tells a run-analysis consumer whether the
 * typed derive-and-inject arm is aimed at the syscalls actually moving
 * coverage, a signal cmp_injected alone (raw + typed conflated) cannot
 * answer.  All five per-nr counters are cumulative lifetime totals;
 * the _gained siblings are per-window deltas with the same rewind
 * guard as edges_gained. */
static void stats_timeseries_emit_table(const struct syscalltable *table,
					unsigned int n, bool do32,
					bool *first)
{
	unsigned int i;
	unsigned int arch_ix = do32 ? 1 : 0;

	for (i = 0; i < n; i++) {
		struct syscallentry *entry = table[i].entry;
		unsigned int nr, attempted_calls;
		unsigned long edges = 0;
		unsigned long edges_gained = 0;
		unsigned long kcov_calls = 0;
		unsigned long local_edges = 0;
		unsigned long remote_edges = 0;
		unsigned long cmp_injected = 0;
		unsigned long cmp_hint_pc_wins = 0;
		unsigned long cmp_hyp_live_injected = 0;
		unsigned long local_edges_gained = 0;
		unsigned long remote_edges_gained = 0;
		unsigned long cmp_injected_gained = 0;
		unsigned long cmp_hint_pc_wins_gained = 0;
		unsigned long cmp_hyp_live_injected_gained = 0;

		if (entry == NULL)
			continue;
		if (entry->active_number == 0)
			continue;

		nr = entry->number;
		attempted_calls = entry->attempted;
		if (nr < MAX_NR_SYSCALL && kcov_shm != NULL) {
			edges = __atomic_load_n(
				&kcov_shm->per_syscall_cmp.per_syscall_diag[nr][arch_ix].bucket_bits_real,
				__ATOMIC_RELAXED);
			kcov_calls = per_syscall_calls_total(nr);
			local_edges = __atomic_load_n(
				&kcov_shm->pc_ctx.local_pc_edge_count[nr],
				__ATOMIC_RELAXED);
			remote_edges = __atomic_load_n(
				&kcov_shm->pc_ctx.remote_pc_edge_count[nr],
				__ATOMIC_RELAXED);
			cmp_injected = __atomic_load_n(
				&kcov_shm->cmp_hint_ps.per_syscall_cmp_injected[nr],
				__ATOMIC_RELAXED);
			cmp_hint_pc_wins = __atomic_load_n(
				&kcov_shm->cmp_hint_ps.per_syscall_cmp_hint_pc_wins[nr],
				__ATOMIC_RELAXED);
		}

		/* Sourced from parent_stats, not kcov_shm: the typed-inject
		 * per-nr denominator is drained through the stats_ring and
		 * lives in MAP_PRIVATE parent memory the kernel cannot
		 * scribble.  Read is unlocked because timeseries emit runs
		 * from parent main_loop context alongside the ring drain --
		 * no cross-thread writer. */
		if (nr < MAX_NR_SYSCALL)
			cmp_hyp_live_injected =
				parent_stats.per_syscall_cmp_hyp_live_injected[nr];

		if (nr < MAX_NR_SYSCALL) {
			edges_gained = stats_ts_window_delta(
				edges,
				&stats_ts_prev_per_syscall_edges[nr][arch_ix]);
			local_edges_gained = stats_ts_window_delta(
				local_edges,
				&stats_ts_prev_per_syscall_local_edges[nr][arch_ix]);
			remote_edges_gained = stats_ts_window_delta(
				remote_edges,
				&stats_ts_prev_per_syscall_remote_edges[nr][arch_ix]);
			cmp_injected_gained = stats_ts_window_delta(
				cmp_injected,
				&stats_ts_prev_per_syscall_cmp_injected[nr][arch_ix]);
			cmp_hint_pc_wins_gained = stats_ts_window_delta(
				cmp_hint_pc_wins,
				&stats_ts_prev_per_syscall_cmp_hint_pc_wins[nr][arch_ix]);
			cmp_hyp_live_injected_gained = stats_ts_window_delta(
				cmp_hyp_live_injected,
				&stats_ts_prev_per_syscall_cmp_hyp_live_injected[nr][arch_ix]);
		}

		fprintf(stats_timeseries_fp,
			"%s{\"nr\":%u,\"arch\":\"%s\",\"name\":\"%s\""
			",\"edges\":%lu,\"edges_gained\":%lu"
			",\"kcov_calls\":%lu,\"attempted_calls\":%u"
			",\"local_edges\":%lu,\"local_edges_gained\":%lu"
			",\"remote_edges\":%lu,\"remote_edges_gained\":%lu"
			",\"cmp_injected\":%lu,\"cmp_injected_gained\":%lu"
			",\"cmp_hint_pc_wins\":%lu,\"cmp_hint_pc_wins_gained\":%lu"
			",\"cmp_hyp_live_injected\":%lu,\"cmp_hyp_live_injected_gained\":%lu}",
			*first ? "" : ",", nr, do32 ? "32" : "64",
			entry->name != NULL ? entry->name : "",
			edges, edges_gained,
			kcov_calls, attempted_calls,
			local_edges, local_edges_gained,
			remote_edges, remote_edges_gained,
			cmp_injected, cmp_injected_gained,
			cmp_hint_pc_wins, cmp_hint_pc_wins_gained,
			cmp_hyp_live_injected, cmp_hyp_live_injected_gained);
		*first = false;
	}
}

/* Head of the record.  Order chosen so existing consumers
 * reading the first three fields keep working; new fields
 * append.  Returns the freshly loaded distinct-edge total so
 * stats_ts_emit_baselines can reuse it -- edges_run_gained
 * differences the same reading against the warm-load baseline
 * and must see the same value that was reported at the head to
 * stay consistent within a single window record. */
static unsigned long stats_ts_emit_record_head(FILE *fp, unsigned long op_count)
{
	/* Previous window's distinct-edge total, for the top-level
	 * edges_gained_this_window delta.  Zero-initialised so the
	 * first window's delta equals the level (a plateau consumer
	 * gets a real first value instead of a phantom zero). */
	static unsigned long prev_edges_total = 0;
	unsigned long edges_total = 0;
	unsigned long edges_gained_this_window;

	if (kcov_shm != NULL)
		edges_total = __atomic_load_n(&kcov_shm->coverage.distinct_edges,
					      __ATOMIC_RELAXED);

	edges_gained_this_window = stats_ts_window_delta(edges_total,
							 &prev_edges_total);

	fprintf(fp,
		"{\"t\":%lu,\"edges_total\":%lu,\"edges_gained_this_window\":%lu",
		op_count, edges_total, edges_gained_this_window);

	return edges_total;
}

/* Bucket-bit sibling + warm-load baselines + run-owned deltas.
 * edges_run_gained and edges_found_run_gained let the first
 * window's line be interpreted as "gained since this run
 * started" instead of the whole warm-loaded corpus. */
static void stats_ts_emit_baselines(FILE *fp, unsigned long edges_total)
{
	/* Bucket-bit sibling of prev_edges_total; kcov_shm->coverage.edges_found
	 * grows with bucket churn on already-known edges so its delta
	 * stays live even when distinct edges have plateaued -- this is
	 * the "cmp is still rising while pc is flat" signal the plateau
	 * classifier reads from strategy_plateau_hypothesis_check(). */
	static unsigned long prev_edges_found_total = 0;
	unsigned long edges_found_total = 0;
	unsigned long edges_found_gained;
	unsigned long edges_warm_loaded = 0;
	unsigned long distinct_edges_warm_loaded = 0;

	if (kcov_shm != NULL) {
		edges_found_total = __atomic_load_n(&kcov_shm->coverage.edges_found,
						    __ATOMIC_RELAXED);
		edges_warm_loaded = __atomic_load_n(
			&kcov_shm->coverage.edges_warm_loaded, __ATOMIC_RELAXED);
		distinct_edges_warm_loaded = __atomic_load_n(
			&kcov_shm->coverage.distinct_edges_warm_loaded,
			__ATOMIC_RELAXED);
	}

	edges_found_gained = stats_ts_window_delta(edges_found_total,
						   &prev_edges_found_total);

	fprintf(fp,
		",\"edges_found_total\":%lu,\"edges_found_gained\":%lu"
		",\"edges_warm_loaded\":%lu,\"distinct_edges_warm_loaded\":%lu"
		",\"edges_run_gained\":%lu,\"edges_found_run_gained\":%lu",
		edges_found_total, edges_found_gained,
		edges_warm_loaded, distinct_edges_warm_loaded,
		sat_sub_ul(edges_total, distinct_edges_warm_loaded),
		sat_sub_ul(edges_found_total, edges_warm_loaded));
}

/* Trace / cmp-trace truncation snapshots.  Level tells the
 * operator how many collect calls have ever hit the buffer cap;
 * the delta partitioned per-window is the decision-relevant
 * signal (a burst of truncations concentrated in the same
 * window as a coverage plateau is the smoking gun for
 * KCOV_TRACE_SIZE / KCOV_CMP_BUFFER_SIZE undersizing). */
static void stats_ts_emit_truncation(FILE *fp)
{
	static unsigned long prev_trace_truncated = 0;
	static unsigned long prev_cmp_trace_truncated = 0;
	unsigned long trace_truncated = 0;
	unsigned long cmp_trace_truncated = 0;

	if (kcov_shm != NULL) {
		trace_truncated = __atomic_load_n(&kcov_shm->coverage.trace_truncated,
						  __ATOMIC_RELAXED);
		cmp_trace_truncated = __atomic_load_n(
			&kcov_shm->cmp_records.cmp_trace_truncated, __ATOMIC_RELAXED);
	}

	fprintf(fp,
		",\"trace_truncated\":%lu,\"trace_truncated_delta\":%lu"
		",\"cmp_trace_truncated\":%lu,\"cmp_trace_truncated_delta\":%lu",
		trace_truncated,
		stats_ts_window_delta(trace_truncated, &prev_trace_truncated),
		cmp_trace_truncated,
		stats_ts_window_delta(cmp_trace_truncated,
				      &prev_cmp_trace_truncated));
}

/* CMP-hint / CMP-hyp inject + conversion snapshots.  A window
 * where injected rose but consumed/wins did not is a
 * conversion-side plateau (targets landed but drove no new
 * coverage); a window where injected fell is a supply-side
 * plateau (nothing to try).  Kept as level+delta so run-analysis
 * can plot both without differencing consecutive lines. */
static void stats_ts_emit_cmp_hints(FILE *fp)
{
	static unsigned long prev_cmp_hints_injected = 0;
	static unsigned long prev_cmp_hints_consumed = 0;
	static unsigned long prev_cmp_hint_wins = 0;
	static unsigned long prev_cmp_hyp_live_injected = 0;
	static unsigned long prev_cmp_hyp_consumed = 0;
	static unsigned long prev_cmp_hyp_pc_wins = 0;
	unsigned long cmp_hints_injected = 0;
	unsigned long cmp_hints_consumed = 0;
	unsigned long cmp_hint_wins = 0;
	unsigned long cmp_hyp_live_injected = 0;
	unsigned long cmp_hyp_consumed = 0;
	unsigned long cmp_hyp_pc_wins = 0;

	if (kcov_shm != NULL) {
		cmp_hints_injected = __atomic_load_n(
			&kcov_shm->hints_flat.cmp_hints_injected, __ATOMIC_RELAXED);
		cmp_hints_consumed = __atomic_load_n(
			&kcov_shm->cmp_hints_consumed, __ATOMIC_RELAXED);
		cmp_hint_wins = __atomic_load_n(&kcov_shm->cmp_hint_wins,
						__ATOMIC_RELAXED);
		cmp_hyp_live_injected = __atomic_load_n(
			&kcov_shm->cmp_hyp_live_injected, __ATOMIC_RELAXED);
		cmp_hyp_consumed = __atomic_load_n(
			&kcov_shm->cmp_hyp_consumed, __ATOMIC_RELAXED);
		cmp_hyp_pc_wins = __atomic_load_n(&kcov_shm->cmp_hyp_pc_wins,
						  __ATOMIC_RELAXED);
	}

	/* cmp_hyp_pc_wins is the typed-hyp LIVE conversion numerator
	 * (denominator cmp_hyp_live_injected is already emitted above).
	 * The flat-replay numerator is cmp_hint_pc_wins_by_pool[] summed
	 * against (cmp_hints_injected - cmp_hyp_live_injected); the
	 * per-pool array is not on the timeseries line -- the stats.log
	 * and stats.json emitters carry the split-by-pool decomposition
	 * for retrospective analysis. */
	fprintf(fp,
		",\"cmp_hints_injected\":%lu,\"cmp_hints_injected_delta\":%lu"
		",\"cmp_hints_consumed\":%lu,\"cmp_hints_consumed_delta\":%lu"
		",\"cmp_hint_wins\":%lu,\"cmp_hint_wins_delta\":%lu"
		",\"cmp_hyp_live_injected\":%lu,\"cmp_hyp_live_injected_delta\":%lu"
		",\"cmp_hyp_consumed\":%lu,\"cmp_hyp_consumed_delta\":%lu"
		",\"cmp_hyp_pc_wins\":%lu,\"cmp_hyp_pc_wins_delta\":%lu",
		cmp_hints_injected,
		stats_ts_window_delta(cmp_hints_injected,
				      &prev_cmp_hints_injected),
		cmp_hints_consumed,
		stats_ts_window_delta(cmp_hints_consumed,
				      &prev_cmp_hints_consumed),
		cmp_hint_wins,
		stats_ts_window_delta(cmp_hint_wins, &prev_cmp_hint_wins),
		cmp_hyp_live_injected,
		stats_ts_window_delta(cmp_hyp_live_injected,
				      &prev_cmp_hyp_live_injected),
		cmp_hyp_consumed,
		stats_ts_window_delta(cmp_hyp_consumed,
				      &prev_cmp_hyp_consumed),
		cmp_hyp_pc_wins,
		stats_ts_window_delta(cmp_hyp_pc_wins, &prev_cmp_hyp_pc_wins));
}

/* Plateau classifier hypothesis + the current intervention mode
 * the picker is running.  Emitted as strings via the existing
 * name accessors so a consumer does not need to link against the
 * enums.  Both fall back to their zeroth entry when shm is not
 * mapped, which matches the picker's runtime behaviour. */
static void stats_ts_emit_plateau(FILE *fp)
{
	int plateau_hypothesis = 0;
	int intervention_mode = 0;

	if (shm != NULL) {
		plateau_hypothesis = __atomic_load_n(
			&shm->plateau_current_hypothesis, __ATOMIC_RELAXED);
		intervention_mode = __atomic_load_n(
			&shm->plateau_intervention_mode_current,
			__ATOMIC_RELAXED);
	}

	fprintf(fp,
		",\"plateau_hypothesis\":\"%s\","
		"\"plateau_intervention_mode\":\"%s\"",
		strategy_plateau_hypothesis_name(plateau_hypothesis),
		plateau_intervention_mode_name(intervention_mode));
}

/* Per-arm learner state.  Fixed-width array indexed by
 * enum strategy; each element carries the lifetime level and
 * the per-window delta for the three parallel reward series
 * the picker reads.  This is the "which arm just got the wins
 * this window" attribution that pc_edge_calls_by_strategy
 * would otherwise require joining stats.json for. */
static void stats_ts_emit_by_strategy(FILE *fp)
{
	/* Per-arm snapshots for the by_strategy block.  NR_STRATEGIES
	 * is a compile-time constant so these live as fixed-width arrays
	 * next to the top-level scalars rather than in shm. */
	static unsigned long prev_bandit_pulls[NR_STRATEGIES];
	static unsigned long prev_bandit_reward_calls[NR_STRATEGIES];
	static unsigned long prev_bandit_reward_pc_edge_count[NR_STRATEGIES];
	int i;

	fputs(",\"by_strategy\":[", fp);
	for (i = 0; i < NR_STRATEGIES; i++) {
		unsigned long pulls = 0;
		unsigned long reward_calls = 0;
		unsigned long reward_pc_edges = 0;

		if (shm != NULL) {
			pulls = __atomic_load_n(&shm->bandit_pulls[i],
						__ATOMIC_RELAXED);
			reward_calls = __atomic_load_n(
				&shm->bandit_reward_calls[i],
				__ATOMIC_RELAXED);
			reward_pc_edges = __atomic_load_n(
				&shm->bandit_reward_pc_edge_count[i],
				__ATOMIC_RELAXED);
		}
		fprintf(fp,
			"%s{\"strategy\":%d,\"pulls\":%lu,\"pulls_delta\":%lu"
			",\"reward_calls\":%lu,\"reward_calls_delta\":%lu"
			",\"reward_pc_edges\":%lu,\"reward_pc_edges_delta\":%lu}",
			i == 0 ? "" : ",", i,
			pulls,
			stats_ts_window_delta(pulls, &prev_bandit_pulls[i]),
			reward_calls,
			stats_ts_window_delta(reward_calls,
					      &prev_bandit_reward_calls[i]),
			reward_pc_edges,
			stats_ts_window_delta(
				reward_pc_edges,
				&prev_bandit_reward_pc_edge_count[i]));
	}
	fputs("]", fp);
}

/* Per-childop edge / invocation / canary attribution.  For every
 * alt-op with any cumulative activity (skip-zero: never-fired ops
 * are elided so a run with ~130 defined ops but only ~10 active
 * does not bloat every window record with all-zero blocks), emit
 * the level + per-window delta for the four shm counters the child_
 * process() post-call block bumps -- childop_edges_discovered (the
 * unbracketed global-delta path, noisy but always live),
 * childop_edges_clean (the outer-KCOV-bracketed per-call delta the
 * canary queue and adapt_budget() consume), childop_calls_with_
 * edges (the "at least one new edge" call-count sibling of
 * bandit_pool_edges_discovered on the syscall path), and
 * childop_invocations (the dispatch count parallel to op_count).
 * Plus the shadow canary recommendation deltas (childop_would_
 * promote / childop_would_demote) so a jump ties to a childop AND
 * its disposition: a nonzero would_promote_delta this window means
 * the shadow policy would PROMOTED_CLEAN / PROMOTED_INTERFERENCE
 * the op, a nonzero would_demote_delta means THROTTLED /
 * QUARANTINED / NO_OUTER_BRACKET.  canary_active / canary_promoted
 * expose the live queue state directly via the public accessors,
 * so an op that is currently the canary pick or currently promoted
 * is emitted even with all-zero counters -- the operator can see
 * canary state before any counter has moved.  CHILD_OP_SYSCALL is
 * skipped: the syscall path attributes its wins through the
 * per_syscall block and the by_strategy bandit counters, and the
 * per-childop shm arrays are documented as skipping this slot at
 * their bump sites. */
static void stats_ts_emit_by_childop(FILE *fp)
{
	enum child_op_type active_canary = canary_active_op();
	bool first_op = true;
	int op;

	fputs(",\"by_childop\":[", fp);
	for (op = CHILD_OP_SYSCALL + 1; op < NR_CHILD_OP_TYPES; op++) {
		unsigned long edges_discovered = 0;
		unsigned long edges_clean = 0;
		unsigned long calls_with_edges = 0;
		unsigned long invocations = 0;
		unsigned long would_promote = 0;
		unsigned long would_demote = 0;
		unsigned long edges_discovered_delta;
		unsigned long edges_clean_delta;
		unsigned long calls_with_edges_delta;
		unsigned long invocations_delta;
		unsigned long would_promote_delta;
		unsigned long would_demote_delta;
		/* Per-op KCOV bracket attribution.  Cumulative only -- these
		 * are diagnostic per-op mirrors of the aggregate childop_kcov_*
		 * counters and let a JSONL reader distinguish
		 * "childop_edges_clean == 0 because the op is genuinely
		 * zero-yield" from "childop_edges_clean == 0 because
		 * kcov_bracket_begin() declined for reason X" (MODE ARTIFACT).
		 * Sourced from kcov_shm, not shm->stats, matching where the
		 * bumps in child_process() write. */
		unsigned long kcov_op_attempts = 0;
		unsigned long kcov_op_bracketed = 0;
		unsigned long kcov_op_skipped_cmp = 0;
		unsigned long kcov_op_skipped_nested = 0;
		unsigned long kcov_op_skipped_inactive = 0;
		bool canary_active = (op == (int)active_canary);
		bool canary_promoted = canary_op_is_promoted(op);

		if (shm != NULL) {
			edges_discovered = __atomic_load_n(
				&shm->stats.childop.edges_discovered[op],
				__ATOMIC_RELAXED);
			edges_clean = __atomic_load_n(
				&shm->stats.childop.edges_clean[op],
				__ATOMIC_RELAXED);
			calls_with_edges = __atomic_load_n(
				&shm->stats.childop.calls_with_edges[op],
				__ATOMIC_RELAXED);
			invocations = __atomic_load_n(
				&shm->stats.childop.invocations[op],
				__ATOMIC_RELAXED);
			would_promote = __atomic_load_n(
				&shm->stats.childop.would_promote[op],
				__ATOMIC_RELAXED);
			would_demote = __atomic_load_n(
				&shm->stats.childop.would_demote[op],
				__ATOMIC_RELAXED);
		}
		if (kcov_shm != NULL && op < KCOV_CHILDOP_NR_MAX) {
			kcov_op_attempts = __atomic_load_n(
				&kcov_shm->childop_kcov.childop_kcov_op_attempts[op],
				__ATOMIC_RELAXED);
			kcov_op_bracketed = __atomic_load_n(
				&kcov_shm->childop_kcov.childop_kcov_op_bracketed[op],
				__ATOMIC_RELAXED);
			kcov_op_skipped_cmp = __atomic_load_n(
				&kcov_shm->childop_kcov.childop_kcov_op_skipped_cmp[op],
				__ATOMIC_RELAXED);
			kcov_op_skipped_nested = __atomic_load_n(
				&kcov_shm->childop_kcov.childop_kcov_op_skipped_nested[op],
				__ATOMIC_RELAXED);
			kcov_op_skipped_inactive = __atomic_load_n(
				&kcov_shm->childop_kcov.childop_kcov_op_skipped_inactive[op],
				__ATOMIC_RELAXED);
		}

		edges_discovered_delta = stats_ts_window_delta(
			edges_discovered,
			&stats_ts_prev_childop_edges_discovered[op]);
		edges_clean_delta = stats_ts_window_delta(
			edges_clean,
			&stats_ts_prev_childop_edges_clean[op]);
		calls_with_edges_delta = stats_ts_window_delta(
			calls_with_edges,
			&stats_ts_prev_childop_calls_with_edges[op]);
		invocations_delta = stats_ts_window_delta(
			invocations,
			&stats_ts_prev_childop_invocations[op]);
		would_promote_delta = stats_ts_window_delta(
			would_promote,
			&stats_ts_prev_childop_would_promote[op]);
		would_demote_delta = stats_ts_window_delta(
			would_demote,
			&stats_ts_prev_childop_would_demote[op]);

		if (edges_discovered == 0 && edges_clean == 0 &&
		    calls_with_edges == 0 && invocations == 0 &&
		    would_promote == 0 && would_demote == 0 &&
		    kcov_op_attempts == 0 &&
		    !canary_active && !canary_promoted)
			continue;

		fprintf(fp,
			"%s{\"op\":%d,\"name\":\"%s\""
			",\"edges_discovered\":%lu,\"edges_discovered_delta\":%lu"
			",\"edges_clean\":%lu,\"edges_clean_delta\":%lu"
			",\"calls_with_edges\":%lu,\"calls_with_edges_delta\":%lu"
			",\"invocations\":%lu,\"invocations_delta\":%lu"
			",\"would_promote\":%lu,\"would_promote_delta\":%lu"
			",\"would_demote\":%lu,\"would_demote_delta\":%lu"
			",\"kcov_op_attempts\":%lu"
			",\"kcov_op_bracketed\":%lu"
			",\"kcov_op_skipped_cmp\":%lu"
			",\"kcov_op_skipped_nested\":%lu"
			",\"kcov_op_skipped_inactive\":%lu"
			",\"canary_active\":%d,\"canary_promoted\":%d}",
			first_op ? "" : ",", op, alt_op_name(op),
			edges_discovered, edges_discovered_delta,
			edges_clean, edges_clean_delta,
			calls_with_edges, calls_with_edges_delta,
			invocations, invocations_delta,
			would_promote, would_promote_delta,
			would_demote, would_demote_delta,
			kcov_op_attempts,
			kcov_op_bracketed,
			kcov_op_skipped_cmp,
			kcov_op_skipped_nested,
			kcov_op_skipped_inactive,
			canary_active ? 1 : 0,
			canary_promoted ? 1 : 0);
		first_op = false;
	}
	fputs("]", fp);
}

void stats_timeseries_emit_window(unsigned long op_count)
{
	unsigned long edges_total;
	bool first = true;

	if (stats_timeseries_fp == NULL)
		return;

	edges_total = stats_ts_emit_record_head(stats_timeseries_fp, op_count);
	stats_ts_emit_baselines(stats_timeseries_fp, edges_total);
	stats_ts_emit_truncation(stats_timeseries_fp);
	stats_ts_emit_cmp_hints(stats_timeseries_fp);
	stats_ts_emit_plateau(stats_timeseries_fp);
	stats_ts_emit_by_strategy(stats_timeseries_fp);
	stats_ts_emit_by_childop(stats_timeseries_fp);

	fputs(",\"per_syscall\":[", stats_timeseries_fp);

	if (biarch == true) {
		stats_timeseries_emit_table(syscalls_64bit,
					    max_nr_64bit_syscalls,
					    false, &first);
		stats_timeseries_emit_table(syscalls_32bit,
					    max_nr_32bit_syscalls,
					    true, &first);
	} else {
		stats_timeseries_emit_table(syscalls,
					    max_nr_syscalls,
					    false, &first);
	}

	fputs("]}\n", stats_timeseries_fp);
	fflush(stats_timeseries_fp);
}

/* Drop the inherited stats-log fd from a fork()'d child.  fopen() on the
 * parent side leaves an ordinary fd in the table; fork shares it, and the
 * syscall fuzzer in the child can hit it numerically (fchmod / ftruncate /
 * fchown / write at random offset) without ever going through an
 * fd-provider.  The symptom is the operator's stats.log gaining random
 * permissions and size jumping around mid-run.  close()ing the fd here
 * removes only the child's fd-table entry (the parent's entry refers to
 * the same kernel struct file but via a separate fd-table slot, so the
 * parent's writes are unaffected).  Null the FILE* so a stray
 * stats_log_write call from the child silently no-ops instead of writing
 * via a dangling fileno. */
void stats_log_drop_in_child(void)
{
	if (stats_log_fp == NULL)
		return;
	close(fileno(stats_log_fp));
	stats_log_fp = NULL;
}

void stats_log_write(const char *fmt, ...)
{
	char buf[STATS_LOG_LINE_BUFSIZE];
	va_list args;

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	output(0, "%s", buf);

	if (stats_log_fp != NULL) {
		fputs(buf, stats_log_fp);
		fflush(stats_log_fp);
	}
}
