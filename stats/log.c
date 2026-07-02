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
#include "child.h"
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

/* Previous window's edge counts, per (nr, arch), for the per-syscall
 * edges_gained delta.  Zero-initialised, so the first window's delta
 * equals the level (matching the top-level edges_gained_this_window
 * convention).  Sized by MAX_NR_SYSCALL rather than the active count
 * because entry->number is the stable numeric key we index by. */
static unsigned long stats_ts_prev_per_syscall_edges[MAX_NR_SYSCALL][2];

/* Walk one syscall table and emit
 * {"nr":N,"edges":E,"edges_gained":G,"kcov_calls":K,"attempted_calls":A}
 * entries for each enabled slot whose entry pointer is non-NULL.
 * *first tracks whether the next entry needs a leading comma so the
 * caller can chain the 32-bit and 64-bit tables into a single array
 * literal.  do32 selects the arch dim into per_syscall_diag[][],
 * matching the kcov_diag_emit_block() convention (false=64-bit,
 * true=32-bit).
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
 * lines.  Also updates the prev array in-place before returning. */
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

		if (entry == NULL)
			continue;
		if (entry->active_number == 0)
			continue;

		nr = entry->number;
		attempted_calls = entry->attempted;
		if (nr < MAX_NR_SYSCALL && kcov_shm != NULL) {
			edges = __atomic_load_n(
				&kcov_shm->per_syscall_diag[nr][arch_ix].bucket_bits_real,
				__ATOMIC_RELAXED);
			kcov_calls = __atomic_load_n(
				&kcov_shm->per_syscall_calls[nr],
				__ATOMIC_RELAXED);
		}

		if (nr < MAX_NR_SYSCALL) {
			unsigned long prev = stats_ts_prev_per_syscall_edges[nr][arch_ix];

			/* Guard against a rewound counter (bounded shm
			 * counter, resume-from-checkpoint, etc.) so we
			 * never emit a wrap-around negative-as-huge
			 * delta. */
			edges_gained = edges >= prev ? edges - prev : 0;
			stats_ts_prev_per_syscall_edges[nr][arch_ix] = edges;
		}

		fprintf(stats_timeseries_fp,
			"%s{\"nr\":%u,\"edges\":%lu,\"edges_gained\":%lu,\"kcov_calls\":%lu,\"attempted_calls\":%u}",
			*first ? "" : ",", nr, edges, edges_gained,
			kcov_calls, attempted_calls);
		*first = false;
	}
}

void stats_timeseries_emit_window(unsigned long op_count)
{
	/* Previous window's distinct-edge total, for the top-level
	 * edges_gained_this_window delta.  Zero-initialised so the
	 * first window's delta equals the level (a plateau consumer
	 * gets a real first value instead of a phantom zero). */
	static unsigned long prev_edges_total = 0;
	unsigned long edges_total = 0;
	unsigned long edges_gained_this_window = 0;
	bool first = true;

	if (stats_timeseries_fp == NULL)
		return;

	if (kcov_shm != NULL)
		edges_total = __atomic_load_n(&kcov_shm->distinct_edges,
					      __ATOMIC_RELAXED);

	/* Guard against a rewound counter for the same reason as the
	 * per-syscall path above. */
	edges_gained_this_window = edges_total >= prev_edges_total
		? edges_total - prev_edges_total
		: 0;
	prev_edges_total = edges_total;

	fprintf(stats_timeseries_fp,
		"{\"t\":%lu,\"edges_total\":%lu,\"edges_gained_this_window\":%lu,\"per_syscall\":[",
		op_count, edges_total, edges_gained_this_window);

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
