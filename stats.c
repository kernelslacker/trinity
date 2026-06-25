#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>
#include "arch.h"
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
#include "sequence.h"
#include "shm.h"
#include "stats.h"
#include "stats_ring.h"
#include "syscall.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"
#include "utils.h"
#include "version.h"

/*
 * Linker-provided bounds of the running binary's executable text.  Used
 * to filter PC samples whose storage was itself stomped by the wild
 * writes we are trying to attribute -- an entry whose pc lands outside
 * [__executable_start, _etext) cannot be a real call site and would
 * otherwise dump as garbage.
 */
extern char __executable_start[];
extern char _etext[];

static inline bool pc_in_text(void *pc)
{
	return pc >= (void *)__executable_start && pc < (void *)_etext;
}

static const char * const op_names[MUT_NUM_OPS] = {
	"bit-flip", "add", "sub", "boundary", "byte-shuf", "keep",
	"bswap-add", "bswap-sub", "fd-swap"
};

/*
 * Aggregate-stats table column widths. Header + every row uses the same
 * format string so output is greppable (grep '^fd_lifecycle ') and
 * human-scannable (columns line up).
 */
#define STATS_ROW_FMT "%-22s  %-32s  %lu\n"
#define STATS_HDR_FMT "%-22s  %-32s  %s\n"

static void stats_emit_header(void)
{
	output(0, "\n");
	output(0, STATS_HDR_FMT, "CATEGORY", "METRIC", "VALUE");
	output(0, STATS_HDR_FMT,
	       "----------------------",
	       "--------------------------------",
	       "-----");
}

static void stat_row(const char *category, const char *metric, unsigned long value)
{
	output(0, STATS_ROW_FMT, category, metric, value);
}

/*
 * Mechanical name-prefix → category lookup.  The table is ordered so that
 * longer prefixes shadow shorter ones for the same head ("readlink" before
 * "read", "sendfile" before "send"); first match wins.  Operator-grade
 * categorisation, not a taxonomy — anything not listed lands in OTHER.
 */
unsigned int stats_syscall_category(const char *name)
{
	static const struct { const char *p; unsigned char cat; } tab[] = {
		{ "readlink", SYSCAT_FILE },   { "preadv",   SYSCAT_READ },
		{ "pread",    SYSCAT_READ },   { "read",     SYSCAT_READ },
		{ "pwritev",  SYSCAT_WRITE },  { "pwrite",   SYSCAT_WRITE },
		{ "writev",   SYSCAT_WRITE },  { "write",    SYSCAT_WRITE },
		{ "open",     SYSCAT_OPEN },   { "creat",    SYSCAT_OPEN },
		{ "mmap",     SYSCAT_MMAP },   { "munmap",   SYSCAT_MMAP },
		{ "mremap",   SYSCAT_MMAP },   { "mprotect", SYSCAT_MMAP },
		{ "madvise",  SYSCAT_MMAP },   { "msync",    SYSCAT_MMAP },
		{ "mbind",    SYSCAT_MMAP },   { "mlock",    SYSCAT_MMAP },
		{ "munlock",  SYSCAT_MMAP },   { "mincore",  SYSCAT_MMAP },
		{ "brk",      SYSCAT_MMAP },
		{ "sendfile", SYSCAT_FILE },
		{ "socket",   SYSCAT_SOCKET }, { "bind",     SYSCAT_SOCKET },
		{ "listen",   SYSCAT_SOCKET }, { "accept",   SYSCAT_SOCKET },
		{ "connect",  SYSCAT_SOCKET }, { "send",     SYSCAT_SOCKET },
		{ "recv",     SYSCAT_SOCKET }, { "shutdown", SYSCAT_SOCKET },
		{ "getsock",  SYSCAT_SOCKET }, { "setsock",  SYSCAT_SOCKET },
		{ "getpeer",  SYSCAT_SOCKET },
		{ "fork",     SYSCAT_PROCESS },{ "vfork",    SYSCAT_PROCESS },
		{ "clone",    SYSCAT_PROCESS },{ "exec",     SYSCAT_PROCESS },
		{ "exit",     SYSCAT_PROCESS },{ "wait",     SYSCAT_PROCESS },
		{ "kill",     SYSCAT_PROCESS },{ "tkill",    SYSCAT_PROCESS },
		{ "tgkill",   SYSCAT_PROCESS },{ "pidfd",    SYSCAT_PROCESS },
		{ "futex",    SYSCAT_IPC },    { "mq_",      SYSCAT_IPC },
		{ "msg",      SYSCAT_IPC },    { "sem",      SYSCAT_IPC },
		{ "shm",      SYSCAT_IPC },    { "pipe",     SYSCAT_IPC },
		{ "eventfd",  SYSCAT_IPC },    { "signalfd", SYSCAT_IPC },
		{ "rt_sig",   SYSCAT_IPC },    { "sigaction",SYSCAT_IPC },
		{ "stat",     SYSCAT_FILE },   { "fstat",    SYSCAT_FILE },
		{ "lstat",    SYSCAT_FILE },   { "access",   SYSCAT_FILE },
		{ "chmod",    SYSCAT_FILE },   { "chown",    SYSCAT_FILE },
		{ "fchmod",   SYSCAT_FILE },   { "fchown",   SYSCAT_FILE },
		{ "lchown",   SYSCAT_FILE },   { "link",     SYSCAT_FILE },
		{ "unlink",   SYSCAT_FILE },   { "symlink",  SYSCAT_FILE },
		{ "rename",   SYSCAT_FILE },   { "mkdir",    SYSCAT_FILE },
		{ "rmdir",    SYSCAT_FILE },   { "close",    SYSCAT_FILE },
		{ "dup",      SYSCAT_FILE },   { "fcntl",    SYSCAT_FILE },
		{ "ioctl",    SYSCAT_FILE },   { "lseek",    SYSCAT_FILE },
		{ "truncate", SYSCAT_FILE },   { "ftruncate",SYSCAT_FILE },
		{ "fsync",    SYSCAT_FILE },   { "fdatasync",SYSCAT_FILE },
		{ "sync",     SYSCAT_FILE },
	};
	unsigned int i;

	if (name == NULL)
		return SYSCAT_OTHER;
	for (i = 0; i < ARRAY_SIZE(tab); i++)
		if (strncmp(name, tab[i].p, strlen(tab[i].p)) == 0)
			return tab[i].cat;
	return SYSCAT_OTHER;
}

static void dump_syscall_category_histogram(void)
{
	static const char * const cat_names[NR_SYSCAT] = {
		"read", "write", "open", "mmap", "socket",
		"process", "file", "ipc", "other",
	};
	unsigned long total = 0;
	unsigned int i;

	for (i = 0; i < NR_SYSCAT; i++)
		total += parent_stats.syscall_category_count[i];
	if (total == 0)
		return;

	output(0, "Syscall category histogram (total: %lu):\n", total);
	for (i = 0; i < NR_SYSCAT; i++) {
		unsigned long c = parent_stats.syscall_category_count[i];
		unsigned long pct10 = total ? (c * 1000UL / total) : 0UL;

		output(0, "  %-8s %10lu  (%lu.%lu%%)\n",
		       cat_names[i], c, pct10 / 10, pct10 % 10);
	}
}

static void dump_entry(const struct syscalltable *table, unsigned int i)
{
	struct syscallentry *entry;
	unsigned int j;

	entry = table[i].entry;
	if (entry == NULL)
		return;

	if (entry->attempted == 0)
		return;

	output(0, "%s: (attempted:%u. success:%u. failures:%u.\n", entry->name, entry->attempted, entry->successes, entry->failures);

	for (j = 0; j <= NR_ERRNOS; j++) {
		if (entry->errnos[j] != 0) {
			output(0, "    %s: %d\n", strerror(j), entry->errnos[j]);
		}
	}
}

/*
 * JSON helpers for --stats-json. Emit straight to stdout (no [main] prefix
 * from output()), so post-run scripts can redirect stdout and parse the
 * result with jq / json.loads / serde_json without stripping anything.
 */
static void json_emit_string(const char *s)
{
	putchar('"');
	if (s != NULL) {
		for (; *s != '\0'; s++) {
			unsigned char c = (unsigned char)*s;

			switch (c) {
			case '"':  fputs("\\\"", stdout); break;
			case '\\': fputs("\\\\", stdout); break;
			case '\b': fputs("\\b", stdout);  break;
			case '\f': fputs("\\f", stdout);  break;
			case '\n': fputs("\\n", stdout);  break;
			case '\r': fputs("\\r", stdout);  break;
			case '\t': fputs("\\t", stdout);  break;
			default:
				if (c < 0x20)
					printf("\\u%04x", c);
				else
					putchar(c);
			}
		}
	}
	putchar('"');
}

/* Emit one syscall entry. Returns true if anything was printed. Caller is
 * responsible for emitting a leading comma between successive entries. */
static bool json_emit_syscall(const struct syscalltable *table, unsigned int i)
{
	struct syscallentry *entry;
	unsigned int j;
	bool first_errno = true;

	entry = table[i].entry;
	if (entry == NULL || entry->attempted == 0)
		return false;

	putchar('{');
	fputs("\"name\":", stdout);
	json_emit_string(entry->name);
	printf(",\"attempted\":%u,\"successes\":%u,\"failures\":%u,\"errnos\":{",
		entry->attempted, entry->successes, entry->failures);
	for (j = 0; j <= NR_ERRNOS; j++) {
		if (entry->errnos[j] == 0)
			continue;
		if (!first_errno)
			putchar(',');
		printf("\"%u\":%u", j, entry->errnos[j]);
		first_errno = false;
	}
	fputs("}}", stdout);
	return true;
}

static void json_emit_syscalls_array(void)
{
	unsigned int i;
	bool first = true;

	fputs("\"syscalls\":[", stdout);
	if (biarch == true) {
		for_each_32bit_syscall(i) {
			if (syscalls_32bit[i].entry == NULL ||
			    syscalls_32bit[i].entry->attempted == 0)
				continue;
			if (!first)
				putchar(',');
			json_emit_syscall(syscalls_32bit, i);
			first = false;
		}
		for_each_64bit_syscall(i) {
			if (syscalls_64bit[i].entry == NULL ||
			    syscalls_64bit[i].entry->attempted == 0)
				continue;
			if (!first)
				putchar(',');
			json_emit_syscall(syscalls_64bit, i);
			first = false;
		}
	} else {
		for_each_syscall(i) {
			if (syscalls[i].entry == NULL ||
			    syscalls[i].entry->attempted == 0)
				continue;
			if (!first)
				putchar(',');
			json_emit_syscall(syscalls, i);
			first = false;
		}
	}
	putchar(']');
}

/* Insertion-sort push for a top-N table held as parallel arrays
 * (vals[], nrs[], descending by value, capped at cap).  Shared by the
 * kcov dump paths that track leading edge-producing, recent-growth, and
 * CMP-insert syscalls. */
static void topn_push(unsigned long *vals, unsigned int *nrs,
		      unsigned int *count, unsigned int cap,
		      unsigned long value, unsigned int nr)
{
	unsigned int j;

	for (j = *count; j > 0 && value > vals[j - 1]; j--) {
		if (j < cap) {
			vals[j] = vals[j - 1];
			nrs[j] = nrs[j - 1];
		}
	}
	if (j < cap) {
		vals[j] = value;
		nrs[j] = nr;
		if (*count < cap)
			(*count)++;
	}
}

static void json_emit_kcov_section(void)
{
	unsigned int i, j;
	const struct syscalltable *table;
	unsigned int nr_syscalls_to_scan;
	unsigned long kc_edges, kc_pcs, kc_calls, kc_remote;
	unsigned long kc_cmp_records, kc_cmp_trunc, kc_cmp_bloom_skipped, kc_cmp_unique;
	unsigned long kc_cmp_strip_skipped;
	unsigned long kc_cmp_save_reject_nonconst;
	unsigned long kc_cmp_save_reject_uninteresting;
	unsigned long kc_cmp_save_reject_sentinel;
	unsigned long kc_cmp_save_reject_dup;
	unsigned long kc_cmp_save_reject_cap;
	unsigned int top_nr[10];
	unsigned long top_edges[10];
	unsigned int top_count = 0;
	unsigned int delta_nr[10];
	unsigned long delta_edges[10];
	unsigned int delta_count = 0;

	if (kcov_shm == NULL) {
		fputs(",\"kcov\":null", stdout);
		return;
	}

	kc_edges  = __atomic_load_n(&kcov_shm->edges_found,  __ATOMIC_RELAXED);
	/* total_pcs / total_calls / remote_calls drained from the
	 * per-child stats_ring into parent_stats; kcov_shm->total_calls
	 * is kept as the stamp source for last_edge_at[] /
	 * last_efault_at[] only, and the other two shm fields are no
	 * longer bumped (no stamp-role consumer references them). */
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

	nr_syscalls_to_scan = biarch ? max_nr_64bit_syscalls : max_nr_syscalls;
	if (nr_syscalls_to_scan > MAX_NR_SYSCALL)
		nr_syscalls_to_scan = MAX_NR_SYSCALL;
	table = biarch ? syscalls_64bit : syscalls;

	memset(top_edges, 0, sizeof(top_edges));
	memset(delta_edges, 0, sizeof(delta_edges));

	for (i = 0; i < nr_syscalls_to_scan; i++) {
		unsigned long edges = __atomic_load_n(&kcov_shm->per_syscall_edges[i], __ATOMIC_RELAXED);
		unsigned long prev  = kcov_shm->per_syscall_edges_previous[i];
		unsigned long delta = (edges > prev) ? edges - prev : 0;

		if (edges > 0)
			topn_push(top_edges, top_nr, &top_count, 10, edges, i);

		if (delta > 0)
			topn_push(delta_edges, delta_nr, &delta_count, 10, delta, i);
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
		"\"cmp_hints_save_reject_cap\":%lu",
		kc_edges, kc_pcs, kc_calls, kc_remote,
		kc_cmp_records, kc_cmp_trunc, kc_cmp_bloom_skipped,
		kc_cmp_strip_skipped, kc_cmp_unique,
		kc_cmp_save_reject_nonconst, kc_cmp_save_reject_uninteresting,
		kc_cmp_save_reject_sentinel, kc_cmp_save_reject_dup,
		kc_cmp_save_reject_cap);

	/* Shadow transition-coverage globals.  Emitted unconditionally
	 * so consumers can rely on a stable schema; both fields are 0
	 * when the mode is OFF (the per-PC hash never runs and the
	 * shared counters stay at their post-memset zero). */
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

	/* Shadow transition-coverage top-N: cumulative by real
	 * transition-slot count, and per-interval growth by call-count
	 * delta.  Mirrors the PC top_syscalls / top_recent_growth blocks
	 * directly above so the two signals share the JSON shape.  Both
	 * arrays come out empty when the mode is OFF since the per-
	 * syscall counters never get bumped. */
	{
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
			unsigned long delta = (curr > prev) ? curr - prev : 0;

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

	fputs(",\"cold_syscalls\":[", stdout);
	{
		bool first_cold = true;

		for (i = 0; i < nr_syscalls_to_scan; i++) {
			unsigned long slot_edges = __atomic_load_n(&kcov_shm->per_syscall_edges[i], __ATOMIC_RELAXED);
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
	}
	putchar(']');

	/* Snapshot current counts for the next interval, matching text path. */
	for (i = 0; i < nr_syscalls_to_scan; i++)
		kcov_shm->per_syscall_edges_previous[i] =
			__atomic_load_n(&kcov_shm->per_syscall_edges[i], __ATOMIC_RELAXED);

	putchar('}');
}

static void json_emit_minicorpus_section(void)
{
	unsigned int i;
	unsigned long s_hits, s_wins, r_count, r_wins;
	unsigned long c_iter, c_subst, c_save, c_replay;

	if (minicorpus_shm == NULL) {
		fputs(",\"minicorpus\":null", stdout);
		return;
	}

	fputs(",\"minicorpus\":{\"mutators\":[", stdout);
	for (i = 0; i < MUT_NUM_OPS; i++) {
		unsigned long t  = __atomic_load_n(&minicorpus_shm->mut_trials[i], __ATOMIC_RELAXED);
		unsigned long w  = __atomic_load_n(&minicorpus_shm->mut_wins[i],   __ATOMIC_RELAXED);
		unsigned long st = __atomic_load_n(&minicorpus_shm->mut_structured_trials[i],
						   __ATOMIC_RELAXED);
		unsigned long sw = __atomic_load_n(&minicorpus_shm->mut_structured_wins[i],
						   __ATOMIC_RELAXED);

		if (i > 0)
			putchar(',');
		fputs("{\"name\":", stdout);
		json_emit_string(op_names[i]);
		printf(",\"trials\":%lu,\"wins\":%lu"
		       ",\"structured_trials\":%lu,\"structured_wins\":%lu}",
		       t, w, st, sw);
	}
	putchar(']');

	s_hits = __atomic_load_n(&minicorpus_shm->splice_hits, __ATOMIC_RELAXED);
	s_wins = __atomic_load_n(&minicorpus_shm->splice_wins, __ATOMIC_RELAXED);
	printf(",\"splice\":{\"hits\":%lu,\"wins\":%lu}", s_hits, s_wins);

	{
		unsigned long xp_hits = __atomic_load_n(
			&minicorpus_shm->xprop_hits, __ATOMIC_RELAXED);
		unsigned long xp_wins = __atomic_load_n(
			&minicorpus_shm->xprop_wins, __ATOMIC_RELAXED);
		/* xprop attempt/reject breakdown so the
		 * hit-rate xp_hits / xp_attempts and the dominant
		 * reject cause are directly readable from the
		 * end-of-run dump. */
		unsigned long xp_attempts = __atomic_load_n(
			&minicorpus_shm->xprop_attempts, __ATOMIC_RELAXED);
		unsigned long xp_r_target = __atomic_load_n(
			&minicorpus_shm->xprop_reject_target_not_fdarg,
			__ATOMIC_RELAXED);
		unsigned long xp_r_self = __atomic_load_n(
			&minicorpus_shm->xprop_reject_src_self,
			__ATOMIC_RELAXED);
		unsigned long xp_r_empty = __atomic_load_n(
			&minicorpus_shm->xprop_reject_src_empty,
			__ATOMIC_RELAXED);

		printf(",\"xprop\":{\"hits\":%lu,\"wins\":%lu,\"attempts\":%lu,"
		       "\"reject_target_not_fdarg\":%lu,"
		       "\"reject_src_self\":%lu,"
		       "\"reject_src_empty\":%lu}",
		       xp_hits, xp_wins, xp_attempts, xp_r_target,
		       xp_r_self, xp_r_empty);
	}

	fputs(",\"stack_depth_histogram\":{", stdout);
	for (i = 1; i <= STACK_MAX; i++) {
		unsigned long d = __atomic_load_n(
			&minicorpus_shm->stack_depth_histogram[i], __ATOMIC_RELAXED);

		if (i > 1)
			putchar(',');
		printf("\"%u\":%lu", i, d);
	}
	putchar('}');

	r_count = __atomic_load_n(&minicorpus_shm->replay_count, __ATOMIC_RELAXED);
	r_wins  = __atomic_load_n(&minicorpus_shm->replay_wins,  __ATOMIC_RELAXED);
	printf(",\"replay\":{\"count\":%lu,\"wins\":%lu}", r_count, r_wins);

	/* Pure-addition fields: dashboards that pin a strict-schema reader
	 * against "minicorpus" must tolerate two new keys.  Tracks the
	 * CMP-source corpus-save gate (saves_by_reason.cmp) and the
	 * CMP-sourced subset of mutator wins (mut_attrib_cmp_wins); both
	 * are zero pre-intervention so an unaware reader sees the
	 * historical signal unchanged.  See
	 * investigations/corpus-mutator-zero-wins-2026-05-20 for what to
	 * expect overnight. */
	{
		unsigned long saves_pc = __atomic_load_n(
			&minicorpus_shm->saves_by_reason[CORPUS_SAVE_REASON_PC],
			__ATOMIC_RELAXED);
		unsigned long saves_cmp = __atomic_load_n(
			&minicorpus_shm->saves_by_reason[CORPUS_SAVE_REASON_CMP],
			__ATOMIC_RELAXED);
		unsigned long saves_errno = __atomic_load_n(
			&minicorpus_shm->saves_by_reason[CORPUS_SAVE_REASON_ERRNO],
			__ATOMIC_RELAXED);
		unsigned long cmp_wins = __atomic_load_n(
			&minicorpus_shm->mut_attrib_cmp_wins,
			__ATOMIC_RELAXED);
		unsigned long evicts_pc = __atomic_load_n(
			&minicorpus_shm->evicts_by_reason[CORPUS_SAVE_REASON_PC],
			__ATOMIC_RELAXED);
		unsigned long evicts_cmp = __atomic_load_n(
			&minicorpus_shm->evicts_by_reason[CORPUS_SAVE_REASON_CMP],
			__ATOMIC_RELAXED);
		unsigned long errno_would = __atomic_load_n(
			&shm->stats.errno_grad_save_would_save,
			__ATOMIC_RELAXED);
		unsigned long errno_did = __atomic_load_n(
			&shm->stats.errno_grad_save_did_save,
			__ATOMIC_RELAXED);

		printf(",\"saves_by_reason\":{\"pc\":%lu,\"cmp\":%lu,\"errno\":%lu}"
		       ",\"evicts_by_reason\":{\"pc\":%lu,\"cmp\":%lu}"
		       ",\"mut_attrib_cmp_wins\":%lu"
		       ",\"errno_grad_save\":{\"would_save\":%lu,\"did_save\":%lu}",
		       saves_pc, saves_cmp, saves_errno, evicts_pc, evicts_cmp,
		       cmp_wins, errno_would, errno_did);
	}

	/* Replay-wins-by-entry-age histogram. */
	fputs(",\"replay_wins_by_age\":{", stdout);
	for (i = 0; i < ARRAY_SIZE(minicorpus_shm->replay_wins_by_age); i++) {
		unsigned long v = __atomic_load_n(
			&minicorpus_shm->replay_wins_by_age[i], __ATOMIC_RELAXED);

		if (i > 0)
			putchar(',');
		printf("\"%u\":%lu", i, v);
	}
	putchar('}');

	c_iter   = __atomic_load_n(&minicorpus_shm->chain_iter_count,         __ATOMIC_RELAXED);
	c_subst  = __atomic_load_n(&minicorpus_shm->chain_substitution_count, __ATOMIC_RELAXED);
	c_save   = chain_corpus_shm ? __atomic_load_n(&chain_corpus_shm->save_count,   __ATOMIC_RELAXED) : 0UL;
	c_replay = chain_corpus_shm ? __atomic_load_n(&chain_corpus_shm->replay_count, __ATOMIC_RELAXED) : 0UL;
	printf(",\"sequence_chains\":{\"iter_count\":%lu,\"substitutions\":%lu,"
		"\"corpus_saves\":%lu,\"corpus_replays\":%lu}",
		c_iter, c_subst, c_save, c_replay);

	putchar('}');
}

static void json_emit_cmp_hints_section(void)
{
	unsigned int i, a, total_hints = 0, syscalls_with_hints = 0;

	if (cmp_hints_shm == NULL) {
		fputs(",\"cmp_hints\":null", stdout);
		return;
	}

	/* Per-arch slots count individually so the histogram reflects the
	 * post-arch-split storage shape; under biarch the 32-bit and
	 * 64-bit halves of the same nr are unrelated syscalls. */
	for (i = 0; i < MAX_NR_SYSCALL; i++) {
		for (a = 0; a < 2; a++) {
			unsigned int n = cmp_hints_pool_safe_count(&cmp_hints_shm->pools[i][a]);

			if (n > 0) {
				total_hints += n;
				syscalls_with_hints++;
			}
		}
	}
	printf(",\"cmp_hints\":{\"values_total\":%u,\"syscalls_with_hints\":%u}",
		total_hints, syscalls_with_hints);
}

/*
 * Descriptor-table form for stat categories whose JSON / text emit shape
 * is "object name + N (field, value) scalar pairs".  Each category lists
 * its fields once; the JSON walker and the text walker iterate the same
 * descriptor so a new counter is added by declaring the struct member and
 * appending one STAT_FIELD() row -- the JSON key is derived from the
 * field-name suffix so the schema cannot drift from the struct.
 *
 * Generalises the in-tree pattern already used by defense_counters[] for
 * the periodic-window dump; here it replaces correlated edits in
 * struct stats_s + dump_stats_json() + dump_stats() with a single edit
 * site per counter.
 */
struct stat_field {
	const char *name;	/* JSON key / text metric column */
	const char *json_key;	/* Optional JSON-key override (NULL = use .name).
				 * Set when the struct member's suffix doesn't
				 * carry the JSON key the schema needs (e.g.
				 * local_fd_hash_insert_dropped emits as
				 * "local_hash_insert_dropped").  Ignored by the
				 * text walker, which always emits .name. */
	size_t      offset;	/* offsetof(struct stats_s, <field>) */
};

struct stat_category {
	const char              *name;		/* JSON object key / text category column */
	size_t                   gate_offset;	/* offsetof of the "is this category active" counter */
	const struct stat_field *fields;
	size_t                   n_fields;
};

#define STAT_FIELD(cat, suffix) \
	{ .name = #suffix, \
	  .offset = offsetof(struct stats_s, cat##_##suffix) }

/* Like STAT_FIELD, but the JSON walker emits @jkey instead of #suffix.
 * Use only when the struct member's suffix doesn't match the JSON schema
 * (cross-prefix fields pulled into a category whose JSON key isn't the
 * struct prefix; see fd_lifecycle's local_fd_/epoll_ members). */
#define STAT_FIELD_JSON(cat, suffix, jkey) \
	{ .name = #suffix, \
	  .json_key = (jkey), \
	  .offset = offsetof(struct stats_s, cat##_##suffix) }

#define STAT_CATEGORY(cat_name, gate_field, fields_array) \
	{ (cat_name), \
	  offsetof(struct stats_s, gate_field), \
	  (fields_array), \
	  ARRAY_SIZE(fields_array) }

static unsigned long stat_field_load(const struct stat_field *f)
{
	unsigned long *p = (unsigned long *)((char *)&shm->stats + f->offset);
	return __atomic_load_n(p, __ATOMIC_RELAXED);
}

static unsigned long stat_gate_load(const struct stat_category *cat)
{
	unsigned long *p = (unsigned long *)((char *)&shm->stats + cat->gate_offset);
	return __atomic_load_n(p, __ATOMIC_RELAXED);
}

/*
 * Emit one category as a JSON object: "name":{"field":N,"field":N,...}.
 * Caller is responsible for the surrounding comma separator.
 */
static void stat_category_emit_json(const struct stat_category *cat)
{
	size_t i;

	printf("\"%s\":{", cat->name);
	for (i = 0; i < cat->n_fields; i++) {
		const struct stat_field *f = &cat->fields[i];
		const char *key = f->json_key ? f->json_key : f->name;

		printf("%s\"%s\":%lu",
		       i ? "," : "",
		       key,
		       stat_field_load(f));
	}
	putchar('}');
}

/*
 * Emit one category as text rows.  Mirrors the existing
 * "if (shm->stats.<gate>) { stat_row(...); ... }" idiom: when the gate
 * counter is zero the whole block is suppressed so quiet runs stay terse.
 */
static void stat_category_emit_text(const struct stat_category *cat)
{
	size_t i;

	if (stat_gate_load(cat) == 0)
		return;
	for (i = 0; i < cat->n_fields; i++)
		stat_row(cat->name, cat->fields[i].name,
		         stat_field_load(&cat->fields[i]));
}

static const struct stat_field msg_zerocopy_churn_fields[] = {
	STAT_FIELD(msg_zerocopy_churn, runs),
	STAT_FIELD(msg_zerocopy_churn, setup_failed),
	STAT_FIELD(msg_zerocopy_churn, sends_ok),
	STAT_FIELD(msg_zerocopy_churn, sends_efault),
	STAT_FIELD(msg_zerocopy_churn, sends_eagain),
	STAT_FIELD(msg_zerocopy_churn, errqueue_drained),
	STAT_FIELD(msg_zerocopy_churn, errqueue_empty),
	STAT_FIELD(msg_zerocopy_churn, munmap_ok),
	STAT_FIELD(msg_zerocopy_churn, send_after_munmap_caught),
	STAT_FIELD(msg_zerocopy_churn, sndzc_disable_ok),
};

static const struct stat_category msg_zerocopy_churn_category =
	STAT_CATEGORY("msg_zerocopy_churn",
	              msg_zerocopy_churn_runs,
	              msg_zerocopy_churn_fields);

static const struct stat_field tcp_ulp_swap_churn_fields[] = {
	STAT_FIELD(tcp_ulp_swap_churn, runs),
	STAT_FIELD(tcp_ulp_swap_churn, setup_failed),
	STAT_FIELD(tcp_ulp_swap_churn, install_tls_ok),
	STAT_FIELD(tcp_ulp_swap_churn, tx_install_ok),
	STAT_FIELD(tcp_ulp_swap_churn, send_ok),
	STAT_FIELD(tcp_ulp_swap_churn, swap_rejected_ok),
	STAT_FIELD(tcp_ulp_swap_churn, ifname_probe_ok),
	STAT_FIELD(tcp_ulp_swap_churn, uninstall_ok),
	STAT_FIELD(tcp_ulp_swap_churn, reinstall_ok),
	STAT_FIELD(tcp_ulp_swap_churn, install_failed),
};

static const struct stat_category tcp_ulp_swap_churn_category =
	STAT_CATEGORY("tcp_ulp_swap_churn",
	              tcp_ulp_swap_churn_runs,
	              tcp_ulp_swap_churn_fields);

static const struct stat_field tls_rotate_fields[] = {
	STAT_FIELD(tls_rotate, runs),
	STAT_FIELD(tls_rotate, setup_failed),
	STAT_FIELD(tls_rotate, ulp_failed),
	STAT_FIELD(tls_rotate, ulp_asymmetric),
	STAT_FIELD(tls_rotate, installs),
	STAT_FIELD(tls_rotate, rekeys_ok),
	STAT_FIELD(tls_rotate, rekeys_rejected),
};

static const struct stat_category tls_rotate_category =
	STAT_CATEGORY("tls_rotate",
	              tls_rotate_runs,
	              tls_rotate_fields);

static const struct stat_field netns_teardown_fields[] = {
	STAT_FIELD(netns_teardown, runs),
	STAT_FIELD(netns_teardown, setup_failed),
	STAT_FIELD(netns_teardown, unshare_ok),
	STAT_FIELD(netns_teardown, socket_pair_ok),
	STAT_FIELD(netns_teardown, fork_ok),
	STAT_FIELD(netns_teardown, setns_ok),
	STAT_FIELD(netns_teardown, kill_ok),
	STAT_FIELD(netns_teardown, completed_ok),
};

static const struct stat_category netns_teardown_category =
	STAT_CATEGORY("netns_teardown",
	              netns_teardown_runs,
	              netns_teardown_fields);

static const struct stat_field setsockopt_pairing_fields[] = {
	STAT_FIELD(setsockopt_pairing, paired_emitted),
};

static const struct stat_category setsockopt_pairing_category =
	STAT_CATEGORY("setsockopt_pairing",
	              setsockopt_pairing_paired_emitted,
	              setsockopt_pairing_fields);

static const struct stat_field sched_cycler_fields[] = {
	STAT_FIELD(sched_cycler, runs),
	STAT_FIELD(sched_cycler, eperm),
};

static const struct stat_category sched_cycler_category =
	STAT_CATEGORY("sched_cycler",
	              sched_cycler_runs,
	              sched_cycler_fields);

static const struct stat_field userns_fuzzer_fields[] = {
	STAT_FIELD(userns, runs),
	STAT_FIELD(userns, inner_crashed),
	STAT_FIELD(userns, unsupported),
};

static const struct stat_category userns_fuzzer_category =
	STAT_CATEGORY("userns_fuzzer",
	              userns_runs,
	              userns_fuzzer_fields);

static const struct stat_field userns_bootstrap_fields[] = {
	STAT_FIELD(userns_bootstrap, runs),
	STAT_FIELD(userns_bootstrap, ran),
	STAT_FIELD(userns_bootstrap, eperm),
	STAT_FIELD(userns_bootstrap, userns_other),
	STAT_FIELD(userns_bootstrap, map_write_fail),
	STAT_FIELD(userns_bootstrap, map_write_fail_eperm),
	STAT_FIELD(userns_bootstrap, map_write_fail_einval),
	STAT_FIELD(userns_bootstrap, map_write_fail_other),
	STAT_FIELD(userns_bootstrap, target_unshare),
	STAT_FIELD(userns_bootstrap, fork_fail),
	STAT_FIELD(userns_bootstrap, signalled),
};

static const struct stat_category userns_bootstrap_category =
	STAT_CATEGORY("userns_bootstrap",
	              userns_bootstrap_runs,
	              userns_bootstrap_fields);

static const struct stat_field barrier_racer_fields[] = {
	STAT_FIELD(barrier_racer, runs),
	STAT_FIELD(barrier_racer, inner_crashed),
};

static const struct stat_category barrier_racer_category =
	STAT_CATEGORY("barrier_racer",
	              barrier_racer_runs,
	              barrier_racer_fields);

static const struct stat_field perf_event_chains_fields[] = {
	STAT_FIELD(perf_chains, runs),
	STAT_FIELD(perf_chains, groups_created),
	STAT_FIELD(perf_chains, ioctl_ops),
};

static const struct stat_category perf_event_chains_category =
	STAT_CATEGORY("perf_event_chains",
	              perf_chains_runs,
	              perf_event_chains_fields);

static const struct stat_field bpf_lifecycle_fields[] = {
	STAT_FIELD(bpf_lifecycle, runs),
	STAT_FIELD(bpf_lifecycle, progs_loaded),
	STAT_FIELD(bpf_lifecycle, attached),
	STAT_FIELD(bpf_lifecycle, triggered),
	STAT_FIELD(bpf_lifecycle, verifier_rejects),
	STAT_FIELD(bpf_lifecycle, attach_failed),
	STAT_FIELD(bpf_lifecycle, eperm),
};

static const struct stat_category bpf_lifecycle_category =
	STAT_CATEGORY("bpf_lifecycle",
	              bpf_lifecycle_runs,
	              bpf_lifecycle_fields);

static const struct stat_field signal_storm_fields[] = {
	STAT_FIELD(signal_storm, runs),
	STAT_FIELD(signal_storm, kill),
	STAT_FIELD(signal_storm, probe),
	STAT_FIELD(signal_storm, sigqueue),
	STAT_FIELD(signal_storm, no_targets),
};

static const struct stat_category signal_storm_category =
	STAT_CATEGORY("signal_storm",
	              signal_storm_runs,
	              signal_storm_fields);

static const struct stat_field socket_family_chain_fields[] = {
	STAT_FIELD(socket_family_chain, runs),
	STAT_FIELD(socket_family_chain, completed),
	STAT_FIELD(socket_family_chain, failed),
	STAT_FIELD(socket_family_chain, authencesn_attempts),
	STAT_FIELD(socket_family_chain, splice_attempts),
};

static const struct stat_category socket_family_chain_category =
	STAT_CATEGORY("socket_family_chain",
	              socket_family_chain_runs,
	              socket_family_chain_fields);

static const struct stat_field socket_family_grammar_fields[] = {
	STAT_FIELD(socket_family_grammar, runs),
	STAT_FIELD(socket_family_grammar, completed),
};

static const struct stat_category socket_family_grammar_category =
	STAT_CATEGORY("socket_family_grammar",
	              socket_family_grammar_runs,
	              socket_family_grammar_fields);

static const struct stat_field tcp_ao_rotate_fields[] = {
	STAT_FIELD(tcp_ao_rotate, runs),
	STAT_FIELD(tcp_ao_rotate, setup_failed),
	STAT_FIELD(tcp_ao_rotate, addkey_rejected),
	STAT_FIELD(tcp_ao_rotate, keys_added),
	STAT_FIELD(tcp_ao_rotate, connect_failed),
	STAT_FIELD(tcp_ao_rotate, connected),
	STAT_FIELD(tcp_ao_rotate, packets_sent),
	STAT_FIELD(tcp_ao_rotate, key_rotations),
	STAT_FIELD(tcp_ao_rotate, info_rejected),
	STAT_FIELD(tcp_ao_rotate, key_dels),
	STAT_FIELD(tcp_ao_rotate, delkey_rejected),
	STAT_FIELD(tcp_ao_rotate, cycles),
};

static const struct stat_category tcp_ao_rotate_category =
	STAT_CATEGORY("tcp_ao_rotate",
	              tcp_ao_rotate_runs,
	              tcp_ao_rotate_fields);

static const struct stat_field tcp_md5_listener_race_fields[] = {
	STAT_FIELD(tcp_md5_listener_race, runs),
	STAT_FIELD(tcp_md5_listener_race, setup_failed),
	STAT_FIELD(tcp_md5_listener_race, md5_set_ok),
	STAT_FIELD(tcp_md5_listener_race, md5_set_failed),
	STAT_FIELD(tcp_md5_listener_race, connect_ok),
	STAT_FIELD(tcp_md5_listener_race, rst_sent_ok),
	STAT_FIELD(tcp_md5_listener_race, completed_ok),
};

static const struct stat_category tcp_md5_listener_race_category =
	STAT_CATEGORY("tcp_md5_listener_race",
	              tcp_md5_listener_race_runs,
	              tcp_md5_listener_race_fields);

static const struct stat_field ipv6_pmtu_race_fields[] = {
	STAT_FIELD(ipv6_pmtu_race, runs),
	STAT_FIELD(ipv6_pmtu_race, setup_failed),
	STAT_FIELD(ipv6_pmtu_race, ptb_sent_ok),
	STAT_FIELD(ipv6_pmtu_race, dellink_ok),
	STAT_FIELD(ipv6_pmtu_race, completed_ok),
};

static const struct stat_category ipv6_pmtu_race_category =
	STAT_CATEGORY("ipv6_pmtu_race",
	              ipv6_pmtu_race_runs,
	              ipv6_pmtu_race_fields);

static const struct stat_field vrf_fib_churn_fields[] = {
	STAT_FIELD(vrf_fib_churn, runs),
	STAT_FIELD(vrf_fib_churn, setup_failed),
	STAT_FIELD(vrf_fib_churn, link_ok),
	STAT_FIELD(vrf_fib_churn, addr_ok),
	STAT_FIELD(vrf_fib_churn, up_ok),
	STAT_FIELD(vrf_fib_churn, rule_added),
	STAT_FIELD(vrf_fib_churn, bound),
	STAT_FIELD(vrf_fib_churn, sendto_ok),
	STAT_FIELD(vrf_fib_churn, rule2_added),
	STAT_FIELD(vrf_fib_churn, rule_removed),
	STAT_FIELD(vrf_fib_churn, link_removed),
};

static const struct stat_category vrf_fib_churn_category =
	STAT_CATEGORY("vrf_fib_churn",
	              vrf_fib_churn_runs,
	              vrf_fib_churn_fields);

static const struct stat_field mpls_route_churn_fields[] = {
	STAT_FIELD(mpls_route_churn, runs),
	STAT_FIELD(mpls_route_churn, label_install_ok),
	STAT_FIELD(mpls_route_churn, iptunnel_install_ok),
	STAT_FIELD(mpls_route_churn, delete_ok),
	STAT_FIELD(mpls_route_churn, ns_unsupported),
};

static const struct stat_category mpls_route_churn_category =
	STAT_CATEGORY("mpls_route_churn",
	              mpls_route_churn_runs,
	              mpls_route_churn_fields);

static const struct stat_field tls_ulp_churn_fields[] = {
	STAT_FIELD(tls_ulp_churn, runs),
	STAT_FIELD(tls_ulp_churn, setup_failed),
	STAT_FIELD(tls_ulp_churn, ulp_install_ok),
	STAT_FIELD(tls_ulp_churn, tx_install_ok),
	STAT_FIELD(tls_ulp_churn, send_ok),
	STAT_FIELD(tls_ulp_churn, splice_ok),
	STAT_FIELD(tls_ulp_churn, rekey_ok),
	STAT_FIELD(tls_ulp_churn, recv_ok),
};

static const struct stat_category tls_ulp_churn_category =
	STAT_CATEGORY("tls_ulp_churn",
	              tls_ulp_churn_runs,
	              tls_ulp_churn_fields);

static const struct stat_field ip6gre_bond_lapb_stack_fields[] = {
	STAT_FIELD(ip6gre_lapb, runs),
	STAT_FIELD(ip6gre_lapb, setup_failed),
	STAT_FIELD(ip6gre_lapb, flag_toggles),
};

static const struct stat_category ip6gre_bond_lapb_stack_category =
	STAT_CATEGORY("ip6gre_bond_lapb_stack",
	              ip6gre_lapb_runs,
	              ip6gre_bond_lapb_stack_fields);

static const struct stat_field vxlan_encap_churn_fields[] = {
	STAT_FIELD(vxlan_encap_churn, runs),
	STAT_FIELD(vxlan_encap_churn, setup_failed),
	STAT_FIELD(vxlan_encap_churn, link_create_ok),
	STAT_FIELD(vxlan_encap_churn, fdb_add_ok),
	STAT_FIELD(vxlan_encap_churn, link_up_ok),
	STAT_FIELD(vxlan_encap_churn, packet_sent_ok),
	STAT_FIELD(vxlan_encap_churn, link_del_ok),
};

static const struct stat_category vxlan_encap_churn_category =
	STAT_CATEGORY("vxlan_encap_churn",
	              vxlan_encap_churn_runs,
	              vxlan_encap_churn_fields);

static const struct stat_field ovs_tunnel_vport_churn_fields[] = {
	STAT_FIELD(ovs_tunnel_vport_churn, runs),
	STAT_FIELD(ovs_tunnel_vport_churn, setup_failed),
	STAT_FIELD(ovs_tunnel_vport_churn, create_ok),
	STAT_FIELD(ovs_tunnel_vport_churn, delete_ok),
	STAT_FIELD(ovs_tunnel_vport_churn, race_dellink_attempted),
};

static const struct stat_category ovs_tunnel_vport_churn_category =
	STAT_CATEGORY("ovs_tunnel_vport_churn",
	              ovs_tunnel_vport_churn_runs,
	              ovs_tunnel_vport_churn_fields);

static const struct stat_field netlink_monitor_race_fields[] = {
	STAT_FIELD(netlink_monitor_race, runs),
	STAT_FIELD(netlink_monitor_race, setup_failed),
	STAT_FIELD(netlink_monitor_race, mon_open),
	STAT_FIELD(netlink_monitor_race, mut_open),
	STAT_FIELD(netlink_monitor_race, mut_op_ok),
	STAT_FIELD(netlink_monitor_race, recv_drained),
	STAT_FIELD(netlink_monitor_race, group_drop),
	STAT_FIELD(netlink_monitor_race, group_add),
};

static const struct stat_category netlink_monitor_race_category =
	STAT_CATEGORY("netlink_monitor_race",
	              netlink_monitor_race_runs,
	              netlink_monitor_race_fields);

static const struct stat_field tipc_link_churn_fields[] = {
	STAT_FIELD(tipc_link_churn, runs),
	STAT_FIELD(tipc_link_churn, setup_failed),
	STAT_FIELD(tipc_link_churn, bearer_enable_ok),
	STAT_FIELD(tipc_link_churn, sock_rdm_ok),
	STAT_FIELD(tipc_link_churn, topsrv_connect_ok),
	STAT_FIELD(tipc_link_churn, sub_ports_sent),
	STAT_FIELD(tipc_link_churn, publish_ok),
	STAT_FIELD(tipc_link_churn, bearer_disable_ok),
};

static const struct stat_category tipc_link_churn_category =
	STAT_CATEGORY("tipc_link_churn",
	              tipc_link_churn_runs,
	              tipc_link_churn_fields);

static const struct stat_field igmp_mld_source_churn_fields[] = {
	STAT_FIELD(igmp_mld_source_churn, runs),
	STAT_FIELD(igmp_mld_source_churn, setup_failed),
	STAT_FIELD(igmp_mld_source_churn, join_ok),
	STAT_FIELD(igmp_mld_source_churn, leave_ok),
	STAT_FIELD(igmp_mld_source_churn, block_ok),
	STAT_FIELD(igmp_mld_source_churn, msfilter_ok),
	STAT_FIELD(igmp_mld_source_churn, drop_ok),
	STAT_FIELD(igmp_mld_source_churn, send_ok),
};

static const struct stat_category igmp_mld_source_churn_category =
	STAT_CATEGORY("igmp_mld_source_churn",
	              igmp_mld_source_churn_runs,
	              igmp_mld_source_churn_fields);

static const struct stat_field bridge_vlan_churn_fields[] = {
	STAT_FIELD(bridge_vlan_churn, runs),
	STAT_FIELD(bridge_vlan_churn, setup_failed),
	STAT_FIELD(bridge_vlan_churn, bridge_create_ok),
	STAT_FIELD(bridge_vlan_churn, veth_create_ok),
	STAT_FIELD(bridge_vlan_churn, vlan_add_ok),
	STAT_FIELD(bridge_vlan_churn, vlan_del_ok),
	STAT_FIELD(bridge_vlan_churn, tunnel_add_ok),
	STAT_FIELD(bridge_vlan_churn, mst_set_ok),
	STAT_FIELD(bridge_vlan_churn, raw_send_ok),
};

static const struct stat_category bridge_vlan_churn_category =
	STAT_CATEGORY("bridge_vlan_churn",
	              bridge_vlan_churn_runs,
	              bridge_vlan_churn_fields);

static const struct stat_field iscsi_target_probe_fields[] = {
	STAT_FIELD(iscsi_target_probe, runs),
	STAT_FIELD(iscsi_target_probe, setup_failed),
	STAT_FIELD(iscsi_target_probe, no_target),
	STAT_FIELD(iscsi_target_probe, connected),
	STAT_FIELD(iscsi_target_probe, login_sent),
	STAT_FIELD(iscsi_target_probe, login_replies),
	STAT_FIELD(iscsi_target_probe, scsi_cmd_sent),
	STAT_FIELD(iscsi_target_probe, bytes_out),
	STAT_FIELD(iscsi_target_probe, bytes_in),
	STAT_FIELD(iscsi_target_probe, length_decoupled),
};

static const struct stat_category iscsi_target_probe_category =
	STAT_CATEGORY("iscsi_target_probe",
	              iscsi_target_probe_runs,
	              iscsi_target_probe_fields);

static const struct stat_field iscsi_login_walker_fields[] = {
	STAT_FIELD(iscsi_walker, runs),
	STAT_FIELD(iscsi_walker, setup_failed),
	STAT_FIELD(iscsi_walker, no_target),
	STAT_FIELD(iscsi_walker, connected),
	STAT_FIELD(iscsi_walker, state_init_sent),
	STAT_FIELD(iscsi_walker, state_security_sent),
	STAT_FIELD(iscsi_walker, state_op_neg_sent),
	STAT_FIELD(iscsi_walker, ffp_iters),
	STAT_FIELD(iscsi_walker, ffp_pdus),
	STAT_FIELD(iscsi_walker, chaos_runs),
	STAT_FIELD(iscsi_walker, chaos_pdus),
	STAT_FIELD(iscsi_walker, bytes_out),
	STAT_FIELD(iscsi_walker, bytes_in),
};

static const struct stat_category iscsi_login_walker_category =
	STAT_CATEGORY("iscsi_login_walker",
	              iscsi_walker_runs,
	              iscsi_login_walker_fields);

static const struct stat_field ipv6_ndisc_proxy_fields[] = {
	STAT_FIELD(ipv6_ndisc_proxy, runs),
	STAT_FIELD(ipv6_ndisc_proxy, ns_sent_ok),
	STAT_FIELD(ipv6_ndisc_proxy, setup_failed),
	STAT_FIELD(ipv6_ndisc_proxy, proxy_enable_ok),
};

static const struct stat_category ipv6_ndisc_proxy_category =
	STAT_CATEGORY("ipv6_ndisc_proxy",
	              ipv6_ndisc_proxy_runs,
	              ipv6_ndisc_proxy_fields);

static const struct stat_field rxrpc_key_install_fields[] = {
	STAT_FIELD(rxrpc_key_install, runs),
	STAT_FIELD(rxrpc_key_install, calls),
	STAT_FIELD(rxrpc_key_install, revokes),
	STAT_FIELD(rxrpc_key_install, quota_hits),
	STAT_FIELD(rxrpc_key_install, unsupported),
};

static const struct stat_category rxrpc_key_install_category =
	STAT_CATEGORY("rxrpc_key_install",
	              rxrpc_key_install_runs,
	              rxrpc_key_install_fields);

static const struct stat_field af_alg_weak_cipher_probe_fields[] = {
	STAT_FIELD(af_alg_weak_cipher_probe, runs),
	STAT_FIELD(af_alg_weak_cipher_probe, socket_failed),
	STAT_FIELD(af_alg_weak_cipher_probe, total_bind_attempts),
	STAT_FIELD(af_alg_weak_cipher_probe, total_bind_accepted),
	STAT_FIELD(af_alg_weak_cipher_probe, weak_accepted_total),
	STAT_FIELD(af_alg_weak_cipher_probe, setkey_accepted_total),
	STAT_FIELD(af_alg_weak_cipher_probe, skcipher_weak_accepted),
	STAT_FIELD(af_alg_weak_cipher_probe, aead_weak_accepted),
	STAT_FIELD(af_alg_weak_cipher_probe, hash_weak_accepted),
	STAT_FIELD(af_alg_weak_cipher_probe, strong_rejected),
};

static const struct stat_category af_alg_weak_cipher_probe_category =
	STAT_CATEGORY("af_alg_weak_cipher_probe",
	              af_alg_weak_cipher_probe_runs,
	              af_alg_weak_cipher_probe_fields);

static const struct stat_field bridge_conntrack_churn_fields[] = {
	STAT_FIELD(bridge_ct, runs),
	STAT_FIELD(bridge_ct, flushes),
	STAT_FIELD(bridge_ct, pkts_sent),
};

static const struct stat_category bridge_conntrack_churn_category =
	STAT_CATEGORY("bridge_conntrack_churn",
	              bridge_ct_runs,
	              bridge_conntrack_churn_fields);

static const struct stat_field blkdev_lifecycle_race_fields[] = {
	STAT_FIELD(blkdev_lifecycle, runs),
	STAT_FIELD(blkdev_lifecycle, setup_failed),
	STAT_FIELD(blkdev_lifecycle, set_fd_ok),
	STAT_FIELD(blkdev_lifecycle, clr_fd),
	STAT_FIELD(blkdev_lifecycle, ebusy),
	STAT_FIELD(blkdev_lifecycle, rescans),
};

static const struct stat_category blkdev_lifecycle_race_category =
	STAT_CATEGORY("blkdev_lifecycle_race",
	              blkdev_lifecycle_runs,
	              blkdev_lifecycle_race_fields);

static const struct stat_field veth_asymmetric_xdp_fields[] = {
	STAT_FIELD(veth_asym, iters),
	STAT_FIELD(veth_asym, eperm),
	STAT_FIELD(veth_asym, unsupported),
	STAT_FIELD(veth_asym, pair_ok),
	STAT_FIELD(veth_asym, xdp_attach_ok),
	STAT_FIELD(veth_asym, send_ok),
};

static const struct stat_category veth_asymmetric_xdp_category =
	STAT_CATEGORY("veth_asymmetric_xdp",
	              veth_asym_iters,
	              veth_asymmetric_xdp_fields);

static const struct stat_field ip6erspan_netns_migrate_fields[] = {
	STAT_FIELD(inm, iters),
	STAT_FIELD(inm, eperm),
	STAT_FIELD(inm, unsupported),
	STAT_FIELD(inm, link_create_ok),
	STAT_FIELD(inm, netns_migrate_ok),
	STAT_FIELD(inm, changelink_ok),
};

static const struct stat_category ip6erspan_netns_migrate_category =
	STAT_CATEGORY("ip6erspan_netns_migrate",
	              inm_iters,
	              ip6erspan_netns_migrate_fields);

static const struct stat_field flowtable_encap_vlan_fields[] = {
	STAT_FIELD(flowtable_vlan, runs),
	STAT_FIELD(flowtable_vlan, setup_ok),
	STAT_FIELD(flowtable_vlan, setup_failed),
	STAT_FIELD(flowtable_vlan, offloaded_pkts),
	STAT_FIELD(flowtable_vlan, gso_sends),
	STAT_FIELD(flowtable_vlan, vlan_teardown_races),
	STAT_FIELD(flowtable_vlan, unsupported_latched),
};

static const struct stat_category flowtable_encap_vlan_category =
	STAT_CATEGORY("flowtable_encap_vlan",
	              flowtable_vlan_runs,
	              flowtable_encap_vlan_fields);

static const struct stat_field splice_protocols_fields[] = {
	STAT_FIELD(splice_protocols, runs),
	STAT_FIELD(splice_protocols, setup_failed),
	STAT_FIELD(splice_protocols, chain_ok),
	STAT_FIELD(splice_protocols, in_bytes),
	STAT_FIELD(splice_protocols, out_bytes),
	STAT_FIELD(splice_protocols, udp_encap_attempted),
	STAT_FIELD(splice_protocols, tcp_repair_attempted),
	STAT_FIELD(splice_protocols, packet_ring_attempted),
	STAT_FIELD(splice_protocols, alg_attempted),
	STAT_FIELD(splice_protocols, rxrpc_attempted),
	STAT_FIELD(splice_protocols, msg_splice_pages_attempted),
	STAT_FIELD(splice_protocols, msg_splice_pages_path_taken_inferred),
};

static const struct stat_category splice_protocols_category =
	STAT_CATEGORY("splice_protocols",
	              splice_protocols_runs,
	              splice_protocols_fields);

static const struct stat_field wireguard_decrypt_flood_fields[] = {
	STAT_FIELD(wgdf, runs),
	STAT_FIELD(wgdf, setup_failed),
	STAT_FIELD(wgdf, packets_sent),
	STAT_FIELD(wgdf, unsupported_latched),
};

static const struct stat_category wireguard_decrypt_flood_category =
	STAT_CATEGORY("wireguard_decrypt_flood",
	              wgdf_runs,
	              wireguard_decrypt_flood_fields);

static const struct stat_field rtnl_vf_broadcast_getlink_fields[] = {
	STAT_FIELD(rtnl_vf_broadcast, runs),
	STAT_FIELD(rtnl_vf_broadcast, setup_ok),
	STAT_FIELD(rtnl_vf_broadcast, setup_failed),
	STAT_FIELD(rtnl_vf_broadcast, getlink_ok),
};

static const struct stat_category rtnl_vf_broadcast_getlink_category =
	STAT_CATEGORY("rtnl_vf_broadcast_getlink",
	              rtnl_vf_broadcast_runs,
	              rtnl_vf_broadcast_getlink_fields);

static const struct stat_field pci_bind_fields[] = {
	STAT_FIELD(pci_bind, runs),
	STAT_FIELD(pci_bind, drivers_available),
	STAT_FIELD(pci_bind, no_devices),
	STAT_FIELD(pci_bind, unbind_ok),
	STAT_FIELD(pci_bind, unbind_enodev),
	STAT_FIELD(pci_bind, unbind_failed),
	STAT_FIELD(pci_bind, bind_ok),
	STAT_FIELD(pci_bind, bind_enodev),
	STAT_FIELD(pci_bind, bind_failed),
};

static const struct stat_category pci_bind_category =
	STAT_CATEGORY("pci_bind",
	              pci_bind_runs,
	              pci_bind_fields);

static const struct stat_field ublk_lifecycle_fields[] = {
	STAT_FIELD(ublk_lifecycle, iters),
	STAT_FIELD(ublk_lifecycle, eperm),
	STAT_FIELD(ublk_lifecycle, add_ok),
	STAT_FIELD(ublk_lifecycle, fetch_ok),
	STAT_FIELD(ublk_lifecycle, del_ok),
	STAT_FIELD(ublk_lifecycle, race_observed),
};

static const struct stat_category ublk_lifecycle_category =
	STAT_CATEGORY("ublk_lifecycle",
	              ublk_lifecycle_iters,
	              ublk_lifecycle_fields);

static const struct stat_field handshake_req_abort_fields[] = {
	STAT_FIELD(handshake_req_abort, runs),
	STAT_FIELD(handshake_req_abort, setup_failed),
	STAT_FIELD(handshake_req_abort, accept_ok),
	STAT_FIELD(handshake_req_abort, done_ok),
	STAT_FIELD(handshake_req_abort, abort_ok),
	STAT_FIELD(handshake_req_abort, orphan_close),
};

static const struct stat_category handshake_req_abort_category =
	STAT_CATEGORY("handshake_req_abort",
	              handshake_req_abort_runs,
	              handshake_req_abort_fields);

static const struct stat_field nf_conntrack_helper_churn_fields[] = {
	STAT_FIELD(nf_conntrack_helper_churn, runs),
	STAT_FIELD(nf_conntrack_helper_churn, setup_failed),
	STAT_FIELD(nf_conntrack_helper_churn, no_helper),
	STAT_FIELD(nf_conntrack_helper_churn, attach_ok),
	STAT_FIELD(nf_conntrack_helper_churn, attach_fail),
	STAT_FIELD(nf_conntrack_helper_churn, exp_ok),
	STAT_FIELD(nf_conntrack_helper_churn, packet_sent),
	STAT_FIELD(nf_conntrack_helper_churn, delete_ok),
	STAT_FIELD(nf_conntrack_helper_churn, zone_swap),
	STAT_FIELD(nf_conntrack_helper_churn, detach_ok),
};

static const struct stat_category nf_conntrack_helper_churn_category =
	STAT_CATEGORY("nf_conntrack_helper_churn",
	              nf_conntrack_helper_churn_runs,
	              nf_conntrack_helper_churn_fields);

static const struct stat_field af_unix_scm_rights_gc_fields[] = {
	STAT_FIELD(af_unix_scm_rights_gc, runs),
	STAT_FIELD(af_unix_scm_rights_gc, setup_failed),
	STAT_FIELD(af_unix_scm_rights_gc, cycle_built_ok),
	STAT_FIELD(af_unix_scm_rights_gc, close_ok),
	STAT_FIELD(af_unix_scm_rights_gc, trigger_ok),
	STAT_FIELD(af_unix_scm_rights_gc, recv_ok),
	STAT_FIELD(af_unix_scm_rights_gc, peek_ok),
	STAT_FIELD(af_unix_scm_rights_gc, iouring_variant_ok),
	STAT_FIELD(af_unix_scm_rights_gc, sibling_spawn_ok),
	STAT_FIELD(af_unix_scm_rights_gc, sibling_spawn_failed),
	STAT_FIELD(af_unix_scm_rights_gc, sibling_reaped_ok),
	STAT_FIELD(af_unix_scm_rights_gc, sibling_crashed),
};

static const struct stat_category af_unix_scm_rights_gc_category =
	STAT_CATEGORY("af_unix_scm_rights_gc",
	              af_unix_scm_rights_gc_runs,
	              af_unix_scm_rights_gc_fields);

static const struct stat_field af_unix_peek_race_fields[] = {
	STAT_FIELD(af_unix_peek_race, runs),
	STAT_FIELD(af_unix_peek_race, setup_failed),
	STAT_FIELD(af_unix_peek_race, pair_open_ok),
	STAT_FIELD(af_unix_peek_race, peek_off_armed),
	STAT_FIELD(af_unix_peek_race, peek_off_rejected),
	STAT_FIELD(af_unix_peek_race, send_ok),
	STAT_FIELD(af_unix_peek_race, shutdown_ok),
	STAT_FIELD(af_unix_peek_race, pair_rebuilds),
	STAT_FIELD(af_unix_peek_race, sibling_spawn_ok),
	STAT_FIELD(af_unix_peek_race, sibling_spawn_failed),
	STAT_FIELD(af_unix_peek_race, sibling_reaped_ok),
	STAT_FIELD(af_unix_peek_race, sibling_crashed),
};

static const struct stat_category af_unix_peek_race_category =
	STAT_CATEGORY("af_unix_peek_race",
		af_unix_peek_race_runs,
		af_unix_peek_race_fields);

static const struct stat_field sysv_shm_orphan_race_fields[] = {
	STAT_FIELD(sysv_shm_orphan_race, runs),
	STAT_FIELD(sysv_shm_orphan_race, setup_failed),
	STAT_FIELD(sysv_shm_orphan_race, shmget_ok),
	STAT_FIELD(sysv_shm_orphan_race, shmget_failed),
	STAT_FIELD(sysv_shm_orphan_race, attach_ok),
	STAT_FIELD(sysv_shm_orphan_race, attach_failed),
	STAT_FIELD(sysv_shm_orphan_race, rmid_ok),
	STAT_FIELD(sysv_shm_orphan_race, rmid_failed),
	STAT_FIELD(sysv_shm_orphan_race, sibling_spawn_ok),
	STAT_FIELD(sysv_shm_orphan_race, sibling_spawn_failed),
	STAT_FIELD(sysv_shm_orphan_race, sibling_reaped_ok),
	STAT_FIELD(sysv_shm_orphan_race, sibling_crashed),
};

static const struct stat_category sysv_shm_orphan_race_category =
	STAT_CATEGORY("sysv_shm_orphan_race",
		sysv_shm_orphan_race_runs,
		sysv_shm_orphan_race_fields);

static const struct stat_field qrtr_bind_race_fields[] = {
	STAT_FIELD(qrtr_bind_race, runs),
	STAT_FIELD(qrtr_bind_race, setup_failed),
	STAT_FIELD(qrtr_bind_race, iter),
	STAT_FIELD(qrtr_bind_race, fork_failed),
	STAT_FIELD(qrtr_bind_race, spawn_pair_ok),
	STAT_FIELD(qrtr_bind_race, sibling_reaped_ok),
	STAT_FIELD(qrtr_bind_race, sibling_crashed),
	STAT_FIELD(qrtr_bind, setup_fail),
};

static const struct stat_category qrtr_bind_race_category =
	STAT_CATEGORY("qrtr_bind_race",
		qrtr_bind_race_runs,
		qrtr_bind_race_fields);

static const struct stat_field pfkey_spd_walk_fields[] = {
	STAT_FIELD(pfkey_spd_walk, runs),
	STAT_FIELD(pfkey_spd_walk, setup_failed),
	STAT_FIELD(pfkey_spd_walk, iter),
	STAT_FIELD(pfkey_spd_walk, fork_failed),
	STAT_FIELD(pfkey_spd_walk, spawn_pair_ok),
	STAT_FIELD(pfkey_spd_walk, sibling_reaped_ok),
	STAT_FIELD(pfkey_spd_walk, sibling_crashed),
	STAT_FIELD(pfkey, spdget_resolved),
	STAT_FIELD(pfkey, spdget_missed),
};

static const struct stat_category pfkey_spd_walk_category =
	STAT_CATEGORY("pfkey_spd_walk",
		pfkey_spd_walk_runs,
		pfkey_spd_walk_fields);

static const struct stat_field l2tp_ifname_race_fields[] = {
	STAT_FIELD(l2tp_ifname_race, runs),
	STAT_FIELD(l2tp_ifname_race, setup_failed),
	STAT_FIELD(l2tp_ifname_race, iter),
	STAT_FIELD(l2tp_ifname_race, tunnel_ok),
	STAT_FIELD(l2tp_ifname_race, tunnel_fail),
	STAT_FIELD(l2tp_ifname_race, fork_failed),
	STAT_FIELD(l2tp_ifname_race, spawn_pair_ok),
	STAT_FIELD(l2tp_ifname_race, sibling_reaped_ok),
	STAT_FIELD(l2tp_ifname_race, sibling_crashed),
};

static const struct stat_category l2tp_ifname_race_category =
	STAT_CATEGORY("l2tp_ifname_race",
		l2tp_ifname_race_runs,
		l2tp_ifname_race_fields);

static const struct stat_field bpf_cgroup_attach_fields[] = {
	STAT_FIELD(bpf_cgroup_attach, runs),
	STAT_FIELD(bpf_cgroup_attach, setup_failed),
	STAT_FIELD(bpf_cgroup_attach, prog_loaded),
	STAT_FIELD(bpf_cgroup_attach, attached),
	STAT_FIELD(bpf_cgroup_attach, attach_rejected),
	STAT_FIELD(bpf_cgroup_attach, packets_sent),
	STAT_FIELD(bpf_cgroup_attach, detached),
	STAT_FIELD(bpf_cgroup_attach, post_detach_sent),
};

static const struct stat_category bpf_cgroup_attach_category =
	STAT_CATEGORY("bpf_cgroup_attach",
	              bpf_cgroup_attach_runs,
	              bpf_cgroup_attach_fields);

static const struct stat_field pipe_thrash_fields[] = {
	STAT_FIELD(pipe_thrash, runs),
	STAT_FIELD(pipe_thrash, pipes),
	STAT_FIELD(pipe_thrash, socketpairs),
	STAT_FIELD(pipe_thrash, alloc_failed),
};

static const struct stat_category pipe_thrash_category =
	STAT_CATEGORY("pipe_thrash",
	              pipe_thrash_runs,
	              pipe_thrash_fields);

static const struct stat_field fork_storm_fields[] = {
	STAT_FIELD(fork_storm, runs),
	STAT_FIELD(fork_storm, forks),
	STAT_FIELD(fork_storm, failed),
	STAT_FIELD(fork_storm, nested),
	STAT_FIELD(fork_storm, reaped_signal),
};

static const struct stat_category fork_storm_category =
	STAT_CATEGORY("fork_storm",
	              fork_storm_runs,
	              fork_storm_fields);

static const struct stat_field cpu_hotplug_rider_fields[] = {
	STAT_FIELD(cpu_hotplug, runs),
	STAT_FIELD(cpu_hotplug, affinity_calls),
	STAT_FIELD(cpu_hotplug, sysfs_writes),
	STAT_FIELD(cpu_hotplug, open_eperm),
	STAT_FIELD(cpu_hotplug, write_eperm),
	STAT_FIELD(cpu_hotplug, write_ok),
	STAT_FIELD(cpu_hotplug, actual_offlines),
};

static const struct stat_category cpu_hotplug_rider_category =
	STAT_CATEGORY("cpu_hotplug_rider",
	              cpu_hotplug_runs,
	              cpu_hotplug_rider_fields);

static const struct stat_field pidfd_storm_fields[] = {
	STAT_FIELD(pidfd_storm, runs),
	STAT_FIELD(pidfd_storm, signals),
	STAT_FIELD(pidfd_storm, getfds),
	STAT_FIELD(pidfd_storm, failed),
};

static const struct stat_category pidfd_storm_category =
	STAT_CATEGORY("pidfd_storm",
	              pidfd_storm_runs,
	              pidfd_storm_fields);

static const struct stat_field madvise_cycler_fields[] = {
	STAT_FIELD(madvise_cycler, runs),
	STAT_FIELD(madvise_cycler, calls),
	STAT_FIELD(madvise_cycler, failed),
};

static const struct stat_category madvise_cycler_category =
	STAT_CATEGORY("madvise_cycler",
	              madvise_cycler_runs,
	              madvise_cycler_fields);

static const struct stat_field keyring_spam_fields[] = {
	STAT_FIELD(keyring_spam, runs),
	STAT_FIELD(keyring_spam, calls),
	STAT_FIELD(keyring_spam, failed),
};

static const struct stat_category keyring_spam_category =
	STAT_CATEGORY("keyring_spam",
	              keyring_spam_runs,
	              keyring_spam_fields);

static const struct stat_field vdso_mremap_race_fields[] = {
	STAT_FIELD(vdso_race, runs),
	STAT_FIELD(vdso_race, mutations),
	STAT_FIELD(vdso_race, helper_segvs),
};

static const struct stat_category vdso_mremap_race_category =
	STAT_CATEGORY("vdso_mremap_race",
	              vdso_race_runs,
	              vdso_mremap_race_fields);

static const struct stat_field flock_thrash_fields[] = {
	STAT_FIELD(flock_thrash, runs),
	STAT_FIELD(flock_thrash, locks),
	STAT_FIELD(flock_thrash, failed),
};

static const struct stat_category flock_thrash_category =
	STAT_CATEGORY("flock_thrash",
	              flock_thrash_runs,
	              flock_thrash_fields);

static const struct stat_field xattr_thrash_fields[] = {
	STAT_FIELD(xattr_thrash, runs),
	STAT_FIELD(xattr_thrash, set),
	STAT_FIELD(xattr_thrash, get),
	STAT_FIELD(xattr_thrash, remove),
	STAT_FIELD(xattr_thrash, list),
	STAT_FIELD(xattr_thrash, failed),
};

static const struct stat_category xattr_thrash_category =
	STAT_CATEGORY("xattr_thrash",
	              xattr_thrash_runs,
	              xattr_thrash_fields);

static const struct stat_field epoll_volatility_fields[] = {
	STAT_FIELD(epoll_volatility, runs),
	STAT_FIELD(epoll_volatility, ctl_calls),
	STAT_FIELD(epoll_volatility, failed),
};

static const struct stat_category epoll_volatility_category =
	STAT_CATEGORY("epoll_volatility",
	              epoll_volatility_runs,
	              epoll_volatility_fields);

static const struct stat_field cgroup_churn_fields[] = {
	STAT_FIELD(cgroup_churn, runs),
	STAT_FIELD(cgroup, mkdirs),
	STAT_FIELD(cgroup, rmdirs),
	STAT_FIELD(cgroup, failed),
	STAT_FIELD(cgroup, psi_race_runs),
	STAT_FIELD(cgroup, psi_race_writes),
	STAT_FIELD(cgroup, psi_race_failed),
};

static const struct stat_category cgroup_churn_category =
	STAT_CATEGORY("cgroup_churn",
	              cgroup_churn_runs,
	              cgroup_churn_fields);

static const struct stat_field mount_churn_fields[] = {
	STAT_FIELD(mount_churn, runs),
	STAT_FIELD(mount_churn, mounts),
	STAT_FIELD(mount_churn, umounts),
	STAT_FIELD(mount_churn, failed),
};

static const struct stat_category mount_churn_category =
	STAT_CATEGORY("mount_churn",
	              mount_churn_runs,
	              mount_churn_fields);

static const struct stat_field umount_race_fields[] = {
	STAT_FIELD(umount_race, runs),
	STAT_FIELD(umount_race, picks),
	STAT_FIELD(umount_race, forks),
	STAT_FIELD(umount_race, umounts),
	STAT_FIELD(umount_race, umount_failed),
	STAT_FIELD(umount_race, setup_failed),
};

static const struct stat_category umount_race_category =
	STAT_CATEGORY("umount_race",
	              umount_race_runs,
	              umount_race_fields);

static const struct stat_field statmount_idmap_fields[] = {
	STAT_FIELD(statmount_idmap, runs),
	STAT_FIELD(statmount_idmap, setup_failed),
	STAT_FIELD(statmount_idmap, iter),
	STAT_FIELD(statmount_idmap, fork_failed),
	STAT_FIELD(statmount_idmap, carrier_ok),
	STAT_FIELD(statmount_idmap, carrier_fail),
	STAT_FIELD(statmount_idmap, setattr_ok),
	STAT_FIELD(statmount_idmap, setattr_fail),
	STAT_FIELD(statmount_idmap, statmount_call),
	STAT_FIELD(statmount_idmap, statmount_ok),
	STAT_FIELD(statmount_idmap, statmount_overflow),
};

static const struct stat_category statmount_idmap_category =
	STAT_CATEGORY("statmount_idmap",
	              statmount_idmap_runs,
	              statmount_idmap_fields);

static const struct stat_field uffd_churn_fields[] = {
	STAT_FIELD(uffd, runs),
	STAT_FIELD(uffd, registers),
	STAT_FIELD(uffd, unregisters),
	STAT_FIELD(uffd, failed),
};

static const struct stat_category uffd_churn_category =
	STAT_CATEGORY("uffd_churn",
	              uffd_runs,
	              uffd_churn_fields);

static const struct stat_field iouring_flood_fields[] = {
	STAT_FIELD(iouring, runs),
	STAT_FIELD(iouring, submits),
	STAT_FIELD(iouring, reaped),
	STAT_FIELD(iouring, failed),
};

static const struct stat_category iouring_flood_category =
	STAT_CATEGORY("iouring_flood",
	              iouring_runs,
	              iouring_flood_fields);

static const struct stat_field iouring_send_zc_churn_fields[] = {
	STAT_FIELD(iouring_send_zc_churn, runs),
	STAT_FIELD(iouring_send_zc_churn, setup_failed),
	STAT_FIELD(iouring_send_zc_churn, register_bufs_ok),
	STAT_FIELD(iouring_send_zc_churn, send_zc_ok),
	STAT_FIELD(iouring_send_zc_churn, sendmsg_zc_ok),
	STAT_FIELD(iouring_send_zc_churn, unregister_race_ok),
	STAT_FIELD(iouring_send_zc_churn, update_race_ok),
	STAT_FIELD(iouring_send_zc_churn, cqe_drained),
};

static const struct stat_category iouring_send_zc_churn_category =
	STAT_CATEGORY("iouring_send_zc_churn",
	              iouring_send_zc_churn_runs,
	              iouring_send_zc_churn_fields);

static const struct stat_field close_racer_fields[] = {
	STAT_FIELD(close_racer, runs),
	STAT_FIELD(close_racer, pairs),
	STAT_FIELD(close_racer, failed),
	STAT_FIELD(close_racer, thread_spawn_fail),
};

static const struct stat_category close_racer_category =
	STAT_CATEGORY("close_racer",
	              close_racer_runs,
	              close_racer_fields);

static const struct stat_field refcount_audit_fields[] = {
	STAT_FIELD(refcount_audit, runs),
	STAT_FIELD(refcount_audit, fd_anomalies),
	STAT_FIELD(refcount_audit, mmap_anomalies),
	STAT_FIELD(refcount_audit, sock_anomalies),
};

static const struct stat_category refcount_audit_category =
	STAT_CATEGORY("refcount_audit",
	              refcount_audit_runs,
	              refcount_audit_fields);

/*
 * Descriptors for dump_stats_json_lifecycle_and_storms().  The JSON walker
 * ignores gate_offset (it emits every category unconditionally) so the gate
 * field here only matters if a future change wires stat_category_emit_text()
 * onto these tables; the current text dump for these two categories stays
 * hand-coded in dump_stats_childop_runs_local().
 */
static const struct stat_field fs_lifecycle_fields[] = {
	STAT_FIELD(fs_lifecycle, tmpfs),
	STAT_FIELD(fs_lifecycle, ramfs),
	STAT_FIELD(fs_lifecycle, rdonly),
	STAT_FIELD(fs_lifecycle, overlay),
	STAT_FIELD(fs_lifecycle, quota),
	STAT_FIELD(fs_lifecycle, bind),
	STAT_FIELD(fs_lifecycle, unsupported),
};

static const struct stat_category fs_lifecycle_category =
	STAT_CATEGORY("fs_lifecycle",
	              fs_lifecycle_tmpfs,
	              fs_lifecycle_fields);

static const struct stat_field futex_storm_fields[] = {
	STAT_FIELD(futex_storm, runs),
	STAT_FIELD(futex_storm, inner_crashed),
	STAT_FIELD(futex_storm, iters),
};

static const struct stat_category futex_storm_category =
	STAT_CATEGORY("futex_storm",
	              futex_storm_runs,
	              futex_storm_fields);

/*
 * Descriptors for dump_stats_json_oracle().  Every member is named
 * <syscall>_oracle_anomalies in struct stats_s but the JSON schema emits it
 * as "<syscall>_anomalies" (the "oracle_" infix is implicit in the enclosing
 * category key), so each row uses STAT_FIELD_JSON to pin the cross-prefix
 * JSON key.  The JSON walker ignores stat_category.gate_offset (it emits
 * every category unconditionally) and the text dump for oracle stays
 * hand-coded in dump_stats_oracle_anomalies() where each row has its own
 * per-field gate, so fd_oracle_anomalies here is a placeholder gate that
 * matters only if a future change wires stat_category_emit_text() onto this
 * table.
 */
static const struct stat_field oracle_fields[] = {
	STAT_FIELD_JSON(fd_oracle, anomalies, "fd_anomalies"),
	STAT_FIELD_JSON(mmap_oracle, anomalies, "mmap_anomalies"),
	STAT_FIELD_JSON(cred_oracle, anomalies, "cred_anomalies"),
	STAT_FIELD_JSON(sched_oracle, anomalies, "sched_anomalies"),
	STAT_FIELD_JSON(uid_oracle, anomalies, "uid_anomalies"),
	STAT_FIELD_JSON(gid_oracle, anomalies, "gid_anomalies"),
	STAT_FIELD_JSON(setgroups_oracle, anomalies, "setgroups_anomalies"),
	STAT_FIELD_JSON(getegid_oracle, anomalies, "getegid_anomalies"),
	STAT_FIELD_JSON(getuid_oracle, anomalies, "getuid_anomalies"),
	STAT_FIELD_JSON(getgid_oracle, anomalies, "getgid_anomalies"),
	STAT_FIELD_JSON(getppid_oracle, anomalies, "getppid_anomalies"),
	STAT_FIELD_JSON(getcwd_oracle, anomalies, "getcwd_anomalies"),
	STAT_FIELD_JSON(getpid_oracle, anomalies, "getpid_anomalies"),
	STAT_FIELD_JSON(getpgid_oracle, anomalies, "getpgid_anomalies"),
	STAT_FIELD_JSON(getpgrp_oracle, anomalies, "getpgrp_anomalies"),
	STAT_FIELD_JSON(geteuid_oracle, anomalies, "geteuid_anomalies"),
	STAT_FIELD_JSON(getsid_oracle, anomalies, "getsid_anomalies"),
	STAT_FIELD_JSON(gettid_oracle, anomalies, "gettid_anomalies"),
	STAT_FIELD_JSON(setsid_oracle, anomalies, "setsid_anomalies"),
	STAT_FIELD_JSON(setpgid_oracle, anomalies, "setpgid_anomalies"),
	STAT_FIELD_JSON(sched_getscheduler_oracle, anomalies, "sched_getscheduler_anomalies"),
	STAT_FIELD_JSON(getgroups_oracle, anomalies, "getgroups_anomalies"),
	STAT_FIELD_JSON(getresuid_oracle, anomalies, "getresuid_anomalies"),
	STAT_FIELD_JSON(getresgid_oracle, anomalies, "getresgid_anomalies"),
	STAT_FIELD_JSON(umask_oracle, anomalies, "umask_anomalies"),
	STAT_FIELD_JSON(sched_get_priority_max_oracle, anomalies, "sched_get_priority_max_anomalies"),
	STAT_FIELD_JSON(sched_get_priority_min_oracle, anomalies, "sched_get_priority_min_anomalies"),
	STAT_FIELD_JSON(sched_yield_oracle, anomalies, "sched_yield_anomalies"),
	STAT_FIELD_JSON(getpagesize_oracle, anomalies, "getpagesize_anomalies"),
	STAT_FIELD_JSON(time_oracle, anomalies, "time_anomalies"),
	STAT_FIELD_JSON(gettimeofday_oracle, anomalies, "gettimeofday_anomalies"),
	STAT_FIELD_JSON(newuname_oracle, anomalies, "newuname_anomalies"),
	STAT_FIELD_JSON(rt_sigpending_oracle, anomalies, "rt_sigpending_anomalies"),
	STAT_FIELD_JSON(sched_getaffinity_oracle, anomalies, "sched_getaffinity_anomalies"),
	STAT_FIELD_JSON(rt_sigprocmask_oracle, anomalies, "rt_sigprocmask_anomalies"),
	STAT_FIELD_JSON(sched_getparam_oracle, anomalies, "sched_getparam_anomalies"),
	STAT_FIELD_JSON(sched_rr_get_interval_oracle, anomalies, "sched_rr_get_interval_anomalies"),
	STAT_FIELD_JSON(get_robust_list_oracle, anomalies, "get_robust_list_anomalies"),
	STAT_FIELD_JSON(getrlimit_oracle, anomalies, "getrlimit_anomalies"),
	STAT_FIELD_JSON(sysinfo_oracle, anomalies, "sysinfo_anomalies"),
	STAT_FIELD_JSON(times_oracle, anomalies, "times_anomalies"),
	STAT_FIELD_JSON(clock_getres_oracle, anomalies, "clock_getres_anomalies"),
	STAT_FIELD_JSON(capget_oracle, anomalies, "capget_anomalies"),
	STAT_FIELD_JSON(capdrop_oracle, anomalies, "capdrop_anomalies"),
	STAT_FIELD_JSON(newlstat_oracle, anomalies, "newlstat_anomalies"),
	STAT_FIELD_JSON(newstat_oracle, anomalies, "newstat_anomalies"),
	STAT_FIELD_JSON(newfstat_oracle, anomalies, "newfstat_anomalies"),
	STAT_FIELD_JSON(newfstatat_oracle, anomalies, "newfstatat_anomalies"),
	STAT_FIELD_JSON(statx_oracle, anomalies, "statx_anomalies"),
	STAT_FIELD_JSON(fstatfs_oracle, anomalies, "fstatfs_anomalies"),
	STAT_FIELD_JSON(fstatfs64_oracle, anomalies, "fstatfs64_anomalies"),
	STAT_FIELD_JSON(statfs_oracle, anomalies, "statfs_anomalies"),
	STAT_FIELD_JSON(statfs64_oracle, anomalies, "statfs64_anomalies"),
	STAT_FIELD_JSON(uname_oracle, anomalies, "uname_anomalies"),
	STAT_FIELD_JSON(lsm_list_modules_oracle, anomalies, "lsm_list_modules_anomalies"),
	STAT_FIELD_JSON(listmount_oracle, anomalies, "listmount_anomalies"),
	STAT_FIELD_JSON(statmount_oracle, anomalies, "statmount_anomalies"),
	STAT_FIELD_JSON(getsockname_oracle, anomalies, "getsockname_anomalies"),
	STAT_FIELD_JSON(getpeername_oracle, anomalies, "getpeername_anomalies"),
	STAT_FIELD_JSON(file_getattr_oracle, anomalies, "file_getattr_anomalies"),
	STAT_FIELD_JSON(sched_getattr_oracle, anomalies, "sched_getattr_anomalies"),
	STAT_FIELD_JSON(getrusage_oracle, anomalies, "getrusage_anomalies"),
	STAT_FIELD_JSON(sigpending_oracle, anomalies, "sigpending_anomalies"),
	STAT_FIELD_JSON(getcpu_oracle, anomalies, "getcpu_anomalies"),
	STAT_FIELD_JSON(clock_gettime_oracle, anomalies, "clock_gettime_anomalies"),
	STAT_FIELD_JSON(get_mempolicy_oracle, anomalies, "get_mempolicy_anomalies"),
	STAT_FIELD_JSON(lsm_get_self_attr_oracle, anomalies, "lsm_get_self_attr_anomalies"),
	STAT_FIELD_JSON(prlimit64_oracle, anomalies, "prlimit64_anomalies"),
	STAT_FIELD_JSON(sigaltstack_oracle, anomalies, "sigaltstack_anomalies"),
	STAT_FIELD_JSON(olduname_oracle, anomalies, "olduname_anomalies"),
	STAT_FIELD_JSON(lookup_dcookie_oracle, anomalies, "lookup_dcookie_anomalies"),
	STAT_FIELD_JSON(getxattr_oracle, anomalies, "getxattr_anomalies"),
	STAT_FIELD_JSON(lgetxattr_oracle, anomalies, "lgetxattr_anomalies"),
	STAT_FIELD_JSON(fgetxattr_oracle, anomalies, "fgetxattr_anomalies"),
	STAT_FIELD_JSON(listxattrat_oracle, anomalies, "listxattrat_anomalies"),
	STAT_FIELD_JSON(flistxattr_oracle, anomalies, "flistxattr_anomalies"),
	STAT_FIELD_JSON(listxattr_oracle, anomalies, "listxattr_anomalies"),
	STAT_FIELD_JSON(llistxattr_oracle, anomalies, "llistxattr_anomalies"),
	STAT_FIELD_JSON(readlink_oracle, anomalies, "readlink_anomalies"),
	STAT_FIELD_JSON(readlinkat_oracle, anomalies, "readlinkat_anomalies"),
	STAT_FIELD_JSON(sysfs_oracle, anomalies, "sysfs_anomalies"),
};

static const struct stat_category oracle_category =
	STAT_CATEGORY("oracle",
	              fd_oracle_anomalies,
	              oracle_fields);

/*
 * Descriptor tables staged for the follow-up JSON fan-out (per-fn conversions
 * of dump_stats_json_iouring_and_zombies / _socket_family_and_tls /
 * _iouring_zc_and_kvm / _netfilter_and_xfrm / _fault_and_fd_lifecycle).
 *
 * The category JSON key in each case doesn't match the struct member's
 * single prefix, so STAT_FIELD() rows pick whichever prefix matches the
 * actual struct member (packet_fanout_*, recipe_*, nat_t_churn_/nat_t_,
 * kvm_run_/kvm_, fd_/local_fd_/epoll_); .name doubles as the text-side
 * key.  For fd_lifecycle's three cross-prefix members (local_fd_* and
 * epoll_*) the suffix alone wouldn't yield the schema's JSON key, so
 * STAT_FIELD_JSON() pins the JSON key explicitly.
 *
 * As with the fs_lifecycle/futex_storm pair above, the JSON walker
 * ignores stat_category.gate_offset; the gate field is set to the same
 * counter the existing text emitter uses (or a placeholder for
 * fd_lifecycle, which has no single gate) so a future text-side wiring
 * has a sensible default.  These tables have no live caller yet -- they
 * land here so the per-fn JSON conversions can be reviewed in isolation.
 */
static const struct stat_field packet_fanout_thrash_fields[] = {
	STAT_FIELD(packet_fanout, runs),
	STAT_FIELD(packet_fanout, setup_failed),
	STAT_FIELD(packet_fanout, ring_failed),
	STAT_FIELD(packet_fanout, rings_installed),
	STAT_FIELD(packet_fanout, mmap_failed),
	STAT_FIELD(packet_fanout, joins),
	STAT_FIELD(packet_fanout, rejoins_ok),
	STAT_FIELD(packet_fanout, rejoins_rejected),
};

static const struct stat_category packet_fanout_thrash_category
	__attribute__((unused)) =
	STAT_CATEGORY("packet_fanout_thrash",
	              packet_fanout_runs,
	              packet_fanout_thrash_fields);

static const struct stat_field recipe_runner_fields[] = {
	STAT_FIELD(recipe, runs),
	STAT_FIELD(recipe, completed),
	STAT_FIELD(recipe, partial),
	STAT_FIELD(recipe, unsupported),
};

static const struct stat_category recipe_runner_category =
	STAT_CATEGORY("recipe_runner",
	              recipe_runs,
	              recipe_runner_fields);

/*
 * Descriptors for the remaining categories in
 * dump_stats_json_iouring_and_zombies().  The text-side dump for these stays
 * hand-coded for now, and the JSON walker ignores gate_offset, so the gate
 * field choices below only matter if a future change wires
 * stat_category_emit_text() onto these tables.
 */
static const struct stat_field iouring_recipes_fields[] = {
	STAT_FIELD(iouring_recipes, runs),
	STAT_FIELD(iouring_recipes, completed),
	STAT_FIELD(iouring_recipes, partial),
	STAT_FIELD(iouring_recipes, enosys),
};

static const struct stat_category iouring_recipes_category =
	STAT_CATEGORY("iouring_recipes",
	              iouring_recipes_runs,
	              iouring_recipes_fields);

static const struct stat_field iouring_eventfd_fields[] = {
	STAT_FIELD(iouring_eventfd, register_ok),
	STAT_FIELD(iouring_eventfd, register_fail),
	STAT_FIELD(iouring_eventfd, recursive_runs),
	STAT_FIELD(iouring_eventfd, recursive_cqes),
};

static const struct stat_category iouring_eventfd_category =
	STAT_CATEGORY("iouring_eventfd",
	              iouring_eventfd_register_ok,
	              iouring_eventfd_fields);

/* zombie_slots mixes two struct prefixes (zombie_slots_ for the gauge,
 * zombies_ for the counters); each STAT_FIELD picks its own prefix so the
 * JSON keys stay flat ("pending", "reaped", "timed_out"). */
static const struct stat_field zombie_slots_fields[] = {
	STAT_FIELD(zombie_slots, pending),
	STAT_FIELD(zombies, reaped),
	STAT_FIELD(zombies, timed_out),
};

static const struct stat_category zombie_slots_category =
	STAT_CATEGORY("zombie_slots",
	              zombies_reaped,
	              zombie_slots_fields);

static const struct stat_field nat_t_churn_fields[] = {
	STAT_FIELD(nat_t_churn, runs),
	STAT_FIELD(nat_t_churn, setup_failed),
	STAT_FIELD(nat_t_churn, sa_added),
	STAT_FIELD(nat_t_churn, sa_deleted),
	STAT_FIELD(nat_t_churn, frames_sent),
	STAT_FIELD(nat_t, xfrm6_setup_ok),
	STAT_FIELD(nat_t, xfrm6_setup_fail),
	STAT_FIELD(nat_t, xfrm6_sendto_runs),
	STAT_FIELD(nat_t, xfrm6_delsa_races),
};

static const struct stat_category nat_t_churn_category
	__attribute__((unused)) =
	STAT_CATEGORY("nat_t_churn",
	              nat_t_churn_runs,
	              nat_t_churn_fields);

static const struct stat_field kvm_run_churn_fields[] = {
	STAT_FIELD(kvm_run, invocations),
	STAT_FIELD(kvm_run, exit_io),
	STAT_FIELD(kvm_run, exit_mmio),
	STAT_FIELD(kvm_run, exit_hlt),
	STAT_FIELD(kvm_run, exit_shutdown),
	STAT_FIELD(kvm_run, exit_fail_entry),
	STAT_FIELD(kvm_run, exit_internal_error),
	STAT_FIELD(kvm_run, exit_intr),
	STAT_FIELD(kvm_run, exit_other),
	STAT_FIELD(kvm_run, errors),
	STAT_FIELD(kvm, gpc_memslot_race_runs),
	STAT_FIELD(kvm, gpc_memslot_race_deletes),
	STAT_FIELD(kvm, gpc_memslot_race_unsupported),
};

static const struct stat_category kvm_run_churn_category
	__attribute__((unused)) =
	STAT_CATEGORY("kvm_run_churn",
	              kvm_run_invocations,
	              kvm_run_churn_fields);

static const struct stat_field fd_lifecycle_fields[] = {
	STAT_FIELD(fd, stale_detected),
	STAT_FIELD(fd, stale_by_generation),
	STAT_FIELD(fd, closed_tracked),
	STAT_FIELD(fd, duped),
	STAT_FIELD(fd, events_processed),
	STAT_FIELD(fd, events_dropped),
	STAT_FIELD(fd, event_close_count),
	STAT_FIELD(fd, event_evict_count),
	STAT_FIELD(fd, hash_reinsert_dropped),
	STAT_FIELD_JSON(local_fd, hash_insert_dropped,
	                "local_hash_insert_dropped"),
	STAT_FIELD(fd, runtime_registered),
	STAT_FIELD_JSON(epoll, lazy_armed, "epoll_lazy_armed"),
	STAT_FIELD_JSON(epoll, blocking_poll_skipped,
	                "epoll_blocking_poll_skipped"),
	STAT_FIELD(fd, random_exhausted),
	STAT_FIELD(fd, provider_invalid),
};

/* fd_lifecycle has no single gate counter -- the text emitter ORs many
 * fields.  Use fd_stale_detected as a placeholder for the JSON walker
 * (which ignores gate_offset); any text-side wiring will need to revisit. */
static const struct stat_category fd_lifecycle_category
	__attribute__((unused)) =
	STAT_CATEGORY("fd_lifecycle",
	              fd_stale_detected,
	              fd_lifecycle_fields);

/*
 * Emit every counter from struct stats_s as a single JSON object.
 * All scalar counters are emitted unconditionally so consumers see a stable
 * schema regardless of which subsystems happened to fire on this run.
 */
static void dump_stats_json_fault_and_fd_lifecycle(void)
{
	printf("\"fault_injection\":{\"armed_fail_nth\":%lu,\"returned_enomem\":%lu},"
		"\"fd_lifecycle\":{\"stale_detected\":%lu,\"stale_by_generation\":%lu,"
			"\"closed_tracked\":%lu,\"duped\":%lu,"
			"\"events_processed\":%lu,\"events_dropped\":%lu,"
			"\"event_close_count\":%lu,\"event_evict_count\":%lu,"
			"\"hash_reinsert_dropped\":%lu,"
			"\"local_hash_insert_dropped\":%lu,"
			"\"runtime_registered\":%lu,\"epoll_lazy_armed\":%lu,"
			"\"epoll_blocking_poll_skipped\":%lu,"
			"\"random_exhausted\":%lu,"
			"\"provider_invalid\":%lu,"
			"\"live_remove_calls\":%lu,"
			"\"live_remove_miss\":%lu,"
			"\"live_remove_scan_histogram\":[%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu],"
			"\"event_full_close\":%lu,"
			"\"event_full_evict\":%lu,"
			"\"event_full_close_range\":%lu,"
			"\"event_close_range_enqueued\":%lu,"
			"\"event_close_range_length_sum\":%lu},",
		parent_stats.fault_injected, parent_stats.fault_consumed,
		shm->stats.fd_stale_detected, shm->stats.fd_stale_by_generation,
		shm->stats.fd_closed_tracked,
		shm->stats.fd_duped, shm->stats.fd_events_processed,
		shm->stats.fd_events_dropped,
		shm->stats.fd_event_close_count, shm->stats.fd_event_evict_count,
		shm->stats.fd_hash_reinsert_dropped,
		shm->stats.local_fd_hash_insert_dropped,
		shm->stats.fd_runtime_registered,
		shm->stats.epoll_lazy_armed,
		shm->stats.epoll_blocking_poll_skipped,
		shm->stats.fd_random_exhausted,
		shm->stats.fd_provider_invalid,
		shm->stats.fd_live_remove_calls,
		shm->stats.fd_live_remove_miss,
		shm->stats.fd_live_remove_scan_histogram[0],
		shm->stats.fd_live_remove_scan_histogram[1],
		shm->stats.fd_live_remove_scan_histogram[2],
		shm->stats.fd_live_remove_scan_histogram[3],
		shm->stats.fd_live_remove_scan_histogram[4],
		shm->stats.fd_live_remove_scan_histogram[5],
		shm->stats.fd_live_remove_scan_histogram[6],
		shm->stats.fd_live_remove_scan_histogram[7],
		shm->stats.fd_event_full_close,
		shm->stats.fd_event_full_evict,
		shm->stats.fd_event_full_close_range,
		shm->stats.fd_event_close_range_enqueued,
		shm->stats.fd_event_close_range_length_sum);
}

static void dump_stats_json_oracle(void)
{
	stat_category_emit_json(&oracle_category);
	putchar(',');
}

/*
 * Descriptor tables for dump_stats_json_basic_subsystems().
 *
 * The eight categories below were previously emitted by a single
 * hand-written printf with one %lu slot per field and a parallel
 * shm->stats.<field> va-list; adding a counter required three
 * correlated edits.  These tables collapse that to one STAT_FIELD*
 * row per field.
 *
 * The JSON walker ignores stat_category.gate_offset (every category
 * emits unconditionally), so the gate choices below only matter if a
 * future change wires stat_category_emit_text() onto these tables.
 * Each text-side block in dump_stats_text() stays hand-coded for now
 * and picks its own gate predicate.
 *
 * Where the JSON schema key doesn't match the struct member suffix
 * (vfs_writes, memory_pressure) the row uses STAT_FIELD_JSON to pin
 * the JSON key; .name still mirrors the struct suffix so the
 * descriptor stays self-consistent.  Those .name values do NOT match
 * the keys the hand-coded text emitter currently uses, so any future
 * text-side wiring onto these tables will need to revisit .name.
 */
static const struct stat_field vfs_writes_fields[] = {
	STAT_FIELD_JSON(procfs_writes, open_fail,  "procfs_open_fail"),
	STAT_FIELD_JSON(procfs_writes, write_fail, "procfs_write_fail"),
	STAT_FIELD_JSON(procfs_writes, write_ok,   "procfs_write_ok"),
	STAT_FIELD_JSON(sysfs_writes, open_fail,   "sysfs_open_fail"),
	STAT_FIELD_JSON(sysfs_writes, write_fail,  "sysfs_write_fail"),
	STAT_FIELD_JSON(sysfs_writes, write_ok,    "sysfs_write_ok"),
	STAT_FIELD_JSON(debugfs_writes, open_fail, "debugfs_open_fail"),
	STAT_FIELD_JSON(debugfs_writes, write_fail,"debugfs_write_fail"),
	STAT_FIELD_JSON(debugfs_writes, write_ok,  "debugfs_write_ok"),
};

static const struct stat_category vfs_writes_category =
	STAT_CATEGORY("vfs_writes",
	              procfs_writes_open_fail,
	              vfs_writes_fields);

static const struct stat_field memory_pressure_fields[] = {
	STAT_FIELD_JSON(memory_pressure, runs, "runs_madv_pageout"),
};

static const struct stat_category memory_pressure_category =
	STAT_CATEGORY("memory_pressure",
	              memory_pressure_runs,
	              memory_pressure_fields);

static const struct stat_field genetlink_fuzzer_fields[] = {
	STAT_FIELD(genetlink, families_discovered),
	STAT_FIELD(genetlink, msgs_sent),
	STAT_FIELD(genetlink, eperm),
	STAT_FIELD(genetlink, stale_seq_drops),
	STAT_FIELD(genetlink, missing_producer),
	STAT_FIELD(genetlink, discovery_io_err),
	STAT_FIELD(genetlink, discovery_nlerr),
};

static const struct stat_category genetlink_fuzzer_category =
	STAT_CATEGORY("genetlink_fuzzer",
	              genetlink_families_discovered,
	              genetlink_fuzzer_fields);

static const struct stat_field genl_family_calls_fields[] = {
	STAT_FIELD(genl_family_calls, devlink),
	STAT_FIELD(genl_family_calls, nl80211),
	STAT_FIELD(genl_family_calls, taskstats),
	STAT_FIELD(genl_family_calls, ethtool),
	STAT_FIELD(genl_family_calls, mptcp_pm),
	STAT_FIELD(genl_family_calls, tipc),
	STAT_FIELD(genl_family_calls, wireguard),
	STAT_FIELD(genl_family_calls, l2tp),
	STAT_FIELD(genl_family_calls, gtp),
	STAT_FIELD(genl_family_calls, macsec),
	STAT_FIELD(genl_family_calls, netlabel),
	STAT_FIELD(genl_family_calls, team),
	STAT_FIELD(genl_family_calls, hsr),
	STAT_FIELD(genl_family_calls, fou),
	STAT_FIELD(genl_family_calls, psample),
	STAT_FIELD(genl_family_calls, ila),
	STAT_FIELD(genl_family_calls, ioam6),
	STAT_FIELD(genl_family_calls, seg6),
	STAT_FIELD(genl_family_calls, thermal),
	STAT_FIELD(genl_family_calls, ipvs),
};

static const struct stat_category genl_family_calls_category =
	STAT_CATEGORY("genl_family_calls",
	              genl_family_calls_devlink,
	              genl_family_calls_fields);

static const struct stat_field nfnl_subsys_calls_fields[] = {
	STAT_FIELD(nfnl_subsys_calls, ctnetlink),
	STAT_FIELD(nfnl_subsys_calls, ctnetlink_exp),
	STAT_FIELD(nfnl_subsys_calls, nftables),
	STAT_FIELD(nfnl_subsys_calls, ipset),
};

static const struct stat_category nfnl_subsys_calls_category =
	STAT_CATEGORY("nfnl_subsys_calls",
	              nfnl_subsys_calls_ctnetlink,
	              nfnl_subsys_calls_fields);

static const struct stat_field netlink_generator_fields[] = {
	STAT_FIELD(netlink, nested_attrs_emitted),
};

static const struct stat_category netlink_generator_category =
	STAT_CATEGORY("netlink_generator",
	              netlink_nested_attrs_emitted,
	              netlink_generator_fields);

static const struct stat_field tracefs_fuzzer_fields[] = {
	STAT_FIELD_JSON(tracefs_kprobe_writes, open_fail,        "kprobe_open_fail"),
	STAT_FIELD_JSON(tracefs_kprobe_writes, write_fail,       "kprobe_write_fail"),
	STAT_FIELD_JSON(tracefs_kprobe_writes, write_ok,         "kprobe_write_ok"),
	STAT_FIELD_JSON(tracefs_uprobe_writes, open_fail,        "uprobe_open_fail"),
	STAT_FIELD_JSON(tracefs_uprobe_writes, write_fail,       "uprobe_write_fail"),
	STAT_FIELD_JSON(tracefs_uprobe_writes, write_ok,         "uprobe_write_ok"),
	STAT_FIELD_JSON(tracefs_filter_writes, open_fail,        "filter_open_fail"),
	STAT_FIELD_JSON(tracefs_filter_writes, write_fail,       "filter_write_fail"),
	STAT_FIELD_JSON(tracefs_filter_writes, write_ok,         "filter_write_ok"),
	STAT_FIELD_JSON(tracefs_event_enable_writes, open_fail,  "event_enable_open_fail"),
	STAT_FIELD_JSON(tracefs_event_enable_writes, write_fail, "event_enable_write_fail"),
	STAT_FIELD_JSON(tracefs_event_enable_writes, write_ok,   "event_enable_write_ok"),
	STAT_FIELD_JSON(tracefs_misc_writes, open_fail,          "misc_open_fail"),
	STAT_FIELD_JSON(tracefs_misc_writes, write_fail,         "misc_write_fail"),
	STAT_FIELD_JSON(tracefs_misc_writes, write_ok,           "misc_write_ok"),
};

static const struct stat_category tracefs_fuzzer_category =
	STAT_CATEGORY("tracefs_fuzzer",
	              tracefs_kprobe_writes_open_fail,
	              tracefs_fuzzer_fields);

static const struct stat_field bpf_fd_provider_fields[] = {
	STAT_FIELD(bpf, maps_provided),
	STAT_FIELD(bpf, progs_provided),
};

static const struct stat_category bpf_fd_provider_category =
	STAT_CATEGORY("bpf_fd_provider",
	              bpf_maps_provided,
	              bpf_fd_provider_fields);

static void dump_stats_json_basic_subsystems(void)
{
	stat_category_emit_json(&vfs_writes_category);
	putchar(',');
	stat_category_emit_json(&memory_pressure_category);
	putchar(',');
	stat_category_emit_json(&genetlink_fuzzer_category);
	putchar(',');
	stat_category_emit_json(&genl_family_calls_category);
	putchar(',');
	stat_category_emit_json(&nfnl_subsys_calls_category);
	putchar(',');
	stat_category_emit_json(&netlink_generator_category);
	putchar(',');
	stat_category_emit_json(&tracefs_fuzzer_category);
	putchar(',');
	stat_category_emit_json(&bpf_fd_provider_category);
	putchar(',');
}

static void dump_stats_json_iouring_and_zombies(void)
{
	stat_category_emit_json(&recipe_runner_category);
	putchar(',');
	stat_category_emit_json(&iouring_recipes_category);
	putchar(',');
	stat_category_emit_json(&iouring_eventfd_category);
	putchar(',');
	stat_category_emit_json(&zombie_slots_category);
	putchar(',');
}

static void dump_stats_json_corruption_and_audit(void)
{
	printf("\"corruption\":{\"fd_event_ring_noncanon\":%lu,"
			"\"fd_event_ring_canary\":%lu,\"fd_event_payload\":%lu,"
			"\"stats_ring_noncanon\":%lu,\"stats_ring_canary\":%lu,"
			"\"deferred_free_corrupt_ptr\":%lu,"
			"\"post_handler_corrupt_ptr\":%lu,\"deferred_free_reject\":%lu,"
			"\"deferred_free_reject_pathname\":%lu,"
			"\"deferred_free_reject_iovec\":%lu,"
			"\"deferred_free_reject_sockaddr\":%lu,"
			"\"deferred_free_reject_other\":%lu,"
			"\"snapshot_non_heap_reject\":%lu,"
			"\"rec_canary_stomped\":%lu,\"rzs_blanket_reject\":%lu,"
			"\"retfd_blanket_reject\":%lu,"
			"\"arena_ptr_stale_caught_arg\":%lu,"
			"\"arena_ptr_stale_caught_post_state\":%lu,"
			"\"sibling_mprotect_failed\":%lu,"
			"\"destroy_object_idx\":%lu,"
			"\"global_obj_uaf_caught\":%lu,"
			"\"maps_pool_draw_exhausted\":%lu,"
			"\"maps_reject_pool_empty\":%lu,"
			"\"maps_reject_bogus_obj_ptr\":%lu,"
			"\"maps_reject_alloc_track_miss\":%lu,"
			"\"maps_reject_alloc_track_miss_anon\":%lu,"
			"\"maps_reject_alloc_track_miss_file\":%lu,"
			"\"maps_reject_alloc_track_miss_testfile\":%lu,"
			"\"maps_reject_size_zero\":%lu,"
			"\"maps_reject_size_too_large\":%lu,"
			"\"maps_pool_chosen_anon\":%lu,"
			"\"maps_pool_chosen_file\":%lu,"
			"\"maps_pool_chosen_testfile\":%lu,"
			"\"maps_reject_pool_empty_anon\":%lu,"
			"\"maps_reject_pool_empty_file\":%lu,"
			"\"maps_reject_pool_empty_testfile\":%lu,"
			"\"maps_prot_reject_by_mask\":[%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu],"
			"\"maps_pick_attempts_sum\":%lu,"
			"\"maps_pick_successes\":%lu,"
			"\"maps_pick_with_prot_attempts_sum\":%lu,"
			"\"maps_pick_with_prot_successes\":%lu,"
			"\"maps_type_resolution_calls\":%lu,"
			"\"maps_type_resolution_scan_length_sum\":%lu,"
			"\"maps_type_resolution_hits\":%lu,"
			"\"chain_corpus_save_dup_shape\":%lu,"
			"\"chain_corpus_save_unique_shape\":%lu,"
			"\"deferred_free_reject_misaligned\":%lu,"
			"\"deferred_free_reject_corrupt_shape\":%lu,"
			"\"deferred_free_reject_non_heap\":%lu,"
			"\"deferred_free_reject_untracked\":%lu,"
			"\"nested_scrub_reject_untracked\":%lu,"
			"\"deferred_free_reject_shared_region\":%lu,"
			"\"deferred_free_outstanding_vmas\":%lu,"
			"\"deferred_free_vma_fallback_immediate\":%lu,"
			"\"deferred_free_enomem_drain\":%lu,"
			"\"deferred_free_rw_restore_enomem\":%lu,"
			"\"deferred_free_pre_dispatch_leaked\":%lu,"
			"\"ring_evict_leaked\":%lu,"
			"\"deferred_free_ring_owned_skip\":%lu,"
			"\"deferred_free_double_admit_skip\":%lu,"
			"\"alloc_track_refresh_ring_owned_skip\":%lu,"
			"\"alloc_track_refresh_unverified_skip\":%lu,"
			"\"pagecache_canary_corrupt_caught\":%lu,"
			"\"objpool_array_stale_caught\":%lu,"
			"\"lock_word_scribbled\":%lu,"
			"\"lock_held_scribble\":%lu,"
			"\"chain_replay_len_corrupt\":%lu},"
		"\"shared_buffer\":{\"args_redirected\":%lu,\"range_overlaps_shared_rejects\":%lu,"
			"\"libc_heap_redirected\":%lu,\"libc_heap_embedded_redirected\":%lu,"
			"\"get_writable_address_scribbled_shm_range\":%lu,"
			"\"get_writable_address_scribbled_mprotect_mmap\":%lu,"
			"\"get_writable_address_scribbled_mprotect_shm\":%lu,"
			"\"get_writable_address_scribbled_postmp_mmap\":%lu,"
			"\"get_writable_address_scribbled_postmp_shm\":%lu,"
			"\"get_writable_address_enomem_exhausted\":%lu,"
			"\"get_writable_address_bookkeeping_ro_fault\":%lu,"
			"\"mm_gate_post_slip\":%lu},",
		shm->stats.fd_event_ring_corrupted,
		shm->stats.fd_event_ring_overwritten,
		shm->stats.fd_event_payload_corrupt,
		shm->stats.stats_ring_corrupted,
		shm->stats.stats_ring_overwritten,
		parent_stats.deferred_free_corrupt_ptr,
		parent_stats.post_handler_corrupt_ptr,
		parent_stats.deferred_free_reject,
		parent_stats.deferred_free_reject_pathname,
		parent_stats.deferred_free_reject_iovec,
		parent_stats.deferred_free_reject_sockaddr,
		parent_stats.deferred_free_reject_other,
		parent_stats.snapshot_non_heap_reject,
		shm->stats.rec_canary_stomped,
		shm->stats.rzs_blanket_reject,
		shm->stats.retfd_blanket_reject,
		shm->stats.arena_ptr_stale_caught_arg,
		shm->stats.arena_ptr_stale_caught_post_state,
		shm->stats.sibling_mprotect_failed,
		shm->stats.destroy_object_idx_corrupt,
		shm->stats.global_obj_uaf_caught,
		shm->stats.maps_pool_draw_exhausted,
		shm->stats.maps_reject_pool_empty,
		shm->stats.maps_reject_bogus_obj_ptr,
		shm->stats.maps_reject_alloc_track_miss,
		shm->stats.maps_reject_alloc_track_miss_anon,
		shm->stats.maps_reject_alloc_track_miss_file,
		shm->stats.maps_reject_alloc_track_miss_testfile,
		shm->stats.maps_reject_size_zero,
		shm->stats.maps_reject_size_too_large,
		shm->stats.maps_pool_chosen_anon,
		shm->stats.maps_pool_chosen_file,
		shm->stats.maps_pool_chosen_testfile,
		shm->stats.maps_reject_pool_empty_anon,
		shm->stats.maps_reject_pool_empty_file,
		shm->stats.maps_reject_pool_empty_testfile,
		shm->stats.maps_prot_reject_by_mask[0],
		shm->stats.maps_prot_reject_by_mask[1],
		shm->stats.maps_prot_reject_by_mask[2],
		shm->stats.maps_prot_reject_by_mask[3],
		shm->stats.maps_prot_reject_by_mask[4],
		shm->stats.maps_prot_reject_by_mask[5],
		shm->stats.maps_prot_reject_by_mask[6],
		shm->stats.maps_prot_reject_by_mask[7],
		shm->stats.maps_pick_attempts_sum,
		shm->stats.maps_pick_successes,
		shm->stats.maps_pick_with_prot_attempts_sum,
		shm->stats.maps_pick_with_prot_successes,
		shm->stats.maps_type_resolution_calls,
		shm->stats.maps_type_resolution_scan_length_sum,
		shm->stats.maps_type_resolution_hits,
		shm->stats.chain_corpus_save_dup_shape,
		shm->stats.chain_corpus_save_unique_shape,
		shm->stats.deferred_free_reject_misaligned,
		shm->stats.deferred_free_reject_corrupt_shape,
		shm->stats.deferred_free_reject_non_heap,
		shm->stats.deferred_free_reject_untracked,
		shm->stats.nested_scrub_reject_untracked,
		shm->stats.deferred_free_reject_shared_region,
		shm->stats.deferred_free_outstanding_vmas,
		shm->stats.deferred_free_vma_fallback_immediate,
		shm->stats.deferred_free_enomem_drain,
		shm->stats.deferred_free_rw_restore_enomem,
		shm->stats.deferred_free_pre_dispatch_leaked,
		shm->stats.ring_evict_leaked,
		shm->stats.deferred_free_ring_owned_skip,
		shm->stats.deferred_free_double_admit_skip,
		shm->stats.alloc_track_refresh_ring_owned_skip,
		shm->stats.alloc_track_refresh_unverified_skip,
		shm->stats.pagecache_canary_corrupt_caught,
		shm->stats.objpool_array_stale_caught,
		parent_stats.lock_word_scribbled,
		shm->stats.lock_held_scribble,
		shm->stats.chain_replay_len_corrupt,
		parent_stats.shared_buffer_redirected, parent_stats.range_overlaps_shared_rejects,
		parent_stats.libc_heap_redirected, parent_stats.libc_heap_embedded_redirected,
		parent_stats.get_writable_address_scribbled_shm_range,
		parent_stats.get_writable_address_scribbled_mprotect_mmap,
		parent_stats.get_writable_address_scribbled_mprotect_shm,
		parent_stats.get_writable_address_scribbled_postmp_mmap,
		parent_stats.get_writable_address_scribbled_postmp_shm,
		parent_stats.get_writable_address_enomem_exhausted,
		parent_stats.get_writable_address_bookkeeping_ro_fault,
		parent_stats.mm_gate_post_slip);
}

static void dump_stats_json_lifecycle_and_storms(void)
{
	stat_category_emit_json(&fs_lifecycle_category);
	putchar(',');
	stat_category_emit_json(&futex_storm_category);
	putchar(',');
}

static void dump_stats_json_socket_family_and_tls(void)
{
	printf("\"packet_fanout_thrash\":{\"runs\":%lu,\"setup_failed\":%lu,\"ring_failed\":%lu,\"rings_installed\":%lu,\"mmap_failed\":%lu,\"joins\":%lu,\"rejoins_ok\":%lu,\"rejoins_rejected\":%lu},"
		"\"eth_emitter\":{\"runs\":%lu,\"setup_failed\":%lu,\"short\":%lu,\"sends_ok\":%lu,\"sends_failed\":%lu,\"tmpl_arp\":%lu,\"tmpl_ipv4_frag_zero\":%lu,\"tmpl_ipv6_na\":%lu,\"tmpl_vlan_qinq\":%lu,\"tmpl_bad_ethertype\":%lu},"
		"\"iouring_net_multishot\":{\"runs\":%lu,\"setup_failed\":%lu,\"pbuf_ring_ok\":%lu,\"pbuf_legacy_ok\":%lu,\"armed\":%lu,\"packets_sent\":%lu,\"completions\":%lu,\"cancel_submitted\":%lu,\"napi_register_ok\":%lu,\"napi_register_fail\":%lu,\"napi_unregister_ok\":%lu,\"napi_unregister_fail\":%lu},"
		"\"bridge_fdb_stp\":{\"runs\":%lu,\"setup_failed\":%lu,\"bridge_create_ok\":%lu,\"veth_create_ok\":%lu,\"raw_send_ok\":%lu,\"stp_toggle_ok\":%lu,\"fdb_del_ok\":%lu,\"link_del_ok\":%lu,\"vlan_mass_runs\":%lu,\"vlan_mass_max_n\":%lu,\"vlan_mass_enotbufs\":%lu},",
		shm->stats.packet_fanout_runs,
		shm->stats.packet_fanout_setup_failed,
		shm->stats.packet_fanout_ring_failed,
		shm->stats.packet_fanout_rings_installed,
		shm->stats.packet_fanout_mmap_failed,
		shm->stats.packet_fanout_joins,
		shm->stats.packet_fanout_rejoins_ok,
		shm->stats.packet_fanout_rejoins_rejected,
		shm->stats.eth_emitter_runs,
		shm->stats.eth_emitter_setup_failed,
		shm->stats.eth_emitter_short,
		shm->stats.eth_emitter_sends_ok,
		shm->stats.eth_emitter_sends_failed,
		shm->stats.eth_emitter_per_tmpl[0],
		shm->stats.eth_emitter_per_tmpl[1],
		shm->stats.eth_emitter_per_tmpl[2],
		shm->stats.eth_emitter_per_tmpl[3],
		shm->stats.eth_emitter_per_tmpl[4],
		shm->stats.iouring_multishot_runs,
		shm->stats.iouring_multishot_setup_failed,
		shm->stats.iouring_multishot_pbuf_ring_ok,
		shm->stats.iouring_multishot_pbuf_legacy_ok,
		shm->stats.iouring_multishot_armed,
		shm->stats.iouring_multishot_packets_sent,
		shm->stats.iouring_multishot_completions,
		shm->stats.iouring_multishot_cancel_submitted,
		shm->stats.iouring_napi_register_ok,
		shm->stats.iouring_napi_register_fail,
		shm->stats.iouring_napi_unregister_ok,
		shm->stats.iouring_napi_unregister_fail,
		shm->stats.bridge_fdb_stp_runs,
		shm->stats.bridge_fdb_stp_setup_failed,
		shm->stats.bridge_fdb_stp_bridge_create_ok,
		shm->stats.bridge_fdb_stp_veth_create_ok,
		shm->stats.bridge_fdb_stp_raw_send_ok,
		shm->stats.bridge_fdb_stp_stp_toggle_ok,
		shm->stats.bridge_fdb_stp_fdb_del_ok,
		shm->stats.bridge_fdb_stp_link_del_ok,
		shm->stats.bridge_vlan_mass_runs,
		shm->stats.bridge_vlan_mass_max_n,
		shm->stats.bridge_vlan_mass_enotbufs);
}

/*
 * Descriptor tables for dump_stats_json_netfilter_and_xfrm().
 *
 * Six categories that the previous hand-written printf emitted with one
 * %lu slot per field and a parallel shm->stats.<field> va-list; adding a
 * counter required three correlated edits.  STAT_FIELD picks whichever
 * struct prefix matches the actual member (nftables_churn_/nft_,
 * tc_qdisc_churn_/tc_qdisc_, xfrm_churn_/xfrm_ah_esn_,
 * mptcp_pm_churn_/mptcp_setsockopt_/mptcp_getsockopt_/mptcp_sockopt_);
 * .name doubles as the (currently unused) text-side key.  STAT_FIELD_JSON
 * pins the JSON key for the xt_ct_* members pulled into nftables_churn,
 * whose struct suffix (e.g. "ct_iters") doesn't carry the "xt_ct_"
 * qualifier the schema emits.
 *
 * The text emitter for these subsystems stays hand-coded for now, so the
 * gate_offset choices below only matter if a future change wires
 * stat_category_emit_text() onto these tables.
 */
static const struct stat_field nftables_churn_fields[] = {
	STAT_FIELD(nftables_churn, runs),
	STAT_FIELD(nftables_churn, setup_failed),
	STAT_FIELD(nftables_churn, table_create_ok),
	STAT_FIELD(nftables_churn, set_create_ok),
	STAT_FIELD(nftables_churn, chain_create_ok),
	STAT_FIELD(nftables_churn, rule_create_ok),
	STAT_FIELD(nftables_churn, packet_sent_ok),
	STAT_FIELD(nftables_churn, rule_insert_ok),
	STAT_FIELD(nftables_churn, rule_del_ok),
	STAT_FIELD(nftables_churn, table_del_ok),
	STAT_FIELD(nftables_churn, payload_expr_emit),
	STAT_FIELD(nftables_churn, objref_expr_emit),
	STAT_FIELD(nft, compat_validate_install_ok),
	STAT_FIELD(nft, compat_validate_install_fail),
	STAT_FIELD(nft, compat_validate_unsupported),
	STAT_FIELD(nft, compat_validate_per_hook_pairs),
	STAT_FIELD(nft, dormant_abort_iters),
	STAT_FIELD(nft, dormant_abort_eperm),
	STAT_FIELD(nft, dormant_abort_emsg),
	STAT_FIELD(nft, dormant_abort_ok),
	STAT_FIELD_JSON(xt, ct_iters, "xt_ct_iters"),
	STAT_FIELD_JSON(xt, ct_eperm, "xt_ct_eperm"),
	STAT_FIELD_JSON(xt, ct_unsupported, "xt_ct_unsupported"),
	STAT_FIELD_JSON(xt, ct_set_ok, "xt_ct_set_ok"),
	STAT_FIELD_JSON(xt, ct_get_ok, "xt_ct_get_ok"),
	STAT_FIELD_JSON(xt, ct_v2_seen, "xt_ct_v2_seen"),
	STAT_FIELD(nft, fwd_loop_runs),
	STAT_FIELD(nft, fwd_loop_ns_setup_failed),
	STAT_FIELD(nft, fwd_loop_probe_sent_ok),
	STAT_FIELD(nft, fwd_loop_completed_ok),
	STAT_FIELD(nft, l4frag_iters),
	STAT_FIELD(nft, l4frag_install_ok),
	STAT_FIELD(nft, l4frag_rule_ok),
	STAT_FIELD(nft, l4frag_send_ok),
	STAT_FIELD(nft, l4frag_send_failed),
};

static const struct stat_category nftables_churn_category =
	STAT_CATEGORY("nftables_churn",
	              nftables_churn_runs,
	              nftables_churn_fields);

static const struct stat_field tc_qdisc_churn_fields[] = {
	STAT_FIELD(tc_qdisc_churn, runs),
	STAT_FIELD(tc_qdisc_churn, setup_failed),
	STAT_FIELD(tc_qdisc_churn, link_create_ok),
	STAT_FIELD(tc_qdisc_churn, qdisc_create_ok),
	STAT_FIELD(tc_qdisc_churn, tclass_create_ok),
	STAT_FIELD(tc_qdisc_churn, tfilter_create_ok),
	STAT_FIELD(tc_qdisc_churn, packet_sent_ok),
	STAT_FIELD(tc_qdisc_churn, qdisc_replace_ok),
	STAT_FIELD(tc_qdisc_churn, tfilter_del_ok),
	STAT_FIELD(tc_qdisc_churn, qdisc_del_ok),
	STAT_FIELD(tc_qdisc_churn, link_del_ok),
	STAT_FIELD(tc_qdisc, peek_stack_runs),
	STAT_FIELD(tc_qdisc, peek_stack_install_ok),
	STAT_FIELD(tc_qdisc, peek_stack_install_fail),
	STAT_FIELD(tc_qdisc, peek_stack_burst_ok),
	STAT_FIELD(tc_qdisc_churn, bridge_parent_runs),
	STAT_FIELD(tc_qdisc_churn, bridge_dellink_race_ok),
	STAT_FIELD(tc_qdisc_churn, gso_burst_ok),
};

static const struct stat_category tc_qdisc_churn_category =
	STAT_CATEGORY("tc_qdisc_churn",
	              tc_qdisc_churn_runs,
	              tc_qdisc_churn_fields);

static const struct stat_field tc_mirred_blockcast_fields[] = {
	STAT_FIELD(tc_mirred_blockcast, runs),
	STAT_FIELD(tc_mirred_blockcast, setup_failed),
	STAT_FIELD(tc_mirred_blockcast, qdisc_ok),
	STAT_FIELD(tc_mirred_blockcast, qdisc_fail),
	STAT_FIELD(tc_mirred_blockcast, filter_ok),
	STAT_FIELD(tc_mirred_blockcast, filter_fail),
	STAT_FIELD(tc_mirred_blockcast, packet_sent_ok),
};

static const struct stat_category tc_mirred_blockcast_category =
	STAT_CATEGORY("tc_mirred_blockcast",
		tc_mirred_blockcast_runs,
		tc_mirred_blockcast_fields);

static const struct stat_field xfrm_churn_fields[] = {
	STAT_FIELD(xfrm_churn, runs),
	STAT_FIELD(xfrm_churn, setup_failed),
	STAT_FIELD(xfrm_churn, sa_added),
	STAT_FIELD(xfrm_churn, tunnel_sa_added),
	STAT_FIELD(xfrm_churn, iptfs_sa_added),
	STAT_FIELD(xfrm_churn, sa_updated),
	STAT_FIELD(xfrm_churn, sa_deleted),
	STAT_FIELD(xfrm_churn, pol_added),
	STAT_FIELD(xfrm_churn, pol_deleted),
	STAT_FIELD(xfrm_churn, esp_sent),
	STAT_FIELD(xfrm_churn, zc_sent),
	STAT_FIELD(xfrm_churn, zc_errq_drained),
	STAT_FIELD(xfrm_churn, pfkey_send_ok),
	STAT_FIELD(xfrm_churn, burn_runs),
	STAT_FIELD(xfrm_churn, burn_throttled),
	STAT_FIELD(xfrm_churn, burn_completed),
	STAT_FIELD(xfrm, ah_esn_setup_ok),
	STAT_FIELD(xfrm, ah_esn_setup_fail),
	STAT_FIELD(xfrm, ah_esn_async_runs),
	STAT_FIELD(xfrm, ah_esn_delsa_races),
};

static const struct stat_category xfrm_churn_category =
	STAT_CATEGORY("xfrm_churn",
	              xfrm_churn_runs,
	              xfrm_churn_fields);

static const struct stat_field sock_diag_walker_fields[] = {
	STAT_FIELD(sock_diag_walker, runs),
	STAT_FIELD(sock_diag_walker, setup_failed),
	STAT_FIELD(sock_diag_walker, inet),
	STAT_FIELD(sock_diag_walker, unix),
	STAT_FIELD(sock_diag_walker, netlink),
	STAT_FIELD(sock_diag_walker, packet),
	STAT_FIELD(sock_diag_walker, vsock),
};

static const struct stat_category sock_diag_walker_category =
	STAT_CATEGORY("sock_diag_walker",
	              sock_diag_walker_runs,
	              sock_diag_walker_fields);

static const struct stat_field sctp_assoc_churn_fields[] = {
	STAT_FIELD(sctp_assoc_churn, runs),
	STAT_FIELD(sctp_assoc_churn, setup_failed),
	STAT_FIELD(sctp_assoc_churn, bindx_added),
	STAT_FIELD(sctp_assoc_churn, bindx_removed),
	STAT_FIELD(sctp_assoc_churn, bindx_rejected),
	STAT_FIELD(sctp_assoc_churn, connect_failed),
	STAT_FIELD(sctp_assoc_churn, connected),
	STAT_FIELD(sctp_assoc_churn, accepted),
	STAT_FIELD(sctp_assoc_churn, packets_sent),
	STAT_FIELD(sctp_assoc_churn, peeled_off),
	STAT_FIELD(sctp_assoc_churn, peeloff_rejected),
	STAT_FIELD(sctp_assoc_churn, cycles),
};

static const struct stat_category sctp_assoc_churn_category =
	STAT_CATEGORY("sctp_assoc_churn",
	              sctp_assoc_churn_runs,
	              sctp_assoc_churn_fields);

static const struct stat_field mptcp_pm_churn_fields[] = {
	STAT_FIELD(mptcp_pm_churn, runs),
	STAT_FIELD(mptcp_pm_churn, setup_failed),
	STAT_FIELD(mptcp_pm_churn, sock_mptcp_ok),
	STAT_FIELD(mptcp_pm_churn, addr_added_ok),
	STAT_FIELD(mptcp_pm_churn, addr_removed_ok),
	STAT_FIELD(mptcp_pm_churn, send_ok),
	STAT_FIELD(mptcp, setsockopt_unsupported),
	STAT_FIELD(mptcp, setsockopt_master_set),
	STAT_FIELD(mptcp, setsockopt_master_fail),
	STAT_FIELD(mptcp, getsockopt_verify_ok),
	STAT_FIELD(mptcp, getsockopt_verify_drift),
	STAT_FIELD(mptcp, sockopt_sweep_runs),
	STAT_FIELD(mptcp, sockopt_set_ok),
	STAT_FIELD(mptcp, sockopt_set_failed),
	STAT_FIELD(mptcp, sockopt_subflow_added),
	STAT_FIELD(mptcp, sockopt_readback_ok),
	STAT_FIELD(mptcp, sockopt_inherit_mismatch),
	STAT_FIELD(mptcp, sockopt_unsupported_latched),
};

static const struct stat_category mptcp_pm_churn_category =
	STAT_CATEGORY("mptcp_pm_churn",
	              mptcp_pm_churn_runs,
	              mptcp_pm_churn_fields);

static const struct stat_field devlink_port_churn_fields[] = {
	STAT_FIELD(devlink_port_churn, iterations),
	STAT_FIELD(devlink_port_churn, split_ok),
	STAT_FIELD(devlink_port_churn, split_fail),
	STAT_FIELD(devlink_port_churn, reload_ok),
	STAT_FIELD(devlink_port_churn, reload_fail),
	STAT_FIELD(devlink_port_churn, create_skipped),
};

static const struct stat_category devlink_port_churn_category =
	STAT_CATEGORY("devlink_port_churn",
	              devlink_port_churn_iterations,
	              devlink_port_churn_fields);

static void dump_stats_json_netfilter_and_xfrm(void)
{
	stat_category_emit_json(&nftables_churn_category);
	putchar(',');
	stat_category_emit_json(&tc_qdisc_churn_category);
	putchar(',');
	stat_category_emit_json(&tc_mirred_blockcast_category);
	putchar(',');
	stat_category_emit_json(&xfrm_churn_category);
	putchar(',');
	stat_category_emit_json(&sock_diag_walker_category);
	putchar(',');
	stat_category_emit_json(&sctp_assoc_churn_category);
	putchar(',');
	stat_category_emit_json(&mptcp_pm_churn_category);
	putchar(',');
	stat_category_emit_json(&devlink_port_churn_category);
}

static void dump_stats_json_iouring_zc_and_kvm(void)
{
	printf(","
		"\"vsock_transport_churn\":{\"runs\":%lu,\"setup_failed\":%lu,\"bind_ok\":%lu,\"connect_ok\":%lu,\"send_ok\":%lu,\"buffer_size_ok\":%lu,\"timeout_ok\":%lu,\"get_cid_ok\":%lu,\"seq_eom_runs\":%lu,\"seq_eom_sends_ok\":%lu,\"seq_eom_sends_failed\":%lu,\"seq_eom_skipped\":%lu},"
		"\"psp_key_rotate\":{\"runs\":%lu,\"setup_failed\":%lu,\"netdev_create_ok\":%lu,\"family_resolve_ok\":%lu,\"dev_get_ok\":%lu,\"key_install_ok\":%lu,\"spi_set_ok\":%lu,\"send_ok\":%lu,\"rotate_ok\":%lu,\"spi_switch_ok\":%lu,\"shutdown_ok\":%lu,\"devlink_port_churn_runs\":%lu,\"devlink_port_churn_port_add_ok\":%lu,\"devlink_port_churn_port_del_ok\":%lu,\"devlink_port_churn_vf_spawn_ok\":%lu,\"devlink_port_churn_unsupported_latched\":%lu},"
		"\"afxdp_churn\":{\"runs\":%lu,\"setup_failed\":%lu,\"umem_reg_ok\":%lu,\"rings_setup_ok\":%lu,\"prog_load_ok\":%lu,\"map_create_ok\":%lu,\"map_update_ok\":%lu,\"bind_ok\":%lu,\"link_attach_ok\":%lu,\"netlink_attach_ok\":%lu,\"attach_failed\":%lu,\"send_ok\":%lu,\"recv_ok\":%lu,\"map_delete_ok\":%lu,\"munmap_race_ok\":%lu,\"xsg_iters\":%lu,\"tx_metadata_iters\":%lu,\"tun_bind_iters\":%lu,\"xsg_bind_failed\":%lu,\"tx_md_bind_failed\":%lu},"
		"\"kvm\":{\"vcpu_ioctls_dispatched\":%lu},"
		"\"kvm_run_churn\":{\"invocations\":%lu,\"exit_io\":%lu,\"exit_mmio\":%lu,\"exit_hlt\":%lu,\"exit_shutdown\":%lu,\"exit_fail_entry\":%lu,\"exit_internal_error\":%lu,\"exit_intr\":%lu,\"exit_other\":%lu,\"errors\":%lu,\"gpc_memslot_race_runs\":%lu,\"gpc_memslot_race_deletes\":%lu,\"gpc_memslot_race_unsupported\":%lu},"
		"\"nl80211\":{\"runs\":%lu,\"setup_failed\":%lu,\"scan_triggered\":%lu,\"connect_attempted\":%lu,\"connect_succeeded\":%lu,\"disconnect_attempted\":%lu,\"regdom_changed\":%lu,\"iface_created\":%lu,\"iface_destroyed\":%lu,\"bursts_sent\":%lu,\"pmsr_runs\":%lu,\"pmsr_ok\":%lu,\"admin_gate_runs\":%lu,\"admin_gate_eperm_ok\":%lu,\"admin_gate_unexpected\":%lu},"
		"\"nat_t_churn\":{\"runs\":%lu,\"setup_failed\":%lu,\"sa_added\":%lu,\"sa_deleted\":%lu,\"frames_sent\":%lu,\"xfrm6_setup_ok\":%lu,\"xfrm6_setup_fail\":%lu,\"xfrm6_sendto_runs\":%lu,\"xfrm6_delsa_races\":%lu},",
		shm->stats.vsock_transport_churn_runs,
		shm->stats.vsock_transport_churn_setup_failed,
		shm->stats.vsock_transport_churn_bind_ok,
		shm->stats.vsock_transport_churn_connect_ok,
		shm->stats.vsock_transport_churn_send_ok,
		shm->stats.vsock_transport_churn_buffer_size_ok,
		shm->stats.vsock_transport_churn_timeout_ok,
		shm->stats.vsock_transport_churn_get_cid_ok,
		shm->stats.vsock_seq_eom_runs,
		shm->stats.vsock_seq_eom_sends_ok,
		shm->stats.vsock_seq_eom_sends_failed,
		shm->stats.vsock_seq_eom_skipped,
		shm->stats.psp_key_rotate_runs,
		shm->stats.psp_key_rotate_setup_failed,
		shm->stats.psp_key_rotate_netdev_create_ok,
		shm->stats.psp_key_rotate_family_resolve_ok,
		shm->stats.psp_key_rotate_dev_get_ok,
		shm->stats.psp_key_rotate_key_install_ok,
		shm->stats.psp_key_rotate_spi_set_ok,
		shm->stats.psp_key_rotate_send_ok,
		shm->stats.psp_key_rotate_rotate_ok,
		shm->stats.psp_key_rotate_spi_switch_ok,
		shm->stats.psp_key_rotate_shutdown_ok,
		shm->stats.psp_devlink_port_churn_runs,
		shm->stats.psp_devlink_port_churn_port_add_ok,
		shm->stats.psp_devlink_port_churn_port_del_ok,
		shm->stats.psp_devlink_port_churn_vf_spawn_ok,
		shm->stats.psp_devlink_port_churn_unsupported_latched,
		shm->stats.afxdp_churn_runs,
		shm->stats.afxdp_churn_setup_failed,
		shm->stats.afxdp_churn_umem_reg_ok,
		shm->stats.afxdp_churn_rings_setup_ok,
		shm->stats.afxdp_churn_prog_load_ok,
		shm->stats.afxdp_churn_map_create_ok,
		shm->stats.afxdp_churn_map_update_ok,
		shm->stats.afxdp_churn_bind_ok,
		shm->stats.afxdp_churn_link_attach_ok,
		shm->stats.afxdp_churn_netlink_attach_ok,
		shm->stats.afxdp_churn_attach_failed,
		shm->stats.afxdp_churn_send_ok,
		shm->stats.afxdp_churn_recv_ok,
		shm->stats.afxdp_churn_map_delete_ok,
		shm->stats.afxdp_churn_munmap_race_ok,
		shm->stats.afxdp_xsg_iters,
		shm->stats.afxdp_tx_metadata_iters,
		shm->stats.afxdp_tun_bind_iters,
		shm->stats.afxdp_xsg_bind_failed,
		shm->stats.afxdp_tx_md_bind_failed,
		shm->stats.kvm_vcpu_ioctls_dispatched,
		shm->stats.kvm_run_invocations,
		shm->stats.kvm_run_exit_io,
		shm->stats.kvm_run_exit_mmio,
		shm->stats.kvm_run_exit_hlt,
		shm->stats.kvm_run_exit_shutdown,
		shm->stats.kvm_run_exit_fail_entry,
		shm->stats.kvm_run_exit_internal_error,
		shm->stats.kvm_run_exit_intr,
		shm->stats.kvm_run_exit_other,
		shm->stats.kvm_run_errors,
		shm->stats.kvm_gpc_memslot_race_runs,
		shm->stats.kvm_gpc_memslot_race_deletes,
		shm->stats.kvm_gpc_memslot_race_unsupported,
		shm->stats.nl80211_runs,
		shm->stats.nl80211_setup_failed,
		shm->stats.nl80211_scan_triggered,
		shm->stats.nl80211_connect_attempted,
		shm->stats.nl80211_connect_succeeded,
		shm->stats.nl80211_disconnect_attempted,
		shm->stats.nl80211_regdom_changed,
		shm->stats.nl80211_iface_created,
		shm->stats.nl80211_iface_destroyed,
		shm->stats.nl80211_bursts_sent,
		shm->stats.nl80211_pmsr_runs,
		shm->stats.nl80211_pmsr_ok,
		shm->stats.nl80211_admin_gate_runs,
		shm->stats.nl80211_admin_gate_eperm_ok,
		shm->stats.nl80211_admin_gate_unexpected,
		shm->stats.nat_t_churn_runs,
		shm->stats.nat_t_churn_setup_failed,
		shm->stats.nat_t_churn_sa_added,
		shm->stats.nat_t_churn_sa_deleted,
		shm->stats.nat_t_churn_frames_sent,
		shm->stats.nat_t_xfrm6_setup_ok,
		shm->stats.nat_t_xfrm6_setup_fail,
		shm->stats.nat_t_xfrm6_sendto_runs,
		shm->stats.nat_t_xfrm6_delsa_races);
}

static void dump_stats_json_rxrpc_alg_ublk_block(void)
{
	printf("\"af_alg_probe\":{\"runs\":%lu,\"unsupported\":%lu,\"accept_total\":%lu,\"reject_total\":%lu},"
		"\"af_alg_recvmsg\":{\"runs\":%lu,\"setkey_sent\":%lu,\"iv_sent\":%lu,\"oob_iov\":%lu,\"zerolen\":%lu,\"oversize\":%lu,\"empty_cmsg_no_more\":%lu,\"unsupported\":%lu},",
		shm->stats.af_alg_probe_runs,
		shm->stats.af_alg_probe_unsupported,
		shm->stats.af_alg_probe_accept_total,
		shm->stats.af_alg_probe_reject_total,
		shm->stats.af_alg_recvmsg_runs,
		shm->stats.af_alg_recvmsg_setkey_sent,
		shm->stats.af_alg_recvmsg_iv_sent,
		shm->stats.af_alg_recvmsg_oob_iov,
		shm->stats.af_alg_recvmsg_zerolen,
		shm->stats.af_alg_recvmsg_oversize,
		shm->stats.af_alg_recvmsg_empty_cmsg_no_more,
		shm->stats.af_alg_recvmsg_unsupported);
}

static void dump_stats_json_probes_misuse_and_tail(void)
{
	printf("\"ipvs_sysctl_writer\":{\"runs\":%lu,\"writes_ok\":%lu,\"writes_failed\":%lu,\"unsupported_latched\":%lu,\"burn_iters\":%lu},"
		"\"ipfrag_source_churn\":{\"runs\":%lu,\"packets_sent_ok\":%lu,\"send_failed\":%lu,\"unique_srcs\":%lu},"
		"\"obscure_af_churn\":{\"runs\":%lu,\"no_viable_pf\":%lu,"
			"\"sendmsg_no_bind\":{\"runs\":%lu,\"rejected\":%lu,\"unexpected_success\":%lu},"
			"\"bind_then_sendmsg\":{\"runs\":%lu,\"rejected\":%lu,\"unexpected_success\":%lu},"
			"\"connect_no_listen\":{\"runs\":%lu,\"rejected\":%lu,\"unexpected_success\":%lu},"
			"\"ioctl_rotation\":{\"runs\":%lu,\"rejected\":%lu,\"unexpected_success\":%lu},"
			"\"setsockopt_zero_len\":{\"runs\":%lu,\"rejected\":%lu,\"unexpected_success\":%lu},"
			"\"close_via_dup\":{\"runs\":%lu,\"rejected\":%lu,\"unexpected_success\":%lu}},"
		"\"rxrpc_sendmsg_cmsg_churn\":{\"runs\":%lu,\"socket_failed\":%lu,\"sendmsg_ok\":%lu,\"sendmsg_fail\":%lu,"
			"\"user_call_id\":%lu,\"abort\":%lu,\"accept\":%lu,\"exclusive_call\":%lu,"
			"\"upgrade_service\":%lu,\"tx_length\":%lu,\"set_call_timeout\":%lu,\"charge_accept\":%lu},"
		"\"tty_ldisc_churn\":{\"runs\":%lu,\"setup_failed\":%lu,\"ldisc_set_ok\":%lu,\"ldisc_set_failed\":%lu,"
			"\"write_ok\":%lu,\"read_ok\":%lu,"
			"\"per_disc\":[%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu]}"
		"}",
		shm->stats.ipvs_sysctl_writer_runs,
		shm->stats.ipvs_sysctl_writer_writes_ok,
		shm->stats.ipvs_sysctl_writer_writes_failed,
		shm->stats.ipvs_sysctl_writer_unsupported_latched,
		shm->stats.ipvs_sysctl_writer_burn_iters,
		shm->stats.ipfrag_source_runs,
		shm->stats.ipfrag_packets_sent_ok,
		shm->stats.ipfrag_send_failed,
		shm->stats.ipfrag_unique_srcs,
		shm->stats.obscure_af_churn_runs,
		shm->stats.obscure_af_churn_no_viable_pf,
		shm->stats.obscure_af_churn_pattern_runs[0],
		shm->stats.obscure_af_churn_pattern_kernel_rejected[0],
		shm->stats.obscure_af_churn_pattern_unexpected_success[0],
		shm->stats.obscure_af_churn_pattern_runs[1],
		shm->stats.obscure_af_churn_pattern_kernel_rejected[1],
		shm->stats.obscure_af_churn_pattern_unexpected_success[1],
		shm->stats.obscure_af_churn_pattern_runs[2],
		shm->stats.obscure_af_churn_pattern_kernel_rejected[2],
		shm->stats.obscure_af_churn_pattern_unexpected_success[2],
		shm->stats.obscure_af_churn_pattern_runs[3],
		shm->stats.obscure_af_churn_pattern_kernel_rejected[3],
		shm->stats.obscure_af_churn_pattern_unexpected_success[3],
		shm->stats.obscure_af_churn_pattern_runs[4],
		shm->stats.obscure_af_churn_pattern_kernel_rejected[4],
		shm->stats.obscure_af_churn_pattern_unexpected_success[4],
		shm->stats.obscure_af_churn_pattern_runs[5],
		shm->stats.obscure_af_churn_pattern_kernel_rejected[5],
		shm->stats.obscure_af_churn_pattern_unexpected_success[5],
		shm->stats.rxrpc_sendmsg_cmsg_runs,
		shm->stats.rxrpc_sendmsg_cmsg_socket_failed,
		shm->stats.rxrpc_sendmsg_cmsg_sendmsg_ok,
		shm->stats.rxrpc_sendmsg_cmsg_sendmsg_fail,
		shm->stats.rxrpc_sendmsg_cmsg_sent[0],
		shm->stats.rxrpc_sendmsg_cmsg_sent[1],
		shm->stats.rxrpc_sendmsg_cmsg_sent[2],
		shm->stats.rxrpc_sendmsg_cmsg_sent[3],
		shm->stats.rxrpc_sendmsg_cmsg_sent[4],
		shm->stats.rxrpc_sendmsg_cmsg_sent[5],
		shm->stats.rxrpc_sendmsg_cmsg_sent[6],
		shm->stats.rxrpc_sendmsg_cmsg_sent[7],
		shm->stats.tty_ldisc_churn_runs,
		shm->stats.tty_ldisc_churn_setup_failed,
		shm->stats.tty_ldisc_churn_ldisc_set_ok,
		shm->stats.tty_ldisc_churn_ldisc_set_failed,
		shm->stats.tty_ldisc_churn_write_ok,
		shm->stats.tty_ldisc_churn_read_ok,
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[0],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[1],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[2],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[3],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[4],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[5],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[6],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[7],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[8],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[9],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[10],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[11],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[12],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[13],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[14],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[15],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[16],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[17],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[18],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[19],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[20],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[21],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[22],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[23],
		shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[24]);
}

static void __cold dump_stats_json(void)
{
	putchar('{');

	json_emit_syscalls_array();

	fputs(",\"stats\":{", stdout);
	dump_stats_json_fault_and_fd_lifecycle();
	dump_stats_json_oracle();
	dump_stats_json_basic_subsystems();
	dump_stats_json_iouring_and_zombies();
	dump_stats_json_corruption_and_audit();
	dump_stats_json_lifecycle_and_storms();
	stat_category_emit_json(&socket_family_grammar_category);
	printf(",");
	dump_stats_json_socket_family_and_tls();
	dump_stats_json_netfilter_and_xfrm();

	printf(",");
	stat_category_emit_json(&nf_conntrack_helper_churn_category);

	printf(",");
	stat_category_emit_json(&tcp_ulp_swap_churn_category);

	printf(",");
	stat_category_emit_json(&msg_zerocopy_churn_category);

	printf(",");
	stat_category_emit_json(&setsockopt_pairing_category);

	printf(",");
	stat_category_emit_json(&sched_cycler_category);

	printf(",");
	stat_category_emit_json(&userns_fuzzer_category);

	printf(",");
	stat_category_emit_json(&userns_bootstrap_category);

	printf(",");
	stat_category_emit_json(&barrier_racer_category);

	printf(",");
	stat_category_emit_json(&perf_event_chains_category);

	printf(",");
	stat_category_emit_json(&bpf_lifecycle_category);

	printf(",");
	stat_category_emit_json(&signal_storm_category);

	printf(",");
	stat_category_emit_json(&pipe_thrash_category);

	printf(",");
	stat_category_emit_json(&fork_storm_category);

	printf(",");
	stat_category_emit_json(&cpu_hotplug_rider_category);

	printf(",");
	stat_category_emit_json(&pidfd_storm_category);

	printf(",");
	stat_category_emit_json(&madvise_cycler_category);

	printf(",");
	stat_category_emit_json(&keyring_spam_category);

	printf(",");
	stat_category_emit_json(&vdso_mremap_race_category);

	printf(",");
	stat_category_emit_json(&flock_thrash_category);

	printf(",");
	stat_category_emit_json(&xattr_thrash_category);

	printf(",");
	stat_category_emit_json(&epoll_volatility_category);

	printf(",");
	stat_category_emit_json(&cgroup_churn_category);

	printf(",");
	stat_category_emit_json(&mount_churn_category);

	printf(",");
	stat_category_emit_json(&umount_race_category);

	printf(",");
	stat_category_emit_json(&statmount_idmap_category);

	printf(",");
	stat_category_emit_json(&uffd_churn_category);

	printf(",");
	stat_category_emit_json(&tls_rotate_category);

	printf(",");
	stat_category_emit_json(&netns_teardown_category);

	printf(",");
	stat_category_emit_json(&socket_family_chain_category);

	printf(",");
	stat_category_emit_json(&tcp_ao_rotate_category);

	printf(",");
	stat_category_emit_json(&tcp_md5_listener_race_category);

	printf(",");
	stat_category_emit_json(&ipv6_pmtu_race_category);

	printf(",");
	stat_category_emit_json(&vrf_fib_churn_category);

	printf(",");
	stat_category_emit_json(&mpls_route_churn_category);

	printf(",");
	stat_category_emit_json(&tls_ulp_churn_category);

	printf(",");
	stat_category_emit_json(&ip6gre_bond_lapb_stack_category);

	printf(",");
	stat_category_emit_json(&vxlan_encap_churn_category);

	printf(",");
	stat_category_emit_json(&ovs_tunnel_vport_churn_category);

	printf(",");
	stat_category_emit_json(&netlink_monitor_race_category);

	printf(",");
	stat_category_emit_json(&tipc_link_churn_category);

	printf(",");
	stat_category_emit_json(&igmp_mld_source_churn_category);

	printf(",");
	stat_category_emit_json(&bridge_vlan_churn_category);

	printf(",");
	stat_category_emit_json(&pci_bind_category);

	printf(",");
	stat_category_emit_json(&ublk_lifecycle_category);

	printf(",");
	stat_category_emit_json(&handshake_req_abort_category);

	printf(",");
	stat_category_emit_json(&af_unix_scm_rights_gc_category);

	printf(",");
	stat_category_emit_json(&af_unix_peek_race_category);

	printf(",");
	stat_category_emit_json(&sysv_shm_orphan_race_category);

	printf(",");
	stat_category_emit_json(&qrtr_bind_race_category);

	printf(",");
	stat_category_emit_json(&pfkey_spd_walk_category);

	printf(",");
	stat_category_emit_json(&l2tp_ifname_race_category);

	printf(",");
	stat_category_emit_json(&bpf_cgroup_attach_category);

	printf(",");
	stat_category_emit_json(&iouring_flood_category);

	printf(",");
	stat_category_emit_json(&close_racer_category);

	printf(",");
	stat_category_emit_json(&refcount_audit_category);

	printf(",");
	stat_category_emit_json(&iouring_send_zc_churn_category);

	printf(",");
	stat_category_emit_json(&iscsi_target_probe_category);

	printf(",");
	stat_category_emit_json(&iscsi_login_walker_category);

	printf(",");
	stat_category_emit_json(&ipv6_ndisc_proxy_category);

	printf(",");
	stat_category_emit_json(&rxrpc_key_install_category);

	printf(",");
	stat_category_emit_json(&af_alg_weak_cipher_probe_category);

	printf(",");
	stat_category_emit_json(&bridge_conntrack_churn_category);

	printf(",");
	stat_category_emit_json(&blkdev_lifecycle_race_category);

	printf(",");
	stat_category_emit_json(&veth_asymmetric_xdp_category);

	printf(",");
	stat_category_emit_json(&ip6erspan_netns_migrate_category);

	printf(",");
	stat_category_emit_json(&flowtable_encap_vlan_category);

	printf(",");
	stat_category_emit_json(&splice_protocols_category);

	printf(",");
	stat_category_emit_json(&wireguard_decrypt_flood_category);

	printf(",");
	stat_category_emit_json(&rtnl_vf_broadcast_getlink_category);

	dump_stats_json_iouring_zc_and_kvm();
	dump_stats_json_rxrpc_alg_ublk_block();
	dump_stats_json_probes_misuse_and_tail();

	/*
	 * Per-childop arrays in struct stats_s indexed by NR_CHILD_OP_TYPES
	 * (taint_transitions[], pool_race_aborted[],
	 * childop_edges_discovered[], childop_calls_with_edges[]) are
	 * intentionally not emitted here.
	 * The JSON schema in this function is a flat per-key mapping;
	 * expanding any of these arrays as a nested object or array would
	 * change the schema shape and inflate the JSON for consumers that
	 * only care about scalar counters.  These arrays remain visible in
	 * the human-readable dump_stats() output, which iterates them as
	 * one row per non-zero entry under the matching group name.
	 */

	json_emit_kcov_section();
	json_emit_minicorpus_section();
	json_emit_cmp_hints_section();

	fputs("}\n", stdout);
	fflush(stdout);
}

/*
 * Walk the per-syscall range_overlaps_shared() reject buckets and emit the
 * top 10 worst offenders.  Names the syscalls whose arg generators are most
 * often producing pointers into trinity's own shared regions, so they can
 * be retrofitted with avoid_shared_buffer() (or similar) sanitisation.
 */
#define ROS_TOPN 10

static void dump_range_overlaps_shared_top_offenders(void)
{
	struct {
		unsigned int nr;
		bool do32bit;
		unsigned long count;
	} top[ROS_TOPN];
	unsigned int top_count = 0;
	unsigned int i, j;

	memset(top, 0, sizeof(top));

	for (i = 0; i < MAX_NR_SYSCALL; i++) {
		unsigned long c64 = parent_stats.range_overlaps_shared_rejects_per_syscall_64[i];
		unsigned long c32 = parent_stats.range_overlaps_shared_rejects_per_syscall_32[i];
		unsigned int pass;
		unsigned long c;
		bool is32;

		for (pass = 0; pass < 2; pass++) {
			c = pass ? c32 : c64;
			is32 = pass ? true : false;

			if (c == 0)
				continue;

			for (j = top_count; j > 0 && c > top[j - 1].count; j--) {
				if (j < ROS_TOPN)
					top[j] = top[j - 1];
			}
			if (j < ROS_TOPN) {
				top[j].nr = i;
				top[j].do32bit = is32;
				top[j].count = c;
				if (top_count < ROS_TOPN)
					top_count++;
			}
		}
	}

	if (top_count == 0)
		return;

	output(0, "Top range_overlaps_shared() offenders by syscall:\n");
	for (j = 0; j < top_count; j++) {
		const char *sname = print_syscall_name(top[j].nr, top[j].do32bit);

		output(0, "  %-24s %s %lu\n",
			sname, top[j].do32bit ? "(32)" : "(64)", top[j].count);
	}
}

/*
 * Spike detector for parent_stats.post_handler_corrupt_ptr.  Called once
 * per main_loop tick from the parent.  Emits a single-line WARNING when
 * the counter advances by at least CORRUPT_PTR_SPIKE_THRESHOLD over a
 * CORRUPT_PTR_SPIKE_WINDOW_SEC window.
 *
 * The counter ticks whenever a post-handler caught a pid-shaped or
 * canonical-out-of-range pointer in rec->aN -- i.e. the snapshot
 * pattern intercepted a wild write.  A slow trickle is normal noise; a
 * sudden burst is the signal that scribbles are landing in rec-> memory
 * often enough to matter.  Per-window throttling keeps the log quiet
 * during a steady drip and re-arms after each report so a sustained
 * spike emits one line per minute, not a flood.
 *
 * Scoped to genuine .post-handler pointer rejections only.  The
 * dispatcher-level RZS rettype-contract check has its own counter
 * (rzs_blanket_reject) and does not feed this detector; previously the
 * two signals shared post_handler_corrupt_ptr and the RZS background
 * (~2/s steady-state across the fleet) drowned the burst-detection
 * window in ~85-90% noise.
 */
#define CORRUPT_PTR_SPIKE_THRESHOLD	100UL
#define CORRUPT_PTR_SPIKE_WINDOW_SEC	60

void corrupt_ptr_spike_check(void)
{
	static unsigned long window_baseline;
	static struct timespec window_start;
	struct timespec now;
	unsigned long current, delta;

	clock_gettime(CLOCK_MONOTONIC, &now);

	/* First call: arm the window from the live counter so any
	 * pre-existing count carried over from earlier in the run is
	 * not mis-attributed to this window.  Reads from parent_stats
	 * since the counter now lives in the parent aggregate (no
	 * atomic needed -- parent is the sole writer via the ring
	 * drain and the sole reader here). */
	if (window_start.tv_sec == 0) {
		window_start = now;
		window_baseline = parent_stats.post_handler_corrupt_ptr;
		return;
	}

	if ((now.tv_sec - window_start.tv_sec) < CORRUPT_PTR_SPIKE_WINDOW_SEC)
		return;

	current = parent_stats.post_handler_corrupt_ptr;
	delta = current - window_baseline;

	if (delta >= CORRUPT_PTR_SPIKE_THRESHOLD)
		output(0, "WARNING: post_handler_corrupt_ptr spiked +%lu in %us (total %lu) -- snapshot guards are catching scribbles\n",
		       delta, CORRUPT_PTR_SPIKE_WINDOW_SEC, current);

	window_start = now;
	window_baseline = current;
}

/*
 * Periodic surface of the defense-counter family that dump_stats() only
 * emits at end-of-run.  Called once per main_loop tick from the parent;
 * every DEFENSE_DUMP_INTERVAL_SEC the diff between the current counter
 * value and the value cached at the prior dump is divided by the elapsed
 * window and emitted as a per-second rate, so an operator watching a
 * long fuzz run can see which guards are catching real wild writes vs
 * sitting at noise without waiting for the run to end.  Counters with a
 * zero delta are skipped so the per-window line stays short on a quiet
 * fleet; the whole block is suppressed entirely on a window where every
 * counter held flat.  Listed once in defense_counters[] so adding a new
 * defense counter only needs one edit to get periodic visibility.
 */
#define DEFENSE_DUMP_INTERVAL_SEC	600

static const struct {
	const char *name;
	size_t off;
	bool    from_aggregate;	/* true: read from parent_stats; false: shm->stats */
} defense_counters[] = {
	{ "shared_buffer_redirected",
	  offsetof(struct stats_aggregate, shared_buffer_redirected), true },
	{ "range_overlaps_shared_rejects",
	  offsetof(struct stats_aggregate, range_overlaps_shared_rejects), true },
	{ "libc_heap_redirected",
	  offsetof(struct stats_aggregate, libc_heap_redirected), true },
	{ "libc_heap_embedded_redirected",
	  offsetof(struct stats_aggregate, libc_heap_embedded_redirected), true },
	{ "asb_relocate_readable_skip",
	  offsetof(struct stats_aggregate, asb_relocate_readable_skip), true },
	{ "asb_relocate_copy_fault",
	  offsetof(struct stats_aggregate, asb_relocate_copy_fault), true },
	{ "heap_pointer_outside_cache",
	  offsetof(struct stats_aggregate, heap_pointer_outside_cache), true },
	{ "heap_brk_stale_window_hit",
	  offsetof(struct stats_aggregate, heap_brk_stale_window_hit), true },
	{ "get_writable_address_scribbled_shm_range",
	  offsetof(struct stats_aggregate, get_writable_address_scribbled_shm_range), true },
	{ "get_writable_address_scribbled_mprotect_mmap",
	  offsetof(struct stats_aggregate, get_writable_address_scribbled_mprotect_mmap), true },
	{ "get_writable_address_scribbled_mprotect_shm",
	  offsetof(struct stats_aggregate, get_writable_address_scribbled_mprotect_shm), true },
	{ "get_writable_address_scribbled_postmp_mmap",
	  offsetof(struct stats_aggregate, get_writable_address_scribbled_postmp_mmap), true },
	{ "get_writable_address_scribbled_postmp_shm",
	  offsetof(struct stats_aggregate, get_writable_address_scribbled_postmp_shm), true },
	{ "get_writable_address_bookkeeping_ro_fault",
	  offsetof(struct stats_aggregate, get_writable_address_bookkeeping_ro_fault), true },
	{ "mm_gate_post_slip",
	  offsetof(struct stats_aggregate, mm_gate_post_slip), true },
	{ "post_handler_corrupt_ptr",
	  offsetof(struct stats_aggregate, post_handler_corrupt_ptr), true },
	{ "deferred_free_reject",
	  offsetof(struct stats_aggregate, deferred_free_reject), true },
	{ "deferred_free_reject_pathname",
	  offsetof(struct stats_aggregate, deferred_free_reject_pathname), true },
	{ "deferred_free_reject_iovec",
	  offsetof(struct stats_aggregate, deferred_free_reject_iovec), true },
	{ "deferred_free_reject_sockaddr",
	  offsetof(struct stats_aggregate, deferred_free_reject_sockaddr), true },
	{ "deferred_free_reject_other",
	  offsetof(struct stats_aggregate, deferred_free_reject_other), true },
	{ "snapshot_non_heap_reject",
	  offsetof(struct stats_aggregate, snapshot_non_heap_reject), true },
	{ "deferred_free_corrupt_ptr",
	  offsetof(struct stats_aggregate, deferred_free_corrupt_ptr), true },
	{ "arg_shadow_stomp",
	  offsetof(struct stats_aggregate, arg_shadow_stomp), true },
	{ "lock_word_scribbled",
	  offsetof(struct stats_aggregate, lock_word_scribbled), true },
	{ "lock_held_scribble",
	  offsetof(struct stats_s, lock_held_scribble) },
	{ "rec_canary_stomped",
	  offsetof(struct stats_s, rec_canary_stomped) },
	{ "rzs_blanket_reject",
	  offsetof(struct stats_s, rzs_blanket_reject) },
	{ "retfd_blanket_reject",
	  offsetof(struct stats_s, retfd_blanket_reject) },
	{ "arena_ptr_stale_caught_arg",
	  offsetof(struct stats_s, arena_ptr_stale_caught_arg) },
	{ "arena_ptr_stale_caught_post_state",
	  offsetof(struct stats_s, arena_ptr_stale_caught_post_state) },
	{ "execve_self_exec_blocked",
	  offsetof(struct stats_s, execve_self_exec_blocked) },
	{ "corpus_count_overcap_caught",
	  offsetof(struct stats_s, corpus_count_overcap_caught) },
	{ "sibling_mprotect_failed",
	  offsetof(struct stats_s, sibling_mprotect_failed) },
	{ "sibling_refreeze_count",
	  offsetof(struct stats_s, sibling_refreeze_count) },
	/* divergence-sentinel anomaly counter, sharded by enum
	 * sentinel_field.  One row per active field id so the periodic
	 * rate dump shows which monitored field is drifting rather than
	 * a lumped headline number.  Gaps in the enum (5..9) are simply
	 * not listed here — their array slots stay zero.
	 */
	{ "divergence_sentinel_anomalies_sysname",
	  offsetof(struct stats_s, divergence_sentinel_anomalies[SF_UNAME_SYSNAME]) },
	{ "divergence_sentinel_anomalies_release",
	  offsetof(struct stats_s, divergence_sentinel_anomalies[SF_UNAME_RELEASE]) },
	{ "divergence_sentinel_anomalies_version",
	  offsetof(struct stats_s, divergence_sentinel_anomalies[SF_UNAME_VERSION]) },
	{ "divergence_sentinel_anomalies_machine",
	  offsetof(struct stats_s, divergence_sentinel_anomalies[SF_UNAME_MACHINE]) },
	{ "divergence_sentinel_anomalies_totalram",
	  offsetof(struct stats_s, divergence_sentinel_anomalies[SF_SYSINFO_TOTALRAM]) },
	{ "divergence_sentinel_anomalies_totalswap",
	  offsetof(struct stats_s, divergence_sentinel_anomalies[SF_SYSINFO_TOTALSWAP]) },
	{ "divergence_sentinel_anomalies_totalhigh",
	  offsetof(struct stats_s, divergence_sentinel_anomalies[SF_SYSINFO_TOTALHIGH]) },
	{ "divergence_sentinel_anomalies_mem_unit",
	  offsetof(struct stats_s, divergence_sentinel_anomalies[SF_SYSINFO_MEM_UNIT]) },
	/* SF_UNAME_RELEASE / SF_UNAME_MACHINE bumps land here instead of
	 * on the per-field anomaly shards above — personality()-driven
	 * legitimate drift, kept separate so the corruption histogram
	 * stays a real signal. */
	{ "divergence_sentinel_expected_drift",
	  offsetof(struct stats_s, divergence_sentinel_expected_drift) },
	{ "iouring_enter_mask_corrupt",
	  offsetof(struct stats_s, iouring_enter_mask_corrupt) },
	{ "watchdog_sigalrm_clobbered",
	  offsetof(struct stats_s, watchdog_sigalrm_clobbered) },
	{ "watchdog_sigxcpu_clobbered",
	  offsetof(struct stats_s, watchdog_sigxcpu_clobbered) },
	{ "fd_event_ring_corrupted",
	  offsetof(struct stats_s, fd_event_ring_corrupted) },
	{ "fd_event_ring_overwritten",
	  offsetof(struct stats_s, fd_event_ring_overwritten) },
	{ "stats_ring_corrupted",
	  offsetof(struct stats_s, stats_ring_corrupted) },
	{ "stats_ring_overwritten",
	  offsetof(struct stats_s, stats_ring_overwritten) },
	{ "fd_event_payload_corrupt",
	  offsetof(struct stats_s, fd_event_payload_corrupt) },
	{ "destroy_object_idx_corrupt",
	  offsetof(struct stats_s, destroy_object_idx_corrupt) },
	{ "global_obj_uaf_caught",
	  offsetof(struct stats_s, global_obj_uaf_caught) },
	{ "maps_pool_draw_exhausted",
	  offsetof(struct stats_s, maps_pool_draw_exhausted) },
	{ "maps_reject_pool_empty",
	  offsetof(struct stats_s, maps_reject_pool_empty) },
	{ "maps_reject_bogus_obj_ptr",
	  offsetof(struct stats_s, maps_reject_bogus_obj_ptr) },
	{ "maps_reject_alloc_track_miss",
	  offsetof(struct stats_s, maps_reject_alloc_track_miss) },
	{ "maps_reject_alloc_track_miss_anon",
	  offsetof(struct stats_s, maps_reject_alloc_track_miss_anon) },
	{ "maps_reject_alloc_track_miss_file",
	  offsetof(struct stats_s, maps_reject_alloc_track_miss_file) },
	{ "maps_reject_alloc_track_miss_testfile",
	  offsetof(struct stats_s, maps_reject_alloc_track_miss_testfile) },
	{ "maps_reject_size_zero",
	  offsetof(struct stats_s, maps_reject_size_zero) },
	{ "maps_reject_size_too_large",
	  offsetof(struct stats_s, maps_reject_size_too_large) },
	/* Map selection / pick-cost rows.  Per-second
	 * rates here let the periodic dump answer "is the
	 * 1000-iter retry budget actually contended" and "which
	 * pool / prot-mask is paying the rejection cost", the
	 * questions the side-index TIER-2/3 rows are gated on. */
	{ "maps_pool_chosen_anon",
	  offsetof(struct stats_s, maps_pool_chosen_anon) },
	{ "maps_pool_chosen_file",
	  offsetof(struct stats_s, maps_pool_chosen_file) },
	{ "maps_pool_chosen_testfile",
	  offsetof(struct stats_s, maps_pool_chosen_testfile) },
	{ "maps_reject_pool_empty_anon",
	  offsetof(struct stats_s, maps_reject_pool_empty_anon) },
	{ "maps_reject_pool_empty_file",
	  offsetof(struct stats_s, maps_reject_pool_empty_file) },
	{ "maps_reject_pool_empty_testfile",
	  offsetof(struct stats_s, maps_reject_pool_empty_testfile) },
	{ "maps_prot_reject_mask_0",
	  offsetof(struct stats_s, maps_prot_reject_by_mask[0]) },
	{ "maps_prot_reject_mask_R",
	  offsetof(struct stats_s, maps_prot_reject_by_mask[1]) },
	{ "maps_prot_reject_mask_W",
	  offsetof(struct stats_s, maps_prot_reject_by_mask[2]) },
	{ "maps_prot_reject_mask_RW",
	  offsetof(struct stats_s, maps_prot_reject_by_mask[3]) },
	{ "maps_prot_reject_mask_X",
	  offsetof(struct stats_s, maps_prot_reject_by_mask[4]) },
	{ "maps_prot_reject_mask_RX",
	  offsetof(struct stats_s, maps_prot_reject_by_mask[5]) },
	{ "maps_prot_reject_mask_WX",
	  offsetof(struct stats_s, maps_prot_reject_by_mask[6]) },
	{ "maps_prot_reject_mask_RWX",
	  offsetof(struct stats_s, maps_prot_reject_by_mask[7]) },
	{ "maps_pick_attempts_sum",
	  offsetof(struct stats_s, maps_pick_attempts_sum) },
	{ "maps_pick_successes",
	  offsetof(struct stats_s, maps_pick_successes) },
	{ "maps_pick_with_prot_attempts_sum",
	  offsetof(struct stats_s, maps_pick_with_prot_attempts_sum) },
	{ "maps_pick_with_prot_successes",
	  offsetof(struct stats_s, maps_pick_with_prot_successes) },
	{ "maps_type_resolution_calls",
	  offsetof(struct stats_s, maps_type_resolution_calls) },
	{ "maps_type_resolution_scan_length_sum",
	  offsetof(struct stats_s, maps_type_resolution_scan_length_sum) },
	{ "maps_type_resolution_hits",
	  offsetof(struct stats_s, maps_type_resolution_hits) },
	/* FD bookkeeping rows.  fd_live_remove
	 * histogram surfaces whether the linear scan
	 * an fd live-list index would replace is actually expensive;
	 * fd_event_full_* says which producer drove a ring
	 * overflow; close_range_* surfaces the compression ratio
	 * the range opcode buys vs the per-fd path. */
	{ "fd_live_remove_calls",
	  offsetof(struct stats_s, fd_live_remove_calls) },
	{ "fd_live_remove_miss",
	  offsetof(struct stats_s, fd_live_remove_miss) },
	{ "fd_live_remove_scan_hist_0",
	  offsetof(struct stats_s, fd_live_remove_scan_histogram[0]) },
	{ "fd_live_remove_scan_hist_1",
	  offsetof(struct stats_s, fd_live_remove_scan_histogram[1]) },
	{ "fd_live_remove_scan_hist_2_3",
	  offsetof(struct stats_s, fd_live_remove_scan_histogram[2]) },
	{ "fd_live_remove_scan_hist_4_7",
	  offsetof(struct stats_s, fd_live_remove_scan_histogram[3]) },
	{ "fd_live_remove_scan_hist_8_15",
	  offsetof(struct stats_s, fd_live_remove_scan_histogram[4]) },
	{ "fd_live_remove_scan_hist_16_31",
	  offsetof(struct stats_s, fd_live_remove_scan_histogram[5]) },
	{ "fd_live_remove_scan_hist_32_63",
	  offsetof(struct stats_s, fd_live_remove_scan_histogram[6]) },
	{ "fd_live_remove_scan_hist_ge64",
	  offsetof(struct stats_s, fd_live_remove_scan_histogram[7]) },
	{ "fd_event_full_close",
	  offsetof(struct stats_s, fd_event_full_close) },
	{ "fd_event_full_evict",
	  offsetof(struct stats_s, fd_event_full_evict) },
	{ "fd_event_full_close_range",
	  offsetof(struct stats_s, fd_event_full_close_range) },
	{ "fd_event_close_range_enqueued",
	  offsetof(struct stats_s, fd_event_close_range_enqueued) },
	{ "fd_event_close_range_length_sum",
	  offsetof(struct stats_s, fd_event_close_range_length_sum) },
	/* Chain-corpus duplicate-shape rate.  Dup
	 * vs unique count over the K=8 most-recent slots; rate
	 * dup/(dup+unique) gates a per-shape chain quota. */
	{ "chain_corpus_save_dup_shape",
	  offsetof(struct stats_s, chain_corpus_save_dup_shape) },
	{ "chain_corpus_save_unique_shape",
	  offsetof(struct stats_s, chain_corpus_save_unique_shape) },
	{ "deferred_free_reject_misaligned",
	  offsetof(struct stats_s, deferred_free_reject_misaligned) },
	{ "deferred_free_reject_corrupt_shape",
	  offsetof(struct stats_s, deferred_free_reject_corrupt_shape) },
	{ "deferred_free_reject_non_heap",
	  offsetof(struct stats_s, deferred_free_reject_non_heap) },
	{ "deferred_free_reject_untracked",
	  offsetof(struct stats_s, deferred_free_reject_untracked) },
	{ "nested_scrub_reject_untracked",
	  offsetof(struct stats_s, nested_scrub_reject_untracked) },
	{ "deferred_free_reject_shared_region",
	  offsetof(struct stats_s, deferred_free_reject_shared_region) },
	{ "deferred_free_outstanding_vmas",
	  offsetof(struct stats_s, deferred_free_outstanding_vmas) },
	{ "deferred_free_vma_fallback_immediate",
	  offsetof(struct stats_s, deferred_free_vma_fallback_immediate) },
	{ "deferred_free_enomem_drain",
	  offsetof(struct stats_s, deferred_free_enomem_drain) },
	{ "deferred_free_rw_restore_enomem",
	  offsetof(struct stats_s, deferred_free_rw_restore_enomem) },
	{ "deferred_free_pre_dispatch_leaked",
	  offsetof(struct stats_s, deferred_free_pre_dispatch_leaked) },
	{ "ring_evict_leaked",
	  offsetof(struct stats_s, ring_evict_leaked) },
	{ "deferred_free_ring_owned_skip",
	  offsetof(struct stats_s, deferred_free_ring_owned_skip) },
	{ "deferred_free_double_admit_skip",
	  offsetof(struct stats_s, deferred_free_double_admit_skip) },
	{ "alloc_track_refresh_ring_owned_skip",
	  offsetof(struct stats_s, alloc_track_refresh_ring_owned_skip) },
	{ "alloc_track_refresh_unverified_skip",
	  offsetof(struct stats_s, alloc_track_refresh_unverified_skip) },
	{ "pagecache_canary_corrupt_caught",
	  offsetof(struct stats_s, pagecache_canary_corrupt_caught) },
	{ "objpool_array_stale_caught",
	  offsetof(struct stats_s, objpool_array_stale_caught) },
	/* genetlink registry per-family dispatch counters; rate-of-change
	 * surfaces the live family selection mix without waiting for the
	 * end-of-run summary.  A counter that stays at zero across an
	 * interval window with the others advancing flags either a missing
	 * registry entry or a family the controller never resolved. */
	{ "genl_family_calls_devlink",
	  offsetof(struct stats_s, genl_family_calls_devlink) },
	{ "genl_family_calls_nl80211",
	  offsetof(struct stats_s, genl_family_calls_nl80211) },
	{ "genl_family_calls_taskstats",
	  offsetof(struct stats_s, genl_family_calls_taskstats) },
	{ "genl_family_calls_ethtool",
	  offsetof(struct stats_s, genl_family_calls_ethtool) },
	{ "genl_family_calls_mptcp_pm",
	  offsetof(struct stats_s, genl_family_calls_mptcp_pm) },
	{ "genl_family_calls_tipc",
	  offsetof(struct stats_s, genl_family_calls_tipc) },
	{ "genl_family_calls_wireguard",
	  offsetof(struct stats_s, genl_family_calls_wireguard) },
	{ "genl_family_calls_l2tp",
	  offsetof(struct stats_s, genl_family_calls_l2tp) },
	{ "genl_family_calls_gtp",
	  offsetof(struct stats_s, genl_family_calls_gtp) },
	{ "genl_family_calls_macsec",
	  offsetof(struct stats_s, genl_family_calls_macsec) },
	{ "genl_family_calls_netlabel",
	  offsetof(struct stats_s, genl_family_calls_netlabel) },
	{ "genl_family_calls_team",
	  offsetof(struct stats_s, genl_family_calls_team) },
	{ "genl_family_calls_hsr",
	  offsetof(struct stats_s, genl_family_calls_hsr) },
	{ "genl_family_calls_fou",
	  offsetof(struct stats_s, genl_family_calls_fou) },
	{ "genl_family_calls_psample",
	  offsetof(struct stats_s, genl_family_calls_psample) },
	{ "genl_family_calls_ila",
	  offsetof(struct stats_s, genl_family_calls_ila) },
	{ "genl_family_calls_ioam6",
	  offsetof(struct stats_s, genl_family_calls_ioam6) },
	{ "genl_family_calls_seg6",
	  offsetof(struct stats_s, genl_family_calls_seg6) },
	{ "genl_family_calls_thermal",
	  offsetof(struct stats_s, genl_family_calls_thermal) },
	{ "genl_family_calls_ipvs",
	  offsetof(struct stats_s, genl_family_calls_ipvs) },
	/* nfnetlink registry per-subsys dispatch counters; same diagnostic
	 * value as the genl ones above but for NETLINK_NETFILTER subsystems.
	 * Lets an operator see the live ctnetlink/nftables/ipset traffic
	 * split at 10-minute granularity without waiting for run end. */
	{ "nfnl_subsys_calls_ctnetlink",
	  offsetof(struct stats_s, nfnl_subsys_calls_ctnetlink) },
	{ "nfnl_subsys_calls_ctnetlink_exp",
	  offsetof(struct stats_s, nfnl_subsys_calls_ctnetlink_exp) },
	{ "nfnl_subsys_calls_nftables",
	  offsetof(struct stats_s, nfnl_subsys_calls_nftables) },
	{ "nfnl_subsys_calls_ipset",
	  offsetof(struct stats_s, nfnl_subsys_calls_ipset) },
	/* UCB1 bandit CMP-novelty reward firings: bumped from
	 * maybe_rotate_strategy() each time the just-finished window had
	 * enough novel comparison constants to clear the integer reward
	 * weight.  Surfaces whether the CMP feedback is meaningfully
	 * contributing to arm selection. */
	{ "bandit_cmp_reward_added",
	  offsetof(struct stats_s, bandit_cmp_reward_added) },
	/* Picks accepted by STRATEGY_COVERAGE_FRONTIER's frontier-weighted
	 * roulette wheel.  Rate-of-change tracks the arm's actual share of
	 * the fleet's syscall throughput when the bandit picker selects it. */
	{ "frontier_strategy_picks",
	  offsetof(struct stats_s, frontier_strategy_picks) },
	/* Saturating-subtract clamps fired during frontier ring rotation --
	 * see comment on struct field.  Non-zero is a correctness flag, not
	 * tuning data. */
	{ "frontier_underflow_prevented",
	  offsetof(struct stats_s, frontier_underflow_prevented) },
	/* Plateau-intervention rotations that selected the frontier arm.
	 * Held side-channel so the learner-facing bandit_pulls[] stays
	 * clean; the snapshot path folds this back in for the plateau
	 * classifier's frontier_cold rule. */
	{ "frontier_intervention_pulls",
	  offsetof(struct stats_s, frontier_intervention_pulls) },
	/* Accept-regime split of frontier_strategy_picks.  Sum equals
	 * frontier_strategy_picks; the periodic ratio surfaces whether the
	 * picker is steering on the K-window ring (live) or has collapsed
	 * to the lifetime cold-weight fallback (silent). */
	{ "frontier_live_picks",
	  offsetof(struct stats_s, frontier_live_picks) },
	{ "frontier_silent_picks",
	  offsetof(struct stats_s, frontier_silent_picks) },
	/* SHADOW-ONLY decay accounting under the tightened no-novelty
	 * predicate (consecutive silent picks past threshold AND no CMP
	 * insert AND no SUCCESS-bucket errno shift since the streak's
	 * most recent reset).  Sibling of frontier_shadow_decay_candidates;
	 * see the struct-field comment in include/stats.h for the per-
	 * counter semantics. */
	{ "frontier_decay_candidates",
	  offsetof(struct stats_s, frontier_decay_candidates) },
	{ "frontier_decay_would_skip",
	  offsetof(struct stats_s, frontier_decay_would_skip) },
	{ "frontier_silent_decay_live_rejects",
	  offsetof(struct stats_s, frontier_silent_decay_live_rejects) },
	/* SHADOW-ONLY LIVE-regime cooldown projections, paired with
	 * frontier_live_miss_streak_per_syscall[].  Candidates is edge-
	 * triggered at FRONTIER_LIVE_MISS_COOLDOWN crossings; would_skip is
	 * cumulative across every LIVE-regime miss past the threshold.  See
	 * the struct-field comments in include/stats.h and the
	 * FRONTIER_LIVE_MISS_COOLDOWN comment in include/strategy.h for the
	 * predicate contract. */
	{ "frontier_live_cooldown_candidates",
	  offsetof(struct stats_s, frontier_live_cooldown_candidates) },
	{ "frontier_live_would_skip",
	  offsetof(struct stats_s, frontier_live_would_skip) },
	/* Did-decay counter for --frontier-live-cooldown.  Bumped per (nr,
	 * rotation) where the early ring-decay in frontier_window_advance
	 * actually halved a non-zero cached sum.  Zero on flag-off runs. */
	{ "frontier_live_cooldown_decays",
	  offsetof(struct stats_s, frontier_live_cooldown_decays) },
	/* Live reject count for the blanket LIVE-regime probabilistic
	 * pick-reject gate.  See the struct-field comment in
	 * include/stats.h and the FRONTIER_LIVE_DECAY_REJECT_DENOM comment
	 * in include/strategy.h for the probabilistic-reject contract. */
	{ "frontier_live_decay_live_rejects",
	  offsetof(struct stats_s, frontier_live_decay_live_rejects) },
	/* SHADOW-ONLY wall-lever accounting.  Eligible_total is
	 * the denominator (every plateau-active pick the lever saw); would_
	 * suppress_total is the projected reclaim count a live variant would
	 * produce.  See the struct-field comment in include/stats.h for the
	 * predicate contract. */
	{ "wall_lever_eligible_total",
	  offsetof(struct stats_s, wall_lever_eligible_total) },
	{ "wall_lever_would_suppress_total",
	  offsetof(struct stats_s, wall_lever_would_suppress_total) },
	/* SHADOW + per-child A/B accounting for the errno-plateau decay at
	 * the coverage-frontier picker's silent-regime accept site.  See the
	 * struct-field comments in include/stats.h and the FRONTIER_ERRNO_
	 * PLATEAU_* contract in include/strategy.h for the per-counter
	 * semantics and the would_skip vs live_rejects vs overlap_silent
	 * triple. */
	{ "frontier_errno_decay_would_skip",
	  offsetof(struct stats_s, frontier_errno_decay_would_skip) },
	{ "frontier_errno_decay_live_rejects",
	  offsetof(struct stats_s, frontier_errno_decay_live_rejects) },
	{ "frontier_errno_decay_overlap_silent",
	  offsetof(struct stats_s, frontier_errno_decay_overlap_silent) },
	/* SHADOW-ONLY A/B scoring for the frontier-blend cold-weight
	 * blend.  The picker still consumes the OLD weight; these counters
	 * expose how often the blended formula would have steered
	 * differently and by how much.  See the struct-field comment in
	 * include/stats.h for the per-counter semantics. */
	{ "frontier_blend_samples",
	  offsetof(struct stats_s, frontier_blend_samples) },
	{ "frontier_blend_new_lower",
	  offsetof(struct stats_s, frontier_blend_new_lower) },
	{ "frontier_blend_new_higher",
	  offsetof(struct stats_s, frontier_blend_new_higher) },
	{ "frontier_blend_new_equal",
	  offsetof(struct stats_s, frontier_blend_new_equal) },
	{ "frontier_blend_old_weight_sum",
	  offsetof(struct stats_s, frontier_blend_old_weight_sum) },
	{ "frontier_blend_new_weight_sum",
	  offsetof(struct stats_s, frontier_blend_new_weight_sum) },
	/* Adaptive remote-KCOV mode A/B disposition counters.  Bumped in
	 * lock-step from BOTH arms in remote_adaptive_decide(); the live
	 * remote_mode diverges only on Arm B.  See the struct-field
	 * comments in include/stats.h for per-counter semantics. */
	{ "remote_adaptive_samples",
	  offsetof(struct stats_s, remote_adaptive_samples) },
	{ "remote_adaptive_would_demote",
	  offsetof(struct stats_s, remote_adaptive_would_demote) },
	{ "remote_adaptive_would_promote",
	  offsetof(struct stats_s, remote_adaptive_would_promote) },
	{ "remote_adaptive_would_force",
	  offsetof(struct stats_s, remote_adaptive_would_force) },
	{ "remote_adaptive_agree",
	  offsetof(struct stats_s, remote_adaptive_agree) },
	/* Picks the explorer pool forced to STRATEGY_RANDOM.  Rate-of-change
	 * over the run divided by explorer_children gives the per-explorer
	 * picker throughput; deviation from the bandit-pool throughput
	 * highlights either picker overhead or per-strategy work skew. */
	{ "strategy_explorer_picks",
	  offsetof(struct stats_s, strategy_explorer_picks) },
	/* Per-pool new-edge counters: ratio
	 *   explorer_pool_edges_discovered / bandit_pool_edges_discovered
	 * compared against
	 *   explorer_children / (max_children - explorer_children)
	 * tells the operator whether the explorer pool is finding edges
	 * disproportionately to its fleet share -- the trigger condition
	 * for considering per-child bandit (Option C). */
	{ "explorer_pool_edges_discovered",
	  offsetof(struct stats_s, explorer_pool_edges_discovered) },
	{ "bandit_pool_edges_discovered",
	  offsetof(struct stats_s, bandit_pool_edges_discovered) },
	/* Epoll lazy-arm wins: rate-of-change tracks fresh epfds reaching
	 * children after the deferred-arm refactor.  A flat counter while
	 * children are issuing epoll_wait suggests the consumer wireup
	 * regressed. */
	{ "epoll_lazy_armed",
	  offsetof(struct stats_s, epoll_lazy_armed) },
	/* Watch-set populations refused because the candidate fd belonged
	 * to a poll_can_block-tagged fd_provider (FUSE / userfaultfd / KVM
	 * vCPU / io_uring / pidfd).  Sustained growth confirms the filter
	 * is intercepting the fds that would otherwise wedge children in
	 * ep_item_poll → fops->poll on the per-fd waitqueue. */
	{ "epoll_blocking_poll_skipped",
	  offsetof(struct stats_s, epoll_blocking_poll_skipped) },
	/* Per-vCPU ioctl dispatches into kvm_vcpu_grp.  Rate-of-change at the
	 * 10-minute window granularity confirms the OBJ_FD_KVM_VCPU fd_test
	 * path is keeping up with vCPU pool churn -- a flat counter while the
	 * vcpu pool is non-empty would mean the new ioctl group isn't winning
	 * find_ioctl_group() arbitration, or the sanitiser is being bypassed
	 * by a fd that doesn't satisfy kvm_vcpu_fd_test. */
	{ "kvm_vcpu_ioctls_dispatched",
	  offsetof(struct stats_s, kvm_vcpu_ioctls_dispatched) },
	/* nl80211_churn invocation rate.  Periodic visibility lets an operator
	 * confirm the cfg80211 state-machine fuzzer is making progress under the
	 * mac80211_hwsim radio without waiting for the end-of-run summary; a
	 * flat counter while other network childops advance is the signal that
	 * the hwsim probe latched ns_unsupported_nl80211 and the op went
	 * noop_forever for the rest of the run. */
	{ "nl80211_runs",
	  offsetof(struct stats_s, nl80211_runs) },
	/* SHADOW-ONLY cumulative count of "deep but warm" calls -- no PC-edge
	 * novelty and no CMP-bloom novelty, yet either a per-call PC walk
	 * meaningfully deeper than the syscall's lifetime mean or a trace
	 * that approached the KCOV_TRACE_SIZE buffer cap.  Periodic stats
	 * dump only; the per-syscall warm_reserve_candidates[] breakdown
	 * surfaces via top_syscalls_periodic_dump()'s warm-reserve row. */
	{ "warm_reserve_candidates_total",
	  offsetof(struct stats_s, warm_reserve_candidates_total) },
};

static unsigned long defense_counter_load(unsigned int i)
{
	const char *base = defense_counters[i].from_aggregate
			   ? (const char *)&parent_stats
			   : (const char *)&shm->stats;
	unsigned long *p = (unsigned long *)(base + defense_counters[i].off);

	return __atomic_load_n(p, __ATOMIC_RELAXED);
}

/*
 * Render the per-handler attribution ring for post_handler_corrupt_ptr.
 * Snapshots the ring under the same lock the recorder uses so a
 * concurrent insertion cannot reorder entries underneath the sort.  The
 * snapshot is then sorted descending by count and emitted; suppressed
 * entirely when the ring is empty so quiet windows stay terse.
 */
static int corrupt_ptr_attr_cmp(const void *a, const void *b)
{
	const struct corrupt_ptr_attr_entry *ea = a;
	const struct corrupt_ptr_attr_entry *eb = b;

	if (eb->count > ea->count)
		return 1;
	if (eb->count < ea->count)
		return -1;
	return 0;
}

/*
 * Comparator for the per-callsite sub-attribution ring.  Same
 * descending-by-count order as the per-handler ring so the dump leads
 * with the loudest call site within each handler row.
 */
static int corrupt_ptr_pc_cmp(const void *a, const void *b)
{
	const struct corrupt_ptr_pc_entry *ea = a;
	const struct corrupt_ptr_pc_entry *eb = b;

	if (eb->count > ea->count)
		return 1;
	if (eb->count < ea->count)
		return -1;
	return 0;
}

/*
 * Render PC sub-attribution entries that match (nr, do32bit) as
 * indented sub-rows beneath the matching per-handler row.  Caller
 * passes a snapshot already sorted descending by count so all rows
 * share one snap+sort across the dump pass; @n_entries is the number
 * of populated slots in @snap (everything from index @n_entries onward
 * is guaranteed zero-count and skipped).  Silent when no entry matches
 * -- pre-sub-attribution runs and quiet handlers stay terse.
 *
 * Each row is annotated with a best-effort "file.c:NNN" from addr2line
 * because pc_to_string() alone renders a PIE-relative offset that gets
 * resolved by addr2line / external tooling DOWN to the nearest
 * preceding global symbol -- a captured PC living inside an
 * LTO-inlined static helper body therefore appears under whichever
 * unrelated non-static symbol happens to precede it in the binary.
 * Source coordinates disambiguate; falls back to the bare offset when
 * addr2line is unavailable or the address can't be resolved.
 */
static void corrupt_ptr_pc_dump_for(const struct corrupt_ptr_pc_entry *snap,
				    unsigned int n_entries,
				    unsigned int nr, bool do32bit)
{
	unsigned int i;

	for (i = 0; i < n_entries; i++) {
		char pcbuf[128];
		char srcbuf[256];
		const char *src;

		if (snap[i].count == 0)
			break;
		if (snap[i].nr != nr || snap[i].do32bit != do32bit)
			continue;
		/*
		 * The pc slots in this ring are themselves a write target
		 * of the wild-write storm being measured -- entries get
		 * stomped between sample-time and dump-time.  Skip rows
		 * whose pc no longer points into our own .text so the
		 * sub-attribution output stays trustworthy for triage.
		 */
		if (snap[i].pc == NULL || !pc_in_text(snap[i].pc))
			continue;
		src = pc_to_source_line(snap[i].pc, srcbuf, sizeof(srcbuf));
		/* The site tag field lives in the same shared stompable ring
		 * as pc, so a wild write can leave site dangling while pc
		 * still passes pc_in_text.  Unlike pc, there is no cheap
		 * in-text/rodata-range helper to validate site before handing
		 * it to vsnprintf, so the [%s] column is omitted entirely:
		 * the pc and (src) columns already identify the rejection
		 * site for triage. */
		if (src != NULL)
			stats_log_write("    %-32s (%s) %lu\n",
					pc_to_string(snap[i].pc, pcbuf, sizeof(pcbuf)),
					src, snap[i].count);
		else
			stats_log_write("    %-32s %lu\n",
					pc_to_string(snap[i].pc, pcbuf, sizeof(pcbuf)),
					snap[i].count);
	}
}

/*
 * Walk every child's local_corrupt_ptr_attr shard and merge into @out
 * by summing counts on (nr, do32bit) key matches.  Returns the number
 * of populated entries written to @out (bounded by @out_cap).  Reads
 * the per-child shards without a lock -- the owning child is the sole
 * writer, so a torn read at most shaves a count by one on a single
 * shard slot, which is in the noise once all shards are summed.
 */
static unsigned int merge_corrupt_ptr_attr_shards(struct corrupt_ptr_attr_entry *out,
						  unsigned int out_cap)
{
	unsigned int i, j, k, n_merged = 0;

	for_each_child(i) {
		struct childdata *child;
		const struct corrupt_ptr_attr_entry *shard;

		child = __atomic_load_n(&children[i], __ATOMIC_ACQUIRE);
		if (child == NULL)
			continue;
		shard = child->local_corrupt_ptr_attr;

		for (j = 0; j < CORRUPT_PTR_ATTR_SLOTS; j++) {
			if (shard[j].count == 0)
				continue;
			for (k = 0; k < n_merged; k++) {
				if (out[k].nr == shard[j].nr &&
				    out[k].do32bit == shard[j].do32bit) {
					out[k].count += shard[j].count;
					break;
				}
			}
			if (k == n_merged && n_merged < out_cap) {
				out[n_merged] = shard[j];
				n_merged++;
			}
		}
	}
	return n_merged;
}

/*
 * Walk every child's local_corrupt_ptr_pc shard and merge into @out
 * by summing counts on (nr, do32bit, pc) key matches.  The first
 * non-NULL site tag wins -- later shards may carry NULL for the same
 * PC if they only saw it through the legacy tagless caller path.
 */
static unsigned int merge_corrupt_ptr_pc_shards(struct corrupt_ptr_pc_entry *out,
						unsigned int out_cap)
{
	unsigned int i, j, k, n_merged = 0;

	for_each_child(i) {
		struct childdata *child;
		const struct corrupt_ptr_pc_entry *shard;

		child = __atomic_load_n(&children[i], __ATOMIC_ACQUIRE);
		if (child == NULL)
			continue;
		shard = child->local_corrupt_ptr_pc;

		for (j = 0; j < CORRUPT_PTR_PC_SLOTS; j++) {
			if (shard[j].count == 0)
				continue;
			for (k = 0; k < n_merged; k++) {
				if (out[k].nr == shard[j].nr &&
				    out[k].do32bit == shard[j].do32bit &&
				    out[k].pc == shard[j].pc) {
					out[k].count += shard[j].count;
					if (out[k].site == NULL &&
					    shard[j].site != NULL)
						out[k].site = shard[j].site;
					break;
				}
			}
			if (k == n_merged && n_merged < out_cap) {
				out[n_merged] = shard[j];
				n_merged++;
			}
		}
	}
	return n_merged;
}

static void corrupt_ptr_attr_dump(void)
{
	struct corrupt_ptr_attr_entry *snap;
	struct corrupt_ptr_pc_entry *pc_snap;
	unsigned int snap_cap, pc_cap, n, n_pc, i;

	/*
	 * Sized for the worst case where every child's shard is full of
	 * unique keys.  In practice the hot keys collide across children
	 * (post-handler attribution is dominated by a handful of syscalls)
	 * and n_merged stays near CORRUPT_PTR_*_SLOTS; the upper bound is
	 * just to avoid truncating when the long tail is unusually wide.
	 * Both allocations are bounded by max_children * SLOTS so a fleet
	 * with a few hundred children stays well under a MiB.
	 */
	snap_cap = max_children * CORRUPT_PTR_ATTR_SLOTS;
	pc_cap = max_children * CORRUPT_PTR_PC_SLOTS;
	snap = calloc(snap_cap, sizeof(*snap));
	pc_snap = calloc(pc_cap, sizeof(*pc_snap));
	if (snap == NULL || pc_snap == NULL) {
		free(snap);
		free(pc_snap);
		return;
	}

	n = merge_corrupt_ptr_attr_shards(snap, snap_cap);
	if (n == 0) {
		free(snap);
		free(pc_snap);
		return;
	}
	n_pc = merge_corrupt_ptr_pc_shards(pc_snap, pc_cap);

	qsort(snap, n, sizeof(snap[0]), corrupt_ptr_attr_cmp);
	if (n_pc > 0)
		qsort(pc_snap, n_pc, sizeof(pc_snap[0]), corrupt_ptr_pc_cmp);

	stats_log_write("post_handler_corrupt_ptr attribution (top %u handlers):\n", n);
	for (i = 0; i < n; i++) {
		const char *name;
		const char *width;

		if (snap[i].nr == CORRUPT_PTR_ATTR_NR_NONE) {
			name = "<deferred-free / non-syscall>";
			width = "(all)";
		} else {
			name = print_syscall_name(snap[i].nr, snap[i].do32bit);
			width = snap[i].do32bit ? "(32)" : "(64)";
		}
		stats_log_write("  %-32s %s %lu\n", name, width, snap[i].count);
		corrupt_ptr_pc_dump_for(pc_snap, n_pc, snap[i].nr, snap[i].do32bit);
	}

	free(snap);
	free(pc_snap);
}

/*
 * Render the per-callsite attribution ring for deferred_free_reject.
 * Mirrors corrupt_ptr_attr_dump() but with no per-handler dimension --
 * every entry is keyed by deferred_free_enqueue's caller PC alone, since
 * all bumps originate from the rec==NULL deferred-free path.  Emits a
 * top-N PC list sorted descending by count and is suppressed entirely
 * on a quiet ring so windows with no rejects stay terse.
 */
static int deferred_free_reject_pc_cmp(const void *a, const void *b)
{
	const struct deferred_free_reject_pc_entry *ea = a;
	const struct deferred_free_reject_pc_entry *eb = b;

	if (eb->count > ea->count)
		return 1;
	if (eb->count < ea->count)
		return -1;
	return 0;
}

/*
 * Walk every child's local_deferred_free_reject_pc shard and merge into
 * @out by summing counts on pc matches.  Same locking model as
 * merge_corrupt_ptr_attr_shards -- single writer per shard, torn reads
 * are tolerable noise on the 600-second dump cadence.
 */
static unsigned int merge_deferred_free_reject_pc_shards(struct deferred_free_reject_pc_entry *out,
							 unsigned int out_cap)
{
	unsigned int i, j, k, n_merged = 0;

	for_each_child(i) {
		struct childdata *child;
		const struct deferred_free_reject_pc_entry *shard;

		child = __atomic_load_n(&children[i], __ATOMIC_ACQUIRE);
		if (child == NULL)
			continue;
		shard = child->local_deferred_free_reject_pc;

		for (j = 0; j < CORRUPT_PTR_PC_SLOTS; j++) {
			if (shard[j].count == 0)
				continue;
			for (k = 0; k < n_merged; k++) {
				if (out[k].pc == shard[j].pc) {
					out[k].count += shard[j].count;
					break;
				}
			}
			if (k == n_merged && n_merged < out_cap) {
				out[n_merged] = shard[j];
				n_merged++;
			}
		}
	}
	return n_merged;
}

static void deferred_free_reject_pc_dump(void)
{
	struct deferred_free_reject_pc_entry *snap;
	unsigned int snap_cap, n, i;

	snap_cap = max_children * CORRUPT_PTR_PC_SLOTS;
	snap = calloc(snap_cap, sizeof(*snap));
	if (snap == NULL)
		return;

	n = merge_deferred_free_reject_pc_shards(snap, snap_cap);
	if (n == 0) {
		free(snap);
		return;
	}

	qsort(snap, n, sizeof(snap[0]), deferred_free_reject_pc_cmp);

	stats_log_write("deferred_free_reject attribution (top %u callers):\n", n);
	for (i = 0; i < n; i++) {
		char pcbuf[128];
		char srcbuf[256];
		const char *src;

		if (snap[i].count == 0)
			break;
		/*
		 * Same in-flight-stomp risk as corrupt_ptr_pc_dump_for: skip
		 * rows whose pc no longer points into our own .text so the
		 * sub-attribution output stays trustworthy for triage.
		 */
		if (snap[i].pc == NULL || !pc_in_text(snap[i].pc))
			continue;
		/*
		 * Annotate with addr2line file:line for the same reason as
		 * corrupt_ptr_pc_dump_for: load-relative offsets resolved by
		 * external tooling round DOWN to the nearest preceding
		 * global symbol, mis-attributing PCs inside LTO-inlined
		 * static helpers (deferred_free_enqueue itself is exactly
		 * that shape via the looks_like_corrupted_ptr_pc and
		 * post_handler_corrupt_ptr_bump inlines).  Falls back to
		 * the bare offset on resolution miss.
		 */
		src = pc_to_source_line(snap[i].pc, srcbuf, sizeof(srcbuf));
		if (src != NULL)
			stats_log_write("  %-32s (%s) %lu\n",
					pc_to_string(snap[i].pc, pcbuf, sizeof(pcbuf)),
					src, snap[i].count);
		else
			stats_log_write("  %-32s %lu\n",
					pc_to_string(snap[i].pc, pcbuf, sizeof(pcbuf)),
					snap[i].count);
	}

	free(snap);
}

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

/*
 * Childop vs random-syscall effort split.
 *
 * Three independent splits between CHILD_OP_SYSCALL (the random-syscall
 * fast path) and all other child_op_types (childop recipes):
 *
 *   walltime   -- cumulative ns spent inside op_fn for each side.
 *                 Source-of-truth for "where is the child loop
 *                 actually spending time".
 *   syscalls   -- random_syscall-mediated syscalls dispatched while
 *                 the per-child in_childop flag was set vs clear.
 *                 Childops that call libc/raw syscall() directly do
 *                 not flow through the call-complete enqueue and are
 *                 not counted here; the walltime metric covers them.
 *   iterations -- per-op_fn dispatch counts: childop_invocations[]
 *                 summed over op != CHILD_OP_SYSCALL vs the parallel
 *                 random_syscall_dispatches counter for the
 *                 CHILD_OP_SYSCALL path.
 *
 * Emitted as one human stat_row line and a single childop_split JSON
 * object so a grep-and-jq reader can audit raw numerators + denominators
 * alongside the rendered percentages.  Cumulative since the run started
 * -- the surrounding defense_counters_periodic_dump already supplies a
 * windowed view via per-dump deltas if the operator wants rate-of-rate
 * trends later.
 *
 * A pct_thousandths helper avoids dragging floating point into the parent
 * stats-dump path while preserving one decimal place of resolution; both
 * sides round to the same scale so the two percentages always sum to
 * 100.0% (within rounding) when the denominator is non-zero.
 */
static unsigned long pct_thousandths(unsigned long num, unsigned long denom)
{
	if (denom == 0)
		return 0;
	/* num * 100000 overflows unsigned long once num approaches ~1.8e14,
	 * which the cumulative childop_walltime_ns numerator reaches on a
	 * sustained run.  Shed low bits from both operands until the multiply
	 * (plus the denom/2 rounding term) can no longer overflow; the ratio
	 * is preserved and the helper only needs 0.1% resolution, so the
	 * dropped bits are immaterial.  num <= denom here, so gating on
	 * ULONG_MAX / 100001 leaves headroom for the rounding add. */
	while (denom > ULONG_MAX / 100001UL) {
		num >>= 1;
		denom >>= 1;
	}
	return (num * 100000UL + denom / 2) / denom;
}

static void childop_split_dump(void)
{
	unsigned long wt_childop = __atomic_load_n(
		&shm->stats.childop_walltime_ns, __ATOMIC_RELAXED);
	unsigned long wt_syscall = __atomic_load_n(
		&shm->stats.syscall_walltime_ns, __ATOMIC_RELAXED);
	unsigned long sc_childop = __atomic_load_n(
		&shm->stats.syscalls_in_childops, __ATOMIC_RELAXED);
	unsigned long sc_random = __atomic_load_n(
		&shm->stats.syscalls_random, __ATOMIC_RELAXED);
	unsigned long it_random = __atomic_load_n(
		&shm->stats.random_syscall_dispatches, __ATOMIC_RELAXED);
	unsigned long it_childop = 0;
	unsigned long wt_total, sc_total, it_total;
	unsigned long wt_pct, sc_pct, it_pct;
	unsigned int op;

	/* Iteration denominator for the childop side: sum the existing
	 * childop_invocations[] over op != CHILD_OP_SYSCALL.  CHILD_OP_SYSCALL
	 * is gated out of that array by child_process()'s is_alt_op check,
	 * so the random_syscall_dispatches counter above is its separate
	 * parallel denominator. */
	for (op = 1; op < NR_CHILD_OP_TYPES; op++) {
		it_childop += __atomic_load_n(
			&shm->stats.childop_invocations[op],
			__ATOMIC_RELAXED);
	}

	wt_total = wt_childop + wt_syscall;
	sc_total = sc_childop + sc_random;
	it_total = it_childop + it_random;

	/* Silently skip the block if no dispatch has happened yet so a
	 * fresh-start dump doesn't print three "0/0 = 0.0%" rows. */
	if (wt_total == 0 && sc_total == 0 && it_total == 0)
		return;

	wt_pct = pct_thousandths(wt_childop, wt_total);
	sc_pct = pct_thousandths(sc_childop, sc_total);
	it_pct = pct_thousandths(it_childop, it_total);

	stats_log_write(
		"childop_split: walltime childop=%lu.%01lu%% (%lu/%lu ns)  "
		"syscalls childop=%lu.%01lu%% (%lu/%lu)  "
		"iterations childop=%lu.%01lu%% (%lu/%lu)\n",
		wt_pct / 1000, (wt_pct / 100) % 10, wt_childop, wt_total,
		sc_pct / 1000, (sc_pct / 100) % 10, sc_childop, sc_total,
		it_pct / 1000, (it_pct / 100) % 10, it_childop, it_total);

	stats_log_write(
		"childop_split_json: {"
		"\"walltime_ns\":{\"childop\":%lu,\"syscall\":%lu,\"pct_childop_x10\":%lu},"
		"\"syscalls\":{\"childop\":%lu,\"random\":%lu,\"pct_childop_x10\":%lu},"
		"\"iterations\":{\"childop\":%lu,\"random\":%lu,\"pct_childop_x10\":%lu}"
		"}\n",
		wt_childop, wt_syscall, wt_pct / 100,
		sc_childop, sc_random, sc_pct / 100,
		it_childop, it_random, it_pct / 100);
}

void __cold defense_counters_periodic_dump(void)
{
	static unsigned long prev[ARRAY_SIZE(defense_counters)];
	static struct timespec last_dump;
	struct timespec now;
	unsigned int i;
	long elapsed;
	int header_emitted = 0;

	clock_gettime(CLOCK_MONOTONIC, &now);

	/* First call: arm the window so any pre-existing counts carried
	 * over from earlier in the run are not mis-attributed to the
	 * first window, mirroring corrupt_ptr_spike_check(). */
	if (last_dump.tv_sec == 0) {
		last_dump = now;
		for (i = 0; i < ARRAY_SIZE(defense_counters); i++)
			prev[i] = defense_counter_load(i);
		return;
	}

	elapsed = now.tv_sec - last_dump.tv_sec;
	if (elapsed < DEFENSE_DUMP_INTERVAL_SEC)
		return;

	for (i = 0; i < ARRAY_SIZE(defense_counters); i++) {
		unsigned long cur = defense_counter_load(i);
		unsigned long delta = cur - prev[i];
		unsigned long rate_milli;

		prev[i] = cur;
		if (delta == 0)
			continue;

		if (header_emitted == 0) {
			stats_log_write("Defense counter rates over last %lds:\n",
					elapsed);
			header_emitted = 1;
		}

		/* Per-second rate scaled by 1000 to keep three decimals
		 * without dragging in floating point on the parent path. */
		rate_milli = (delta * 1000UL) / (unsigned long)elapsed;
		stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
				defense_counters[i].name, delta,
				rate_milli / 1000, rate_milli % 1000, cur);
	}

	corrupt_ptr_attr_dump();
	deferred_free_reject_pc_dump();

	/* Per-fire breadcrumbs printed below the attribution rollup so a
	 * triage scan sees the headline rates, then which handlers, then
	 * the individual scribbled values that drove them.  Self-rate-
	 * limited inside the helper to the same 600 s cadence as the
	 * surrounding dump. */
	corrupt_ptr_breadcrumb_dump(10);

	childop_split_dump();

	/* Advance the per-childop decaying recency ring on the same tick
	 * that drives the other operator-visibility dumps so the recent-
	 * edge / recent-wall view ages out over a wall-clock horizon of
	 * roughly CHILDOP_DECAY_WINDOWS * DEFENSE_DUMP_INTERVAL_SEC.
	 * SHADOW: no picker / canary code reads the ring; rotation cadence
	 * only affects what the shutdown dump labels "recent". */
	childop_window_advance();

	last_dump = now;
}

/* Per-pool top-N entry for top_syscalls_periodic_dump's stack-resident
 * insertion sort.  Holds the syscall's table index and the per-window
 * delta of its strategy-attributed new-edge counter. */
struct top_syscall_entry {
	unsigned int nr;
	unsigned long delta;
};

#define TOP_SYSCALLS_DUMP_TOPN	5

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
		unsigned long delta = (cur[i] > prev[i]) ? cur[i] - prev[i] : 0;

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
		unsigned long live_d = (cur_live_picks[i] > prev_live_picks[i])
			? cur_live_picks[i] - prev_live_picks[i] : 0;
		unsigned long silent_d = (cur_silent_picks[i] > prev_silent_picks[i])
			? cur_silent_picks[i] - prev_silent_picks[i] : 0;
		unsigned long wins_d = (cur_wins[i] > prev_wins[i])
			? cur_wins[i] - prev_wins[i] : 0;
		unsigned long misses_d = (cur_misses[i] > prev_misses[i])
			? cur_misses[i] - prev_misses[i] : 0;

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
	unsigned long bandit_window_now;
	struct timespec now;
	long elapsed;
	unsigned int nr_to_scan;
	const struct syscalltable *table;
	unsigned int i;

	clock_gettime(CLOCK_MONOTONIC, &now);

	/* First call: arm the window so any pre-existing counts carried
	 * over from earlier in the run are not mis-attributed to the
	 * first window, mirroring defense_counters_periodic_dump. */
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
				&shm->stats.frontier_picks_per_syscall[i],
				__ATOMIC_RELAXED);
			prev_frontier_live_picks[i] = __atomic_load_n(
				&shm->stats.frontier_live_picks_per_syscall[i],
				__ATOMIC_RELAXED);
			prev_frontier_silent_picks[i] = __atomic_load_n(
				&shm->stats.frontier_silent_picks_per_syscall[i],
				__ATOMIC_RELAXED);
			prev_frontier_wins[i] = __atomic_load_n(
				&shm->stats.frontier_productive_wins_per_syscall[i],
				__ATOMIC_RELAXED);
			prev_frontier_live_misses[i] = __atomic_load_n(
				&shm->stats.frontier_live_misses_per_syscall[i],
				__ATOMIC_RELAXED);
			prev_rq_saves[i] = __atomic_load_n(
				&shm->stats.rq_sourced_saves_per_syscall[i],
				__ATOMIC_RELAXED);
			prev_rq_wins[i] = __atomic_load_n(
				&shm->stats.rq_sourced_pcedge_wins_per_syscall[i],
				__ATOMIC_RELAXED);
			prev_warm_reserve[i] = __atomic_load_n(
				&shm->stats.warm_reserve_candidates[i],
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
			&shm->stats.frontier_picks_per_syscall[i],
			__ATOMIC_RELAXED);
		cur_frontier_live_picks[i] = __atomic_load_n(
			&shm->stats.frontier_live_picks_per_syscall[i],
			__ATOMIC_RELAXED);
		cur_frontier_silent_picks[i] = __atomic_load_n(
			&shm->stats.frontier_silent_picks_per_syscall[i],
			__ATOMIC_RELAXED);
		cur_frontier_wins[i] = __atomic_load_n(
			&shm->stats.frontier_productive_wins_per_syscall[i],
			__ATOMIC_RELAXED);
		cur_frontier_live_misses[i] = __atomic_load_n(
			&shm->stats.frontier_live_misses_per_syscall[i],
			__ATOMIC_RELAXED);
		cur_frontier_last_productive[i] = __atomic_load_n(
			&shm->stats.frontier_last_productive_window_per_syscall[i],
			__ATOMIC_RELAXED);
		cur_frontier_recent_weight[i] = __atomic_load_n(
			&shm->frontier_recent_count_cached[i],
			__ATOMIC_RELAXED);
		cur_rq_saves[i] = __atomic_load_n(
			&shm->stats.rq_sourced_saves_per_syscall[i],
			__ATOMIC_RELAXED);
		cur_rq_wins[i] = __atomic_load_n(
			&shm->stats.rq_sourced_pcedge_wins_per_syscall[i],
			__ATOMIC_RELAXED);
		cur_warm_reserve[i] = __atomic_load_n(
			&shm->stats.warm_reserve_candidates[i],
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

	/* Frontier-picker accept distribution: which syscalls ate the
	 * coverage-frontier picks this window.  Same top-N emitter as the
	 * edge pools above; an empty distribution (frontier arm never
	 * selected, or selected but accepted nothing) skips the row via the
	 * helper's zero-total gate. */
	stats_log_write("Top %u syscalls by frontier picks in last %lds:\n",
			TOP_SYSCALLS_DUMP_TOPN, elapsed);
	top_syscalls_emit_pool("frontier", cur_frontier_picks,
			       prev_frontier_picks, nr_to_scan, table, false);

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
			cur_frontier_live_picks, prev_frontier_live_picks,
			cur_frontier_silent_picks, prev_frontier_silent_picks,
			cur_frontier_wins, prev_frontier_wins,
			cur_frontier_live_misses, prev_frontier_live_misses,
			cur_frontier_recent_weight,
			cur_frontier_last_productive,
			bandit_window_now,
			nr_to_scan, table, false);

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
	top_syscalls_emit_pool("rq-saves", cur_rq_saves, prev_rq_saves,
			       nr_to_scan, table, false);
	stats_log_write("Top %u syscalls by PC-edge wins from "
			"RedQueen-sourced saves in last %lds:\n",
			TOP_SYSCALLS_DUMP_TOPN, elapsed);
	top_syscalls_emit_pool("rq-pcedge-wins", cur_rq_wins, prev_rq_wins,
			       nr_to_scan, table, false);

	/* SHADOW deep-but-warm candidate accounting (see the warm_reserve_
	 * candidates* comment in include/stats.h for the predicate).  Same
	 * top-N shape and zero-total skip as the pools above; an empty
	 * distribution (no syscall fired the deep-but-warm predicate this
	 * window) collapses to no row via the emitter's gate. */
	stats_log_write("Top %u syscalls by deep-but-warm candidates "
			"in last %lds:\n",
			TOP_SYSCALLS_DUMP_TOPN, elapsed);
	top_syscalls_emit_pool("warm-reserve", cur_warm_reserve,
			       prev_warm_reserve, nr_to_scan, table, false);

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

	last_dump = now;
}

/*
 * Count newline-terminated lines in @path.  Returns -1 on open failure
 * (caller skips the slot) and the line count otherwise.  Each completed
 * /proc/<pid>/maps line is one VMA in the target's address space, so the
 * line count is the VMA count without the cost of parsing the address /
 * permission / pathname columns we don't care about here.  Anchoring on
 * '\n' avoids over-counting when a single maps line exceeds the read
 * buffer (rare but possible -- there's no kernel-side cap on the trailing
 * pathname column) and fgets returns the tail in a follow-up call.
 */
static long count_proc_maps_lines(const char *path)
{
	FILE *f;
	char buf[1024];
	long lines = 0;

	f = fopen(path, "r");
	if (f == NULL)
		return -1;

	while (fgets(buf, sizeof(buf), f) != NULL) {
		if (strchr(buf, '\n') != NULL)
			lines++;
	}

	fclose(f);
	return lines;
}

/*
 * Per-tick scan paired with defense_counters_periodic_dump: every dump
 * window, snapshot the parent's VMA count and walk the live child pid
 * slots to sum, max, and min the children's VMA counts.  The point is
 * post-mortem visibility for the cgroup-OOM class where one of trinity's
 * thaw/freeze paths leaks a VMA per cycle (a failed mprotect that gets
 * retried can split a VMA without merging back, and the leak only
 * manifests when the host kills the parent for memory exhaustion).
 * children_max is the diagnostic of interest: if a single slot grows
 * its VMA count an order of magnitude faster than the others, that's
 * the leak signature.  /proc reads that fail (process died between the
 * pid snapshot and the open) are silently skipped rather than panicked.
 */
void __cold vma_count_periodic_dump(void)
{
	static struct timespec last_dump;
	struct timespec now;
	long elapsed;
	long parent_vmas;
	unsigned long total = 0;
	unsigned long max_vmas = 0;
	unsigned long min_vmas = 0;
	bool min_set = false;
	unsigned int i;

	clock_gettime(CLOCK_MONOTONIC, &now);

	/* First call: arm the window so the first emission lands at the
	 * same cadence as the rest of the periodic dumps. */
	if (last_dump.tv_sec == 0) {
		last_dump = now;
		return;
	}

	elapsed = now.tv_sec - last_dump.tv_sec;
	if (elapsed < DEFENSE_DUMP_INTERVAL_SEC)
		return;

	parent_vmas = count_proc_maps_lines("/proc/self/maps");

	for_each_child(i) {
		char path[32];
		pid_t pid;
		long n;

		pid = __atomic_load_n(&pids[i], __ATOMIC_RELAXED);
		if (pid == EMPTY_PIDSLOT)
			continue;

		snprintf(path, sizeof(path), "/proc/%d/maps", (int)pid);
		n = count_proc_maps_lines(path);
		if (n < 0)
			continue;

		total += (unsigned long)n;
		if ((unsigned long)n > max_vmas)
			max_vmas = (unsigned long)n;
		if (!min_set || (unsigned long)n < min_vmas) {
			min_vmas = (unsigned long)n;
			min_set = true;
		}
	}

	/*
	 * Coalesce identical VMAs lines.  In steady-state runs all four
	 * counts (parent, total, max, min) are unchanged window after
	 * window.  Suppress repeats but force a print every 30 windows so
	 * the stats log still carries a periodic state anchor.
	 */
	unsigned long parent = (parent_vmas < 0) ? 0UL : (unsigned long)parent_vmas;
	static unsigned long last_vma_parent;
	static unsigned long last_vma_total;
	static unsigned long last_vma_max;
	static unsigned long last_vma_min;
	static unsigned int vma_suppress = 30; /* force first print */
	if (vma_suppress >= 30 ||
	    parent != last_vma_parent ||
	    total != last_vma_total ||
	    max_vmas != last_vma_max ||
	    min_vmas != last_vma_min) {
		stats_log_write("[main] VMAs: parent=%lu children_total=%lu children_max=%lu children_min=%lu\n",
				parent, total, max_vmas, min_vmas);
		last_vma_parent = parent;
		last_vma_total = total;
		last_vma_max = max_vmas;
		last_vma_min = min_vmas;
		vma_suppress = 0;
	} else {
		vma_suppress++;
	}

	last_dump = now;
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
static void kcov_cmp_observability_block_render(long elapsed __unused__)
{
	static unsigned long prev_cmp_inserts[MAX_NR_SYSCALL];
	static unsigned long prev_cmp_injected[MAX_NR_SYSCALL];
	static unsigned long prev_pc_wins[MAX_NR_SYSCALL];
	static unsigned long prev_edges[MAX_NR_SYSCALL];
	static bool armed;
	unsigned int top_nr[10];
	unsigned long top_cmp[10];
	unsigned long top_injected[10];
	unsigned long top_pc_wins[10];
	unsigned long top_edges[10];
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

	for (i = 0; i < nr_syscalls_to_scan; i++) {
		unsigned long cur_inserts = __atomic_load_n(
			&kcov_shm->per_syscall_cmp_inserts[i], __ATOMIC_RELAXED);
		unsigned long cur_injected = __atomic_load_n(
			&kcov_shm->per_syscall_cmp_injected[i], __ATOMIC_RELAXED);
		unsigned long cur_pc_wins = __atomic_load_n(
			&kcov_shm->per_syscall_cmp_hint_pc_wins[i], __ATOMIC_RELAXED);
		unsigned long cur_edges = __atomic_load_n(
			&kcov_shm->per_syscall_edges[i], __ATOMIC_RELAXED);
		unsigned long delta_inserts;
		unsigned long delta_injected;
		unsigned long delta_pc_wins;
		unsigned long delta_edges;
		unsigned int k;

		/* First window: arm the snapshot and skip emit so any
		 * pre-existing cumulative counts (warm-start / prior epoch)
		 * are not mis-attributed to the first dump window. */
		if (!armed) {
			prev_cmp_inserts[i] = cur_inserts;
			prev_cmp_injected[i] = cur_injected;
			prev_pc_wins[i] = cur_pc_wins;
			prev_edges[i] = cur_edges;
			continue;
		}

		/* Guarded unsigned subtraction.  Counters are monotonic in
		 * the steady-state case but a cmp-hints warm-start that
		 * lands between two dumps can publish a lower value; clamp
		 * to zero so a one-shot warm-start doesn't underflow into a
		 * ~ULONG_MAX delta the topn picker would pin to slot 0. */
		delta_inserts  = (cur_inserts  > prev_cmp_inserts[i])  ? cur_inserts  - prev_cmp_inserts[i]  : 0;
		delta_injected = (cur_injected > prev_cmp_injected[i]) ? cur_injected - prev_cmp_injected[i] : 0;
		delta_pc_wins  = (cur_pc_wins  > prev_pc_wins[i])      ? cur_pc_wins  - prev_pc_wins[i]      : 0;
		delta_edges    = (cur_edges    > prev_edges[i])        ? cur_edges    - prev_edges[i]        : 0;

		prev_cmp_inserts[i] = cur_inserts;
		prev_cmp_injected[i] = cur_injected;
		prev_pc_wins[i] = cur_pc_wins;
		prev_edges[i] = cur_edges;

		if (delta_inserts == 0)
			continue;

		/* Rank by cmp_inserts delta: that's the producer-side
		 * "kernel emitted distinct CMP signal for this syscall"
		 * column, which is the one the PHASE-0 hold cares about.
		 * Insertion sort on the four arrays in lock-step so the
		 * top-N rows stay aligned across columns. */
		for (j = top_count; j > 0 && delta_inserts > top_cmp[j - 1]; j--) {
			if (j < 10) {
				top_cmp[j]      = top_cmp[j - 1];
				top_injected[j] = top_injected[j - 1];
				top_pc_wins[j]  = top_pc_wins[j - 1];
				top_edges[j]    = top_edges[j - 1];
				top_nr[j]       = top_nr[j - 1];
			}
		}
		k = j;
		if (k < 10) {
			top_cmp[k]      = delta_inserts;
			top_injected[k] = delta_injected;
			top_pc_wins[k]  = delta_pc_wins;
			top_edges[k]    = delta_edges;
			top_nr[k]       = i;
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
	stats_log_write("  %-24s %10s %10s %10s %10s\n",
			"syscall", "cmp+", "injected+", "pc-wins+", "edge+");
	for (j = 0; j < top_count; j++) {
		struct syscallentry *entry = table[top_nr[j]].entry;
		const char *name = entry ? entry->name : "???";

		stats_log_write("  %-24s %10lu %10lu %10lu %10lu\n",
				name, top_cmp[j], top_injected[j],
				top_pc_wins[j], top_edges[j]);
	}
}

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

		delta_attempts = (cur_attempts > prev_attempts[i])  ? cur_attempts - prev_attempts[i]  : 0;
		delta_ambig    = (cur_ambig    > prev_ambiguous[i]) ? cur_ambig    - prev_ambiguous[i] : 0;

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
		if ((slot_hist[i] | slot_success[i]) != 0)
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
 * Old-flat-pool vs shadow-hypothesis comparison block.  Two sub-blocks:
 *
 *   1. Flat per-pool-kind summary: per-pool consumed / pc-wins / misses /
 *      cmp-novelty cumulative + window-delta.  Lets an operator read the
 *      per-syscall vs field-pool conversion ratio at a glance without
 *      having to thread per-syscall arrays.
 *
 *   2. Per-syscall top-N table: for the top syscalls by per-window
 *      cmp-hint injection delta, print the OLD per-syscall pool's
 *      conversion (per_syscall_cmp_hint_pc_wins / per_syscall_cmp_injected)
 *      alongside the SHADOW typed-hypothesis per-syscall pc-wins (summed
 *      across the matching hyp_pools[nr][0/1] entries).  The two columns
 *      answer the t75 question directly: does the typed store predict
 *      better-converting picks than the flat pool on the same syscalls
 *      the flat pool is most active on.
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
	static unsigned long prev_per_nr_injected[MAX_NR_SYSCALL];
	static unsigned long prev_per_nr_pc_wins[MAX_NR_SYSCALL];
	static uint64_t prev_per_nr_hyp_pc_wins[MAX_NR_SYSCALL];
	static bool armed;

	unsigned long cur_consumed_by_pool[CMP_HINT_POOL_KIND_NR];
	unsigned long cur_pc_wins_by_pool[CMP_HINT_POOL_KIND_NR];
	unsigned long cur_misses_by_pool[CMP_HINT_POOL_KIND_NR];
	unsigned long cur_cmp_novelty_by_pool[CMP_HINT_POOL_KIND_NR];
	unsigned long delta_consumed_by_pool[CMP_HINT_POOL_KIND_NR];
	unsigned long delta_pc_wins_by_pool[CMP_HINT_POOL_KIND_NR];
	unsigned long delta_misses_by_pool[CMP_HINT_POOL_KIND_NR];
	unsigned long delta_cmp_novelty_by_pool[CMP_HINT_POOL_KIND_NR];

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
	unsigned int k, i, j;
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
		 * windowed emit below; the first call seeds prev_ and skips
		 * the comparison, identical to the pattern in
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

		if (cmp_hints_shm != NULL) {
			unsigned int do32_i, e_i;

			for (do32_i = 0; do32_i < 2; do32_i++) {
				struct cmp_hyp_pool *p =
					&cmp_hints_shm->hyp_pools[i][do32_i];
				unsigned int n = p->count;

				if (n > CMP_HYP_PER_SYSCALL)
					n = CMP_HYP_PER_SYSCALL;
				for (e_i = 0; e_i < n; e_i++) {
					struct cmp_hypothesis *h = &p->entries[e_i];

					cur_hyp_pc_wins_nr += __atomic_load_n(
						&h->pc_wins, __ATOMIC_RELAXED);
					cur_hyp_consumed_nr += __atomic_load_n(
						&h->consumed_count, __ATOMIC_RELAXED);
					cur_hyp_misses_nr += __atomic_load_n(
						&h->misses, __ATOMIC_RELAXED);
				}
			}
		}

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
 * Surface the KCOV CMP counters in the same 600s periodic stats-log-file
 * dump as defense_counters_periodic_dump.  Without this the cmp counters
 * are only visible from dump_stats() (run shutdown) and the JSON dump
 * (on enable), so a long overnight run produces no time-series — just a
 * single end-snapshot — making it impossible to correlate cmp_hints
 * effectiveness with edge-discovery cadence over the run.
 *
 * Three sub-blocks, each gated independently so a healthy run that has
 * no DIAG errnos doesn't carry an empty "DIAG:" line into the log:
 *  - per-window deltas + rates + cumulative totals for the three cmp
 *    counters, formatted to match defense_counters_periodic_dump;
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
	bool any_prop_callsite_delta = false;
	unsigned int pc_kids, cmp_kids;

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
	cur_frontier_blend_samples          = __atomic_load_n(&shm->stats.frontier_blend_samples,         __ATOMIC_RELAXED);
	cur_frontier_blend_arm_a_children   = __atomic_load_n(&kcov_shm->frontier_blend_arm_a_children,   __ATOMIC_RELAXED);
	cur_frontier_blend_arm_b_children   = __atomic_load_n(&kcov_shm->frontier_blend_arm_b_children,   __ATOMIC_RELAXED);
	cur_remote_adaptive_samples         = __atomic_load_n(&shm->stats.remote_adaptive_samples,        __ATOMIC_RELAXED);
	cur_remote_adaptive_would_demote    = __atomic_load_n(&shm->stats.remote_adaptive_would_demote,   __ATOMIC_RELAXED);
	cur_remote_adaptive_would_promote   = __atomic_load_n(&shm->stats.remote_adaptive_would_promote,  __ATOMIC_RELAXED);
	cur_remote_adaptive_would_force     = __atomic_load_n(&shm->stats.remote_adaptive_would_force,    __ATOMIC_RELAXED);
	cur_remote_adaptive_agree           = __atomic_load_n(&shm->stats.remote_adaptive_agree,          __ATOMIC_RELAXED);
	cur_remote_adaptive_arm_a_children  = __atomic_load_n(&kcov_shm->remote_adaptive_arm_a_children,  __ATOMIC_RELAXED);
	cur_remote_adaptive_arm_b_children  = __atomic_load_n(&kcov_shm->remote_adaptive_arm_b_children,  __ATOMIC_RELAXED);
	cur_arg_meta_addr_with_meta            = __atomic_load_n(&shm->stats.arg_meta_addr_with_meta,            __ATOMIC_RELAXED);
	cur_arg_meta_addr_without_meta         = __atomic_load_n(&shm->stats.arg_meta_addr_without_meta,         __ATOMIC_RELAXED);
	cur_arg_meta_argtype_stale             = __atomic_load_n(&shm->stats.arg_meta_argtype_stale,             __ATOMIC_RELAXED);
	cur_arg_meta_scrub_would_destroy_in    = __atomic_load_n(&shm->stats.arg_meta_scrub_would_destroy_in,    __ATOMIC_RELAXED);
	cur_arg_meta_scrub_would_preserve_out  = __atomic_load_n(&shm->stats.arg_meta_scrub_would_preserve_out,  __ATOMIC_RELAXED);
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
	 * first window, mirroring defense_counters_periodic_dump. */
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
			for (cs = 0; cs < CMP_HINT_CALLSITE_NR; cs++)
				prev_cmp_hint_callsite[cs] = cur_cmp_hint_callsite[cs];
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

	delta_records       = cur_records       - prev_records;
	delta_truncated     = cur_truncated     - prev_truncated;
	delta_bloom_skipped = cur_bloom_skipped - prev_bloom_skipped;
	delta_strip_skipped = cur_strip_skipped - prev_strip_skipped;
	delta_unique        = cur_unique        - prev_unique;
	delta_try_get_attempts = cur_try_get_attempts - prev_try_get_attempts;
	delta_try_get_returned = cur_try_get_returned - prev_try_get_returned;
	delta_injected         = cur_injected         - prev_injected;
	delta_prop_injected    = cur_prop_injected    - prev_prop_injected;
	delta_chaos_suppressed = cur_chaos_suppressed - prev_chaos_suppressed;
	delta_count_oob        = cur_count_oob        - prev_count_oob;
	delta_canary_lock_post = cur_canary_lock_post - prev_canary_lock_post;
	delta_canary_pre       = cur_canary_pre       - prev_canary_pre;
	delta_canary_post      = cur_canary_post      - prev_canary_post;
	delta_reexec_attempts                = cur_reexec_attempts                - prev_reexec_attempts;
	delta_reexec_attempts_with_new_cmp   = cur_reexec_attempts_with_new_cmp   - prev_reexec_attempts_with_new_cmp;
	delta_reexec_attribution_found       = cur_reexec_attribution_found       - prev_reexec_attribution_found;
	delta_reexec_attribution_ambiguous   = cur_reexec_attribution_ambiguous   - prev_reexec_attribution_ambiguous;
	delta_reexec_attribution_width_match = cur_reexec_attribution_width_match - prev_reexec_attribution_width_match;
	delta_reexec_new_cmps_total          = cur_reexec_new_cmps_total          - prev_reexec_new_cmps_total;
	delta_reexec_skipped_destructive     = cur_reexec_skipped_destructive     - prev_reexec_skipped_destructive;
	delta_reexec_skipped_validate_silent = cur_reexec_skipped_validate_silent - prev_reexec_skipped_validate_silent;
	delta_reexec_window_cap_hit          = cur_reexec_window_cap_hit          - prev_reexec_window_cap_hit;
	delta_reexec_pending_dropped         = cur_reexec_pending_dropped         - prev_reexec_pending_dropped;
	delta_reexec_gate_skip_in_reexec     = cur_reexec_gate_skip_in_reexec     - prev_reexec_gate_skip_in_reexec;
	delta_reexec_gate_skip_disabled      = cur_reexec_gate_skip_disabled      - prev_reexec_gate_skip_disabled;
	delta_reexec_gate_skip_mode          = cur_reexec_gate_skip_mode          - prev_reexec_gate_skip_mode;
	delta_reexec_gate_skip_chain_mid     = cur_reexec_gate_skip_chain_mid     - prev_reexec_gate_skip_chain_mid;
	delta_reexec_gate_skip_no_new_cmp    = cur_reexec_gate_skip_no_new_cmp    - prev_reexec_gate_skip_no_new_cmp;
	delta_reexec_gate_skip_no_pending    = cur_reexec_gate_skip_no_pending    - prev_reexec_gate_skip_no_pending;
	delta_reexec_gate_skip_rate          = cur_reexec_gate_skip_rate          - prev_reexec_gate_skip_rate;
	delta_reexec_gate_pass               = cur_reexec_gate_pass               - prev_reexec_gate_pass;
	delta_cmp_parent_calls_enabled       = cur_cmp_parent_calls_enabled       - prev_cmp_parent_calls_enabled;
	delta_cmp_parent_calls_control       = cur_cmp_parent_calls_control       - prev_cmp_parent_calls_control;
	delta_cmp_parent_new_cmps_enabled    = cur_cmp_parent_new_cmps_enabled    - prev_cmp_parent_new_cmps_enabled;
	delta_cmp_parent_new_cmps_control    = cur_cmp_parent_new_cmps_control    - prev_cmp_parent_new_cmps_control;
	delta_save_reject_nonconst      = cur_save_reject_nonconst      - prev_save_reject_nonconst;
	delta_save_reject_uninteresting = cur_save_reject_uninteresting - prev_save_reject_uninteresting;
	delta_save_reject_sentinel      = cur_save_reject_sentinel      - prev_save_reject_sentinel;
	delta_save_reject_dup           = cur_save_reject_dup           - prev_save_reject_dup;
	delta_save_reject_cap           = cur_save_reject_cap           - prev_save_reject_cap;
	{
		unsigned int cs;
		for (cs = 0; cs < CMP_HINT_CALLSITE_NR; cs++) {
			delta_cmp_hint_callsite[cs] =
				cur_cmp_hint_callsite[cs] - prev_cmp_hint_callsite[cs];
			if (delta_cmp_hint_callsite[cs] != 0)
				any_callsite_delta = true;
		}
	}
	{
		unsigned int cs;
		for (cs = 0; cs < PROP_INJECTED_CALLSITE_NR; cs++) {
			delta_prop_injected_callsite[cs] =
				cur_prop_injected_callsite[cs] - prev_prop_injected_callsite[cs];
			if (delta_prop_injected_callsite[cs] != 0)
				any_prop_callsite_delta = true;
		}
	}
	delta_cmp_hints_consumed             = cur_cmp_hints_consumed             - prev_cmp_hints_consumed;
	delta_cmp_hint_wins                  = cur_cmp_hint_wins                  - prev_cmp_hint_wins;
	delta_cmp_hint_misses                = cur_cmp_hint_misses                - prev_cmp_hint_misses;
	delta_cmp_hint_cmp_novelty_wins      = cur_cmp_hint_cmp_novelty_wins      - prev_cmp_hint_cmp_novelty_wins;
	delta_cmp_hint_stash_overflow        = cur_cmp_hint_stash_overflow        - prev_cmp_hint_stash_overflow;
	delta_cmp_hint_credit_entry_evicted  = cur_cmp_hint_credit_entry_evicted  - prev_cmp_hint_credit_entry_evicted;
	delta_cmp_recent_inserts             = cur_cmp_recent_inserts             - prev_cmp_recent_inserts;
	delta_cmp_recent_evicts              = cur_cmp_recent_evicts              - prev_cmp_recent_evicts;
	delta_cmp_recent_would_pick          = cur_cmp_recent_would_pick          - prev_cmp_recent_would_pick;
	delta_cmp_recent_would_miss          = cur_cmp_recent_would_miss          - prev_cmp_recent_would_miss;
	delta_cmp_recent_live_picks          = cur_cmp_recent_live_picks          - prev_cmp_recent_live_picks;
	delta_cmp_inject_arm_a_baseline_fires = cur_cmp_inject_arm_a_baseline_fires - prev_cmp_inject_arm_a_baseline_fires;
	delta_cmp_inject_arm_b_baseline_fires = cur_cmp_inject_arm_b_baseline_fires - prev_cmp_inject_arm_b_baseline_fires;
	delta_cmp_inject_denom_diverged       = cur_cmp_inject_denom_diverged       - prev_cmp_inject_denom_diverged;
	delta_prop_ring_argop_arm_b_fires     = cur_prop_ring_argop_arm_b_fires     - prev_prop_ring_argop_arm_b_fires;
	delta_frontier_blend_samples          = cur_frontier_blend_samples          - prev_frontier_blend_samples;
	delta_remote_adaptive_samples         = cur_remote_adaptive_samples         - prev_remote_adaptive_samples;
	delta_mut_structured_shadow_divergences = cur_mut_structured_shadow_divergences - prev_mut_structured_shadow_divergences;

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
	    any_callsite_delta || any_prop_callsite_delta) {
		stats_log_write("KCOV CMP stats over last %lds:\n", elapsed);

		if (delta_records) {
			unsigned long rate_milli = (delta_records * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_records_collected", delta_records,
					rate_milli / 1000, rate_milli % 1000, cur_records);
		}
		if (delta_truncated) {
			unsigned long rate_milli = (delta_truncated * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_trace_truncated", delta_truncated,
					rate_milli / 1000, rate_milli % 1000, cur_truncated);
		}
		if (delta_bloom_skipped) {
			unsigned long rate_milli = (delta_bloom_skipped * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hints_bloom_skipped", delta_bloom_skipped,
					rate_milli / 1000, rate_milli % 1000, cur_bloom_skipped);
		}
		if (delta_strip_skipped) {
			unsigned long rate_milli = (delta_strip_skipped * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hints_strip_skipped", delta_strip_skipped,
					rate_milli / 1000, rate_milli % 1000, cur_strip_skipped);
		}
		if (delta_unique) {
			unsigned long rate_milli = (delta_unique * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hints_unique_inserts", delta_unique,
					rate_milli / 1000, rate_milli % 1000, cur_unique);
		}
		if (delta_save_reject_nonconst) {
			unsigned long rate_milli = (delta_save_reject_nonconst * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hints_save_reject_nonconst", delta_save_reject_nonconst,
					rate_milli / 1000, rate_milli % 1000, cur_save_reject_nonconst);
		}
		if (delta_save_reject_uninteresting) {
			unsigned long rate_milli = (delta_save_reject_uninteresting * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hints_save_reject_uninteresting", delta_save_reject_uninteresting,
					rate_milli / 1000, rate_milli % 1000, cur_save_reject_uninteresting);
		}
		if (delta_save_reject_sentinel) {
			unsigned long rate_milli = (delta_save_reject_sentinel * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hints_save_reject_sentinel", delta_save_reject_sentinel,
					rate_milli / 1000, rate_milli % 1000, cur_save_reject_sentinel);
		}
		if (delta_save_reject_dup) {
			unsigned long rate_milli = (delta_save_reject_dup * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hints_save_reject_dup", delta_save_reject_dup,
					rate_milli / 1000, rate_milli % 1000, cur_save_reject_dup);
		}
		if (delta_save_reject_cap) {
			unsigned long rate_milli = (delta_save_reject_cap * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hints_save_reject_cap", delta_save_reject_cap,
					rate_milli / 1000, rate_milli % 1000, cur_save_reject_cap);
		}
		if (delta_try_get_attempts) {
			unsigned long rate_milli = (delta_try_get_attempts * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hints_try_get_attempts", delta_try_get_attempts,
					rate_milli / 1000, rate_milli % 1000, cur_try_get_attempts);
		}
		if (delta_try_get_returned) {
			unsigned long rate_milli = (delta_try_get_returned * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hints_try_get_returned", delta_try_get_returned,
					rate_milli / 1000, rate_milli % 1000, cur_try_get_returned);
		}
		if (delta_injected) {
			unsigned long rate_milli = (delta_injected * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hints_injected", delta_injected,
					rate_milli / 1000, rate_milli % 1000, cur_injected);
		}
		if (delta_prop_injected) {
			unsigned long rate_milli = (delta_prop_injected * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"propagation_injected", delta_prop_injected,
					rate_milli / 1000, rate_milli % 1000, cur_prop_injected);
		}
		if (delta_chaos_suppressed) {
			unsigned long rate_milli = (delta_chaos_suppressed * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu, chaos_active=%d)\n",
					"cmp_hints_chaos_suppressed", delta_chaos_suppressed,
					rate_milli / 1000, rate_milli % 1000, cur_chaos_suppressed,
					cmp_hints_chaos_query() ? 1 : 0);
		}
		/* Wild-write detection: any non-zero delta is news, and the
		 * 0/s rate noise of a one-shot stomp is fine -- the canary
		 * counters surface a real corruption channel, not a hot-path
		 * statistic, so the same row format is used as the rest. */
		if (delta_count_oob) {
			unsigned long rate_milli = (delta_count_oob * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hints_count_oob", delta_count_oob,
					rate_milli / 1000, rate_milli % 1000, cur_count_oob);
		}
		if (delta_canary_lock_post) {
			unsigned long rate_milli = (delta_canary_lock_post * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hints_canary_lock_post_corrupt", delta_canary_lock_post,
					rate_milli / 1000, rate_milli % 1000, cur_canary_lock_post);
		}
		if (delta_canary_pre) {
			unsigned long rate_milli = (delta_canary_pre * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hints_canary_pre_corrupt", delta_canary_pre,
					rate_milli / 1000, rate_milli % 1000, cur_canary_pre);
		}
		if (delta_canary_post) {
			unsigned long rate_milli = (delta_canary_post * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hints_canary_post_corrupt", delta_canary_post,
					rate_milli / 1000, rate_milli % 1000, cur_canary_post);
		}
		if (delta_reexec_attempts) {
			unsigned long rate_milli = (delta_reexec_attempts * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"reexec_attempts", delta_reexec_attempts,
					rate_milli / 1000, rate_milli % 1000, cur_reexec_attempts);
		}
		if (delta_reexec_attempts_with_new_cmp) {
			unsigned long rate_milli = (delta_reexec_attempts_with_new_cmp * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"reexec_attempts_with_new_cmp", delta_reexec_attempts_with_new_cmp,
					rate_milli / 1000, rate_milli % 1000, cur_reexec_attempts_with_new_cmp);
		}
		if (delta_reexec_attribution_found) {
			unsigned long rate_milli = (delta_reexec_attribution_found * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"reexec_attribution_found", delta_reexec_attribution_found,
					rate_milli / 1000, rate_milli % 1000, cur_reexec_attribution_found);
		}
		if (delta_reexec_attribution_ambiguous) {
			unsigned long rate_milli = (delta_reexec_attribution_ambiguous * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"reexec_attribution_ambiguous", delta_reexec_attribution_ambiguous,
					rate_milli / 1000, rate_milli % 1000, cur_reexec_attribution_ambiguous);
		}
		if (delta_reexec_attribution_width_match) {
			unsigned long rate_milli = (delta_reexec_attribution_width_match * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"reexec_attribution_width_match", delta_reexec_attribution_width_match,
					rate_milli / 1000, rate_milli % 1000, cur_reexec_attribution_width_match);
		}
		if (delta_reexec_new_cmps_total) {
			unsigned long rate_milli = (delta_reexec_new_cmps_total * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"reexec_new_cmps_total", delta_reexec_new_cmps_total,
					rate_milli / 1000, rate_milli % 1000, cur_reexec_new_cmps_total);
		}
		if (delta_reexec_skipped_destructive) {
			unsigned long rate_milli = (delta_reexec_skipped_destructive * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"reexec_skipped_destructive", delta_reexec_skipped_destructive,
					rate_milli / 1000, rate_milli % 1000, cur_reexec_skipped_destructive);
		}
		if (delta_reexec_skipped_validate_silent) {
			unsigned long rate_milli = (delta_reexec_skipped_validate_silent * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"reexec_skipped_validate_silent", delta_reexec_skipped_validate_silent,
					rate_milli / 1000, rate_milli % 1000, cur_reexec_skipped_validate_silent);
		}
		if (delta_reexec_window_cap_hit) {
			unsigned long rate_milli = (delta_reexec_window_cap_hit * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"reexec_window_cap_hit", delta_reexec_window_cap_hit,
					rate_milli / 1000, rate_milli % 1000, cur_reexec_window_cap_hit);
		}
		if (delta_reexec_pending_dropped) {
			unsigned long rate_milli = (delta_reexec_pending_dropped * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"reexec_pending_dropped", delta_reexec_pending_dropped,
					rate_milli / 1000, rate_milli % 1000, cur_reexec_pending_dropped);
		}
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
		if (delta_reexec_gate_skip_in_reexec) {
			unsigned long rate_milli = (delta_reexec_gate_skip_in_reexec * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"reexec_gate_skip_in_reexec", delta_reexec_gate_skip_in_reexec,
					rate_milli / 1000, rate_milli % 1000, cur_reexec_gate_skip_in_reexec);
		}
		if (delta_reexec_gate_skip_disabled) {
			unsigned long rate_milli = (delta_reexec_gate_skip_disabled * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"reexec_gate_skip_disabled", delta_reexec_gate_skip_disabled,
					rate_milli / 1000, rate_milli % 1000, cur_reexec_gate_skip_disabled);
		}
		if (delta_reexec_gate_skip_mode) {
			unsigned long rate_milli = (delta_reexec_gate_skip_mode * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"reexec_gate_skip_mode", delta_reexec_gate_skip_mode,
					rate_milli / 1000, rate_milli % 1000, cur_reexec_gate_skip_mode);
		}
		if (delta_reexec_gate_skip_chain_mid) {
			unsigned long rate_milli = (delta_reexec_gate_skip_chain_mid * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"reexec_gate_skip_chain_mid", delta_reexec_gate_skip_chain_mid,
					rate_milli / 1000, rate_milli % 1000, cur_reexec_gate_skip_chain_mid);
		}
		if (delta_reexec_gate_skip_no_new_cmp) {
			unsigned long rate_milli = (delta_reexec_gate_skip_no_new_cmp * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"reexec_gate_skip_no_new_cmp", delta_reexec_gate_skip_no_new_cmp,
					rate_milli / 1000, rate_milli % 1000, cur_reexec_gate_skip_no_new_cmp);
		}
		if (delta_reexec_gate_skip_no_pending) {
			unsigned long rate_milli = (delta_reexec_gate_skip_no_pending * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"reexec_gate_skip_no_pending", delta_reexec_gate_skip_no_pending,
					rate_milli / 1000, rate_milli % 1000, cur_reexec_gate_skip_no_pending);
		}
		if (delta_reexec_gate_skip_rate) {
			unsigned long rate_milli = (delta_reexec_gate_skip_rate * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"reexec_gate_skip_rate", delta_reexec_gate_skip_rate,
					rate_milli / 1000, rate_milli % 1000, cur_reexec_gate_skip_rate);
		}
		if (delta_reexec_gate_pass) {
			unsigned long rate_milli = (delta_reexec_gate_pass * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"reexec_gate_pass", delta_reexec_gate_pass,
					rate_milli / 1000, rate_milli % 1000, cur_reexec_gate_pass);
		}
		if (delta_cmp_parent_calls_enabled) {
			unsigned long rate_milli = (delta_cmp_parent_calls_enabled * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_parent_calls_enabled", delta_cmp_parent_calls_enabled,
					rate_milli / 1000, rate_milli % 1000, cur_cmp_parent_calls_enabled);
		}
		if (delta_cmp_parent_calls_control) {
			unsigned long rate_milli = (delta_cmp_parent_calls_control * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_parent_calls_control", delta_cmp_parent_calls_control,
					rate_milli / 1000, rate_milli % 1000, cur_cmp_parent_calls_control);
		}
		if (delta_cmp_parent_new_cmps_enabled) {
			unsigned long rate_milli = (delta_cmp_parent_new_cmps_enabled * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_parent_new_cmps_enabled", delta_cmp_parent_new_cmps_enabled,
					rate_milli / 1000, rate_milli % 1000, cur_cmp_parent_new_cmps_enabled);
		}
		if (delta_cmp_parent_new_cmps_control) {
			unsigned long rate_milli = (delta_cmp_parent_new_cmps_control * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_parent_new_cmps_control", delta_cmp_parent_new_cmps_control,
					rate_milli / 1000, rate_milli % 1000, cur_cmp_parent_new_cmps_control);
		}
		if (any_callsite_delta) {
			static const char * const callsite_names[CMP_HINT_CALLSITE_NR] = {
				[CMP_HINT_CALLSITE_ARG_OP]          = "ARG_OP",
				[CMP_HINT_CALLSITE_ARG_LIST]        = "ARG_LIST",
				[CMP_HINT_CALLSITE_ARG_UNDEFINED]   = "ARG_UNDEFINED",
				[CMP_HINT_CALLSITE_ARG_STRUCT_SIZE] = "ARG_STRUCT_SIZE",
				[CMP_HINT_CALLSITE_STRUCT_FIELD]    = "STRUCT_FIELD",
				[CMP_HINT_CALLSITE_OTHER]           = "OTHER",
			};
			unsigned int cs;

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
		/* SHADOW per-entry feedback scoring counters
		 * ([11-feedback-loop] PHASE 4).  Live pool selection is
		 * uniform here -- these counters record outcomes for a future
		 * A/B-gated live-pick weight to read.  cmp_hint_wins /
		 * cmp_hint_misses are PC-edge only; cmp_hint_cmp_novelty_wins
		 * is the SEPARATE CMP-mode novelty channel (kept out of the
		 * PC-edge score). */
		if (delta_cmp_hints_consumed) {
			unsigned long rate_milli = (delta_cmp_hints_consumed * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hints_consumed", delta_cmp_hints_consumed,
					rate_milli / 1000, rate_milli % 1000, cur_cmp_hints_consumed);
		}
		if (delta_cmp_hint_wins) {
			unsigned long rate_milli = (delta_cmp_hint_wins * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hint_wins", delta_cmp_hint_wins,
					rate_milli / 1000, rate_milli % 1000, cur_cmp_hint_wins);
		}
		if (delta_cmp_hint_misses) {
			unsigned long rate_milli = (delta_cmp_hint_misses * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hint_misses", delta_cmp_hint_misses,
					rate_milli / 1000, rate_milli % 1000, cur_cmp_hint_misses);
		}
		if (delta_cmp_hint_cmp_novelty_wins) {
			unsigned long rate_milli = (delta_cmp_hint_cmp_novelty_wins * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hint_cmp_novelty_wins",
					delta_cmp_hint_cmp_novelty_wins,
					rate_milli / 1000, rate_milli % 1000,
					cur_cmp_hint_cmp_novelty_wins);
		}
		if (delta_cmp_hint_stash_overflow) {
			unsigned long rate_milli = (delta_cmp_hint_stash_overflow * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hint_stash_overflow",
					delta_cmp_hint_stash_overflow,
					rate_milli / 1000, rate_milli % 1000,
					cur_cmp_hint_stash_overflow);
		}
		if (delta_cmp_hint_credit_entry_evicted) {
			unsigned long rate_milli = (delta_cmp_hint_credit_entry_evicted * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_hint_credit_entry_evicted",
					delta_cmp_hint_credit_entry_evicted,
					rate_milli / 1000, rate_milli % 1000,
					cur_cmp_hint_credit_entry_evicted);
		}
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
		if (delta_cmp_recent_inserts) {
			unsigned long rate_milli = (delta_cmp_recent_inserts * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_recent_inserts", delta_cmp_recent_inserts,
					rate_milli / 1000, rate_milli % 1000, cur_cmp_recent_inserts);
		}
		if (delta_cmp_recent_evicts) {
			unsigned long rate_milli = (delta_cmp_recent_evicts * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_recent_evicts", delta_cmp_recent_evicts,
					rate_milli / 1000, rate_milli % 1000, cur_cmp_recent_evicts);
		}
		if (delta_cmp_recent_would_pick) {
			unsigned long rate_milli = (delta_cmp_recent_would_pick * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_recent_would_pick", delta_cmp_recent_would_pick,
					rate_milli / 1000, rate_milli % 1000, cur_cmp_recent_would_pick);
		}
		if (delta_cmp_recent_would_miss) {
			unsigned long rate_milli = (delta_cmp_recent_would_miss * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_recent_would_miss", delta_cmp_recent_would_miss,
					rate_milli / 1000, rate_milli % 1000, cur_cmp_recent_would_miss);
		}
		if (delta_cmp_recent_live_picks) {
			unsigned long rate_milli = (delta_cmp_recent_live_picks * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_recent_live_picks", delta_cmp_recent_live_picks,
					rate_milli / 1000, rate_milli % 1000, cur_cmp_recent_live_picks);
		}
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
		if (delta_cmp_inject_denom_diverged) {
			unsigned long rate_milli = (delta_cmp_inject_denom_diverged * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
					"cmp_inject_denom_diverged",
					delta_cmp_inject_denom_diverged,
					rate_milli / 1000, rate_milli % 1000,
					cur_cmp_inject_denom_diverged);
		}
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
					"remote_adaptive_agree",
					cur_remote_adaptive_agree);
		}
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
		unsigned long delta_hyp_observations = cur_hyp_observations - prev_hyp_observations;
		unsigned long delta_hyp_inserted = cur_hyp_inserted - prev_hyp_inserted;
		unsigned long delta_hyp_pool_full = cur_hyp_pool_full - prev_hyp_pool_full;
		unsigned long delta_hyp_pool_overflow = cur_hyp_pool_overflow - prev_hyp_pool_overflow;
		unsigned long delta_hyp_kind_full = cur_hyp_kind_full - prev_hyp_kind_full;
		unsigned long delta_hyp_consumed = cur_hyp_consumed - prev_hyp_consumed;
		unsigned long delta_hyp_pc_wins = cur_hyp_pc_wins - prev_hyp_pc_wins;
		unsigned long delta_hyp_transition_wins = cur_hyp_transition_wins - prev_hyp_transition_wins;
		unsigned long delta_hyp_cmp_novelty_wins = cur_hyp_cmp_novelty_wins - prev_hyp_cmp_novelty_wins;
		unsigned long delta_hyp_misses = cur_hyp_misses - prev_hyp_misses;
		unsigned long delta_hyp_disabled_skips = cur_hyp_disabled_skips - prev_hyp_disabled_skips;
		unsigned long delta_hyp_corpus_save = cur_hyp_corpus_save - prev_hyp_corpus_save;
		unsigned long delta_hyp_destructive = cur_hyp_destructive - prev_hyp_destructive;
		unsigned long delta_hyp_context_skip = cur_hyp_context_skip - prev_hyp_context_skip;

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

			/* Per-kind census: accepted (inserted_by_kind) vs dropped
			 * at the per-kind sub-cap (kind_full_by_kind).  Surfaces
			 * which hypothesis kind dominates cmp_hyp_kind_full so the
			 * CMP_HYP_PER_KIND cap can be tuned at the right kind. */
			{
				static const char * const kind_labels[CMP_HYP_KIND_NR] = {
					"exact", "range", "boundary", "bitmask",
					"enum_family", "alignment", "length",
					"foreign_value",
				};
				static unsigned long prev_hyp_ins_kind[CMP_HYP_KIND_NR];
				static unsigned long prev_hyp_full_kind[CMP_HYP_KIND_NR];
				unsigned int k;

				for (k = 0; k < CMP_HYP_KIND_NR; k++) {
					unsigned long cur_ins = __atomic_load_n(
						&kcov_shm->cmp_hyp_inserted_by_kind[k],
						__ATOMIC_RELAXED);
					unsigned long cur_full = __atomic_load_n(
						&kcov_shm->cmp_hyp_kind_full_by_kind[k],
						__ATOMIC_RELAXED);

					stats_log_write(
						"  cmp_hyp[%-13s] inserted +%lu (total %lu)  kind_full +%lu (total %lu)\n",
						kind_labels[k],
						cur_ins - prev_hyp_ins_kind[k], cur_ins,
						cur_full - prev_hyp_full_kind[k], cur_full);
					prev_hyp_ins_kind[k] = cur_ins;
					prev_hyp_full_kind[k] = cur_full;
				}
			}

			/* Per-kind census of typed-hypothesis consumes.  Bumped in
			 * lock-step with the scalar cmp_hyp_consumed from
			 * cmp_hyp_credit_consume(); sum across kinds equals
			 * cmp_hyp_consumed modulo concurrent sampling.  Paired
			 * with cmp_hyp_inserted_by_kind this shows, per kind, the
			 * share of insertions the typed consumer is pulling. */
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
						cur_cons - prev_hyp_consumed_kind[k], cur_cons);
					prev_hyp_consumed_kind[k] = cur_cons;
				}
			}
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
	{
		static const char * const kind_labels[CMP_HYP_KIND_NR] = {
			"exact", "range", "boundary", "bitmask",
			"enum_family", "alignment", "length",
			"foreign_value",
		};
		static unsigned long prev_hyp_would_pick_kind[CMP_HYP_KIND_NR];
		static unsigned long prev_hyp_would_miss_kind[CMP_HYP_KIND_NR];
		static unsigned long prev_hyp_would_value_differs;
		unsigned long cur_hyp_would_pick_kind[CMP_HYP_KIND_NR];
		unsigned long cur_hyp_would_miss_kind[CMP_HYP_KIND_NR];
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
			any_would_delta |=
				(cur_hyp_would_pick_kind[k] - prev_hyp_would_pick_kind[k]) |
				(cur_hyp_would_miss_kind[k] - prev_hyp_would_miss_kind[k]);
		}
		cur_hyp_would_value_differs = __atomic_load_n(
			&kcov_shm->cmp_hyp_would_value_differs, __ATOMIC_RELAXED);
		delta_hyp_would_value_differs =
			cur_hyp_would_value_differs - prev_hyp_would_value_differs;
		any_would_delta |= delta_hyp_would_value_differs;

		if (any_would_delta != 0) {
			stats_log_write("KCOV CMP hyp would-pick shadow stats over last %lds:\n",
					elapsed);
			for (k = 0; k < CMP_HYP_KIND_NR; k++) {
				stats_log_write(
					"  cmp_hyp_would[%-13s] pick +%lu (total %lu)  miss +%lu (total %lu)\n",
					kind_labels[k],
					cur_hyp_would_pick_kind[k] - prev_hyp_would_pick_kind[k],
					cur_hyp_would_pick_kind[k],
					cur_hyp_would_miss_kind[k] - prev_hyp_would_miss_kind[k],
					cur_hyp_would_miss_kind[k]);
			}
			stats_log_write("  %-32s +%lu  (total %lu)\n",
					"cmp_hyp_would_value_differs",
					delta_hyp_would_value_differs,
					cur_hyp_would_value_differs);
		}

		for (k = 0; k < CMP_HYP_KIND_NR; k++) {
			prev_hyp_would_pick_kind[k] = cur_hyp_would_pick_kind[k];
			prev_hyp_would_miss_kind[k] = cur_hyp_would_miss_kind[k];
		}
		prev_hyp_would_value_differs = cur_hyp_would_value_differs;
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
			cur_hyp_live_injected - prev_hyp_live_injected;
		unsigned long delta_hyp_live_gate_passed =
			cur_hyp_live_gate_passed - prev_hyp_live_gate_passed;
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
				cur_hyp_live_injected_kind[k] -
					prev_hyp_live_injected_kind[k],
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
	{
		static const char * const reason_labels[CMP_HYP_LIVE_INJECT_REASON_NR] = {
			"not_plateau",
			"dice_miss",
			"no_match",
			"derive_fail",
			"accept_reject",
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
				(cur_hyp_live_inject_reason[r] -
				 prev_hyp_live_inject_reason[r]);
		}

		if (any_delta != 0) {
			stats_log_write("KCOV CMP live-inject gate-close reasons over last %lds:\n",
					elapsed);
			for (r = 0; r < CMP_HYP_LIVE_INJECT_REASON_NR; r++) {
				stats_log_write(
					"  cmp_hyp_live_inject_reason[%-13s] +%lu (total %lu)\n",
					reason_labels[r],
					cur_hyp_live_inject_reason[r] -
						prev_hyp_live_inject_reason[r],
					cur_hyp_live_inject_reason[r]);
			}
		}

		for (r = 0; r < CMP_HYP_LIVE_INJECT_REASON_NR; r++)
			prev_hyp_live_inject_reason[r] = cur_hyp_live_inject_reason[r];
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
				(cur_hyp_would_promote_kind[k] - prev_hyp_would_promote_kind[k]) |
				(cur_hyp_would_demote_kind[k] - prev_hyp_would_demote_kind[k]);
		}

		if (any_delta != 0) {
			stats_log_write("KCOV CMP hyp would-promote/demote shadow stats over last %lds:\n",
					elapsed);
			for (k = 0; k < CMP_HYP_KIND_NR; k++) {
				stats_log_write(
					"  cmp_hyp_would[%-13s] promote +%lu (total %lu)  demote +%lu (total %lu)\n",
					kind_labels[k],
					cur_hyp_would_promote_kind[k] - prev_hyp_would_promote_kind[k],
					cur_hyp_would_promote_kind[k],
					cur_hyp_would_demote_kind[k] - prev_hyp_would_demote_kind[k],
					cur_hyp_would_demote_kind[k]);
			}
		}

		for (k = 0; k < CMP_HYP_KIND_NR; k++) {
			prev_hyp_would_promote_kind[k] = cur_hyp_would_promote_kind[k];
			prev_hyp_would_demote_kind[k] = cur_hyp_would_demote_kind[k];
		}
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
	if (cmp_hints_shm != NULL) {
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

		delta_hyp_corpus_save_wins = cur_hyp_corpus_save_wins - prev_hyp_corpus_save_wins;
		delta_hyp_destructive_skips = cur_hyp_destructive_skips - prev_hyp_destructive_skips;
		delta_hyp_context_skips = cur_hyp_context_skips - prev_hyp_context_skips;

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

	pc_kids  = __atomic_load_n(&kcov_shm->pc_mode_children,  __ATOMIC_RELAXED);
	cmp_kids = __atomic_load_n(&kcov_shm->cmp_mode_children, __ATOMIC_RELAXED);

	if ((pc_kids | cmp_kids) != 0) {
		stats_log_write("KCOV CMP modes (cumulative):\n");
		stats_log_write("  pc_mode_children=%u cmp_mode_children=%u\n",
				pc_kids, cmp_kids);
	}

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

	{
		char pc_buf[256];
		int np;

		np = kcov_pc_diag_format(pc_buf, sizeof(pc_buf));
		if (np > 0) {
			stats_log_write("KCOV PC DIAG (first-failure-wins errnos + retry counters, cumulative):\n");
			stats_log_write(" %s\n", pc_buf);
		}
	}

	kcov_cmp_observability_block_render(elapsed);
	kcov_redqueen_observability_block_render(elapsed);
	kcov_cmp_oldpool_vs_shadow_block_render(elapsed);
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
		for (cs = 0; cs < CMP_HINT_CALLSITE_NR; cs++)
			prev_cmp_hint_callsite[cs] = cur_cmp_hint_callsite[cs];
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

void __cold minicorpus_mut_attrib_canary_check(void)
{
	static time_t last_check_mono;
	static bool first_witness_emitted;
	struct timespec ts;
	time_t now;
	unsigned int i;

	if (minicorpus_shm == NULL)
		return;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	now = ts.tv_sec;

	/* First call seeds the gate without scanning -- mirrors the
	 * kcov_bitmap_canary_check() first-call seed.  Subsequent calls
	 * scan no more than once per MUT_ATTRIB_CANARY_INTERVAL_SEC, with
	 * the timestamp stamped from CLOCK_MONOTONIC so a backward NTP
	 * step cannot suppress an otherwise-due check. */
	if (last_check_mono == 0) {
		last_check_mono = now;
		return;
	}
	if ((unsigned long)(now - last_check_mono) <
	    MUT_ATTRIB_CANARY_INTERVAL_SEC)
		return;
	last_check_mono = now;

	/* Sample trials BEFORE wins for each pair so any in-flight
	 * producer that bumps both between the two loads biases the
	 * observed (wins - trials) DOWNWARD (the matching trial bump is
	 * already in the trials sample, the matching win bump may not
	 * be in the wins sample yet) and cannot manufacture a false
	 * inversion.  The opposite order is the one with the per-CPU
	 * skew window, hence the load order. */
	for (i = 0; i < MUT_NUM_OPS; i++) {
		unsigned long t  = __atomic_load_n(&minicorpus_shm->mut_trials[i],
						   __ATOMIC_RELAXED);
		unsigned long w  = __atomic_load_n(&minicorpus_shm->mut_wins[i],
						   __ATOMIC_RELAXED);
		unsigned long st = __atomic_load_n(
			&minicorpus_shm->mut_structured_trials[i],
			__ATOMIC_RELAXED);
		unsigned long sw = __atomic_load_n(
			&minicorpus_shm->mut_structured_wins[i],
			__ATOMIC_RELAXED);

		if (w > t + MUT_ATTRIB_INVERSION_TOL) {
			__atomic_fetch_add(&shm->stats.mut_attrib_inversion_caught,
					   1UL, __ATOMIC_RELAXED);
			if (!first_witness_emitted) {
				stats_log_write("CANARY: minicorpus mut_wins[%u]=%lu > mut_trials[%u]=%lu (tol=%lu, op=%s) -- counter word scribbled\n",
						i, w, i, t,
						MUT_ATTRIB_INVERSION_TOL,
						op_names[i]);
				first_witness_emitted = true;
			}
		}

		if (sw > st + MUT_ATTRIB_INVERSION_TOL) {
			__atomic_fetch_add(&shm->stats.mut_attrib_inversion_caught,
					   1UL, __ATOMIC_RELAXED);
			if (!first_witness_emitted) {
				stats_log_write("CANARY: minicorpus mut_structured_wins[%u]=%lu > mut_structured_trials[%u]=%lu (tol=%lu, op=%s) -- counter word scribbled\n",
						i, sw, i, st,
						MUT_ATTRIB_INVERSION_TOL,
						op_names[i]);
				first_witness_emitted = true;
			}
		}
	}
}

/* Per-syscall KCOV diagnostic blocks.  One block per counter in
 * struct kcov_per_syscall_diag, emitted as a top-20-non-zero list
 * sorted descending by counter value.  The block is skipped entirely
 * when no (nr, arch) slot has a non-zero value -- silence is the
 * diagnostic signal for the truncation/overflow counters in a
 * well-sized run, and an empty top-20 stanza would only be noise.
 *
 * Counter ordering across the dump is alphabetical by counter name.
 * Keep it that way: future additions to kcov_per_syscall_diag slot
 * in deterministically and log-grep over historical dumps stays
 * stable.
 */

enum kcov_diag_counter {
	KCOV_DIAG_BUCKET_BITS_REAL,
	KCOV_DIAG_CMP_TRACE_TRUNCATED,
	KCOV_DIAG_DEDUP_PROBE_OVERFLOW,
	KCOV_DIAG_DISTINCT_PCS,
	KCOV_DIAG_MAX_TRACE_SIZE,
	KCOV_DIAG_TRACE_TRUNCATED,
};

#define KCOV_DIAG_TOPN	20

struct kcov_diag_entry {
	unsigned int nr;
	bool do32;
	uint64_t value;
};

static uint64_t kcov_diag_load(const struct kcov_per_syscall_diag *d,
			       enum kcov_diag_counter c)
{
	switch (c) {
	case KCOV_DIAG_BUCKET_BITS_REAL:
		return __atomic_load_n(&d->bucket_bits_real, __ATOMIC_RELAXED);
	case KCOV_DIAG_CMP_TRACE_TRUNCATED:
		return __atomic_load_n(&d->cmp_trace_truncated, __ATOMIC_RELAXED);
	case KCOV_DIAG_DEDUP_PROBE_OVERFLOW:
		return __atomic_load_n(&d->dedup_probe_overflow, __ATOMIC_RELAXED);
	case KCOV_DIAG_DISTINCT_PCS:
		return __atomic_load_n(&d->distinct_pcs, __ATOMIC_RELAXED);
	case KCOV_DIAG_MAX_TRACE_SIZE:
		return __atomic_load_n(&d->max_trace_size, __ATOMIC_RELAXED);
	case KCOV_DIAG_TRACE_TRUNCATED:
		return __atomic_load_n(&d->trace_truncated, __ATOMIC_RELAXED);
	}
	return 0;
}

static void kcov_diag_emit_block(const char *counter_name,
				 enum kcov_diag_counter counter)
{
	struct kcov_diag_entry top[KCOV_DIAG_TOPN];
	unsigned int top_count = 0;
	unsigned int nr_per_arch[2];
	unsigned int arch, i;
	int j;

	/* Mirror the arch-dim scan bounds used by the existing per-syscall
	 * top-N blocks: under biarch iterate both tables, under uniarch
	 * only the single active table.  do32=true rows are always zero in
	 * uniarch builds and the (skipped) arch=1 column drops out
	 * naturally. */
	if (biarch) {
		nr_per_arch[0] = max_nr_64bit_syscalls;
		nr_per_arch[1] = max_nr_32bit_syscalls;
	} else {
		nr_per_arch[0] = max_nr_syscalls;
		nr_per_arch[1] = 0;
	}
	for (arch = 0; arch < 2; arch++)
		if (nr_per_arch[arch] > MAX_NR_SYSCALL)
			nr_per_arch[arch] = MAX_NR_SYSCALL;

	for (arch = 0; arch < 2; arch++) {
		bool do32 = (arch == 1);

		for (i = 0; i < nr_per_arch[arch]; i++) {
			uint64_t value = kcov_diag_load(
				&kcov_shm->per_syscall_diag[i][do32 ? 1 : 0],
				counter);

			if (value == 0)
				continue;

			/* Insertion sort, descending by value, capped at
			 * KCOV_DIAG_TOPN -- same shape as the sibling
			 * top-edges block above. */
			for (j = (int)top_count;
			     j > 0 && value > top[j - 1].value; j--) {
				if (j < KCOV_DIAG_TOPN)
					top[j] = top[j - 1];
			}
			if (j < KCOV_DIAG_TOPN) {
				top[j].nr = i;
				top[j].do32 = do32;
				top[j].value = value;
				if (top_count < KCOV_DIAG_TOPN)
					top_count++;
			}
		}
	}

	if (top_count == 0)
		return;

	output(0, "Top syscalls by %s:\n", counter_name);
	for (j = 0; j < (int)top_count; j++) {
		const char *name = print_syscall_name(top[j].nr, top[j].do32);

		output(0, "  nr=%u (%s) [arch=%s] %" PRIu64 "\n",
		       top[j].nr, name,
		       top[j].do32 ? "32" : "64",
		       top[j].value);
	}
}

/* combined top-N table joining
 * per-syscall trace_truncated + cmp_trace_truncated + max_trace_size
 * (with its share of KCOV_TRACE_SIZE) on the same row, plus a single
 * summary line for dedup-probe-overflow.
 *
 * Sibling kcov_diag_emit_block calls already rank each counter on its
 * own; that flattens the cross-counter signal -- a syscall whose trace
 * mostly saturates without an outright truncation event drops off the
 * trace_truncated block, and one whose CMP buffer truncates appears in
 * a separate stanza from the trace one.  This combined view ranks by
 * max(trace_truncated, max_trace_size) so saturation-without-trunc and
 * trunc-with-modest-max both surface, and prints the CMP counterpart in
 * the same row -- the data needed to decide between a global
 * --kcov-trace-size knob and a targeted large-trace child pool
 * (buffer knob).  Diagnostic only; no collection, buffer, or
 * reward path is touched.
 */
#define KCOV_DIAG_TRUNC_TOPN	10

struct kcov_diag_trunc_entry {
	unsigned int nr;
	bool do32;
	uint64_t trace_truncated;
	uint64_t cmp_trace_truncated;
	uint64_t max_trace_size;
	/* per_syscall_calls[] and per_syscall_edges[] are indexed by nr
	 * only, not by arch; under biarch both rows for the same nr show
	 * the same denominator.  The ratio still answers "what share of
	 * this syscall's calls produced an arch-N trunc" / "how many
	 * edge-winning calls landed for each truncation on this syscall". */
	uint64_t calls;
	uint64_t edge_wins;
	uint64_t rank;
};

static void kcov_diag_emit_truncation_topn(void)
{
	struct kcov_diag_trunc_entry top[KCOV_DIAG_TRUNC_TOPN];
	unsigned int top_count = 0;
	unsigned int nr_per_arch[2];
	unsigned int arch, i;
	int j;
	uint64_t dedup_per_syscall_sum = 0;
	uint64_t dedup_global;
	unsigned int dedup_syscall_count = 0;

	if (biarch) {
		nr_per_arch[0] = max_nr_64bit_syscalls;
		nr_per_arch[1] = max_nr_32bit_syscalls;
	} else {
		nr_per_arch[0] = max_nr_syscalls;
		nr_per_arch[1] = 0;
	}
	for (arch = 0; arch < 2; arch++)
		if (nr_per_arch[arch] > MAX_NR_SYSCALL)
			nr_per_arch[arch] = MAX_NR_SYSCALL;

	for (arch = 0; arch < 2; arch++) {
		bool do32 = (arch == 1);

		for (i = 0; i < nr_per_arch[arch]; i++) {
			const struct kcov_per_syscall_diag *d =
				&kcov_shm->per_syscall_diag[i][do32 ? 1 : 0];
			uint64_t tt = __atomic_load_n(&d->trace_truncated,
						      __ATOMIC_RELAXED);
			uint64_t ct = __atomic_load_n(&d->cmp_trace_truncated,
						      __ATOMIC_RELAXED);
			uint64_t mt = __atomic_load_n(&d->max_trace_size,
						      __ATOMIC_RELAXED);
			uint64_t dpo = __atomic_load_n(&d->dedup_probe_overflow,
						       __ATOMIC_RELAXED);
			uint64_t calls = __atomic_load_n(
				&kcov_shm->per_syscall_calls[i],
				__ATOMIC_RELAXED);
			uint64_t ew = __atomic_load_n(
				&kcov_shm->per_syscall_edges[i],
				__ATOMIC_RELAXED);
			uint64_t rank;

			if (dpo > 0) {
				dedup_per_syscall_sum += dpo;
				dedup_syscall_count++;
			}

			rank = (tt > mt) ? tt : mt;
			if (rank == 0 && ct == 0)
				continue;
			if (rank == 0)
				rank = ct;

			for (j = (int)top_count;
			     j > 0 && rank > top[j - 1].rank; j--) {
				if (j < KCOV_DIAG_TRUNC_TOPN)
					top[j] = top[j - 1];
			}
			if (j < KCOV_DIAG_TRUNC_TOPN) {
				top[j].nr = i;
				top[j].do32 = do32;
				top[j].trace_truncated = tt;
				top[j].cmp_trace_truncated = ct;
				top[j].max_trace_size = mt;
				top[j].calls = calls;
				top[j].edge_wins = ew;
				top[j].rank = rank;
				if (top_count < KCOV_DIAG_TRUNC_TOPN)
					top_count++;
			}
		}
	}

	if (top_count > 0) {
		output(0, "Top syscalls by trace truncation / max trace (kcov_trace_size=%u longs):\n",
		       kcov_trace_size);
		output(0, "  %5s %-24s %-4s %14s %14s %14s %7s %8s %8s\n",
		       "nr", "name", "arch",
		       "trace_trunc", "cmp_trace_tr", "max_trace",
		       "pct_max", "tt/call", "ew/tt");
		for (j = 0; j < (int)top_count; j++) {
			const char *name = print_syscall_name(top[j].nr,
							      top[j].do32);
			unsigned int pct10 = (unsigned int)
				((top[j].max_trace_size * 1000ULL) /
				 (uint64_t)kcov_trace_size);
			char tt_call_str[32];
			char ew_tt_str[32];

			if (top[j].calls > 0) {
				uint64_t p = (top[j].trace_truncated * 1000ULL) /
					     top[j].calls;
				snprintf(tt_call_str, sizeof(tt_call_str),
					 "%5" PRIu64 ".%" PRIu64 "%%",
					 p / 10, p % 10);
			} else {
				snprintf(tt_call_str, sizeof(tt_call_str),
					 "%8s", "-");
			}
			if (top[j].trace_truncated > 0) {
				uint64_t p = (top[j].edge_wins * 1000ULL) /
					     top[j].trace_truncated;
				snprintf(ew_tt_str, sizeof(ew_tt_str),
					 "%5" PRIu64 ".%" PRIu64 "%%",
					 p / 10, p % 10);
			} else {
				snprintf(ew_tt_str, sizeof(ew_tt_str),
					 "%8s", "-");
			}

			output(0, "  %5u %-24s %-4s %14" PRIu64
				  " %14" PRIu64 " %14" PRIu64
				  " %4u.%u%% %8s %8s\n",
			       top[j].nr, name,
			       top[j].do32 ? "32" : "64",
			       top[j].trace_truncated,
			       top[j].cmp_trace_truncated,
			       top[j].max_trace_size,
			       pct10 / 10, pct10 % 10,
			       tt_call_str, ew_tt_str);
		}
	}

	dedup_global = __atomic_load_n(&kcov_shm->dedup_probe_overflow,
				       __ATOMIC_RELAXED);
	if (dedup_global > 0 || dedup_per_syscall_sum > 0) {
		output(0, "kcov dedup probe overflow: global=%" PRIu64
			  " per_syscall_sum=%" PRIu64
			  " syscalls_affected=%u\n",
		       dedup_global, dedup_per_syscall_sum,
		       dedup_syscall_count);
	}
}

/* --------------------------------------------------------------------
 * Run-identity block: provenance + post-warm-load start baseline +
 * shutdown deltas.  Closes the stale-cache-key trap from the 2026-06-14
 * triage where comparing two final cache snapshots made a fully
 * productive cold run look like zero growth (the warm cache had been
 * silently reused under a stale key).  The own-start delta is immune
 * to that: it is the work this process actually did, regardless of
 * what the carrier looked like before the run started.
 * -------------------------------------------------------------------- */

struct run_start_baseline {
	bool captured;
	time_t monotonic_at_start;
	unsigned long edges_found;
	unsigned long distinct_edges;
	unsigned long edges_warm_loaded;
	unsigned long distinct_edges_warm_loaded;
	unsigned long corpus_entries;
	/* Snapshot of the persisted cmp-hints pool taken AFTER the loader
	 * has populated cmp_hints_shm but BEFORE the fuzz loop starts.
	 * The carrier warm/cold classification has to read this -- not the
	 * runtime cmp_records_collected counter, which is zero at snapshot
	 * time and would label a warm-loaded run "cold". */
	unsigned long cmp_hints_loaded_values;
	unsigned long cmp_hints_loaded_syscalls;
};

static struct run_start_baseline run_start;

/* CLOCK_MONOTONIC second counter -- duplicate of child-canary.c's
 * file-static helper (kept private to avoid exposing it through a
 * widely-included header for two callers).  Wall-clock-skew-immune,
 * so a negative duration cannot trip a spurious panic on an NTP
 * step. */
static time_t runid_monotonic_seconds(void)
{
	struct timespec ts;

	(void)clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec;
}

/* Sum every per-syscall ring's entry count to get the parent's view
 * of total corpus size.  Reads each ring's count with __ATOMIC_RELAXED
 * since the snapshot is observability-only -- a torn read against a
 * concurrent writer at most miscounts by one entry per syscall, well
 * inside the noise floor of a "did this run grow the corpus" check.
 *
 * Each per-ring count is clamped to CORPUS_RING_SIZE before contributing
 * to the sum, matching the picker (minicorpus.c) and the snapshot
 * walker.  Both save paths (in-run minicorpus_save_with_reason and the
 * on-disk loader) cap count at CORPUS_RING_SIZE before publishing, so
 * count > CORPUS_RING_SIZE is structurally impossible through the
 * documented writer flow -- a value above the cap is a zero-false-
 * positive signal that the ring's count word has been scribbled by a
 * sibling wild write.  Without the clamp a single garbage count word
 * inflated the headline corpus_entries figure into the millions and
 * masked the underlying corruption.  On detection, bump the per-event
 * counter and (once per run) emit a first-witness line naming the ring
 * nr and the unclamped count value so the next triage pass can
 * attribute the scribbler. */
static unsigned long runid_corpus_entries_total(void)
{
	static bool overcap_warned;
	unsigned long total = 0;
	unsigned int i;

	if (minicorpus_shm == NULL)
		return 0;

	for (i = 0; i < MAX_NR_SYSCALL; i++) {
		unsigned int count = __atomic_load_n(
			&minicorpus_shm->rings[i].count, __ATOMIC_RELAXED);

		if (unlikely(count > CORPUS_RING_SIZE)) {
			__atomic_add_fetch(
				&shm->stats.corpus_count_overcap_caught,
				1UL, __ATOMIC_RELAXED);
			if (!overcap_warned) {
				overcap_warned = true;
				output(0,
				       "[main] WARNING corpus_count_overcap "
				       "nr=%u count=%u clamped_to=%u "
				       "(first witness)\n",
				       i, count, CORPUS_RING_SIZE);
			}
			count = CORPUS_RING_SIZE;
		}
		total += count;
	}
	return total;
}

/* Render the 32-byte kallsyms fingerprint as a short hex prefix
 * suitable for an at-a-glance identity line; truncated to 16 hex
 * chars (8 bytes of entropy) is far past what a human eyeballs but
 * short enough to fit on one line beside the other identity fields.
 * Returns true iff the fingerprint was available -- a v5+ kcov path
 * that cannot resolve _text leaves it unavailable on this run. */
static bool runid_kallsyms_hex(char *out, size_t outlen)
{
	uint8_t fp[32];
	size_t i, want;

	if (outlen < 17)
		return false;
	if (!kcov_get_kernel_fp(fp))
		return false;
	want = 8;
	for (i = 0; i < want; i++)
		snprintf(out + (i * 2), outlen - (i * 2), "%02x", fp[i]);
	out[want * 2] = '\0';
	return true;
}

/* Read /proc/sys/kernel/random/boot_id into a NUL-terminated string
 * (the on-disk value is a 36-char UUID followed by a newline).
 * Returns true on success.  The boot_id is no longer used as a
 * cache-key guard (KCOV bitmap moved to canonicalised PCs at file
 * version 5), but it remains the single most useful "did the kernel
 * reboot between these two runs" anchor for the run-identity block. */
static bool runid_read_boot_id(char *out, size_t outlen)
{
	int fd;
	ssize_t n;

	if (outlen < 37)
		return false;

	fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
	if (fd < 0)
		return false;
	n = read(fd, out, outlen - 1);
	close(fd);
	if (n <= 0)
		return false;
	out[n] = '\0';
	/* Strip the trailing newline so the value renders inline. */
	if (n > 0 && out[n - 1] == '\n')
		out[n - 1] = '\0';
	return true;
}

void __cold stats_runid_snapshot_start(void)
{
	if (run_start.captured)
		return;

	run_start.monotonic_at_start = runid_monotonic_seconds();
	if (kcov_shm != NULL) {
		run_start.edges_found = __atomic_load_n(
			&kcov_shm->edges_found, __ATOMIC_RELAXED);
		run_start.distinct_edges = __atomic_load_n(
			&kcov_shm->distinct_edges, __ATOMIC_RELAXED);
		run_start.edges_warm_loaded = __atomic_load_n(
			&kcov_shm->edges_warm_loaded, __ATOMIC_RELAXED);
		run_start.distinct_edges_warm_loaded = __atomic_load_n(
			&kcov_shm->distinct_edges_warm_loaded,
			__ATOMIC_RELAXED);
	}
	run_start.corpus_entries = runid_corpus_entries_total();

	/* Sum the persisted cmp-hints pool as it stands right after the
	 * loader has finished -- this is the authoritative "did a prior
	 * run hand us a warm cache" answer for the cmp_hints carrier.
	 * Per-arch slots count individually, matching the JSON / text
	 * pool histograms emitted elsewhere in this file. */
	run_start.cmp_hints_loaded_values = 0;
	run_start.cmp_hints_loaded_syscalls = 0;
	if (cmp_hints_shm != NULL) {
		unsigned int i, a;

		for (i = 0; i < MAX_NR_SYSCALL; i++) {
			for (a = 0; a < 2; a++) {
				unsigned int n = cmp_hints_pool_safe_count(
					&cmp_hints_shm->pools[i][a]);

				if (n > 0) {
					run_start.cmp_hints_loaded_values += n;
					run_start.cmp_hints_loaded_syscalls++;
				}
			}
		}
	}

	run_start.captured = true;
}

static const char *runid_warm_state(bool gated_off, unsigned long start_value)
{
	if (gated_off)
		return "disabled";
	return start_value > 0 ? "warm" : "cold";
}

static const char *runid_transition_coverage_name(void)
{
	switch (kcov_transition_coverage_mode) {
	case KCOV_TRANSITION_COVERAGE_OFF:    return "off";
	case KCOV_TRANSITION_COVERAGE_SHADOW: return "shadow";
	}
	return "?";
}

static const char *runid_transition_reward_name(void)
{
	switch (kcov_transition_reward_mode) {
	case KCOV_TRANSITION_REWARD_OFF:         return "off";
	case KCOV_TRANSITION_REWARD_SHADOW_ONLY: return "shadow_only";
	case KCOV_TRANSITION_REWARD_COMBINED:    return "combined";
	}
	return "?";
}

void __cold stats_runid_render(void)
{
	unsigned long end_edges = 0;
	unsigned long end_distinct = 0;
	unsigned long end_corpus = 0;
	unsigned long edges_delta = 0;
	unsigned long distinct_delta = 0;
	unsigned long corpus_delta = 0;
	time_t now = runid_monotonic_seconds();
	long elapsed = 0;
	struct utsname uts;
	bool have_uname;
	char kallsyms_hex[17] = "(unavailable)";
	char boot_id[64] = "(unavailable)";
	const char *kcov_state;
	const char *corpus_state;
	const char *cmp_state;

	have_uname = (uname(&uts) == 0);
	(void)runid_kallsyms_hex(kallsyms_hex, sizeof(kallsyms_hex));
	(void)runid_read_boot_id(boot_id, sizeof(boot_id));

	if (kcov_shm != NULL) {
		end_edges = __atomic_load_n(&kcov_shm->edges_found,
					    __ATOMIC_RELAXED);
		end_distinct = __atomic_load_n(&kcov_shm->distinct_edges,
					       __ATOMIC_RELAXED);
	}
	end_corpus = runid_corpus_entries_total();

	output(0, "\n");
	output(0, "===== run identity =====\n");

	/* Identity / provenance triple: the three values that together
	 * decide whether a persisted warm cache will load on the next run.
	 * Cache-key drift across runs is the failure mode the 2026-06-14
	 * triage chased; printing the triple at shutdown makes the drift
	 * visible without needing the loader's verbose path. */
	output(0, "run-id provenance: build=%s kernel=%s%s%s kallsyms=%s "
		  "boot_id=%s asan=%s\n",
	       GIT_HASH,
	       have_uname ? uts.release : "(uname-failed)",
	       have_uname ? " " : "",
	       have_uname ? uts.version : "",
	       kallsyms_hex,
	       boot_id,
#ifdef __SANITIZE_ADDRESS__
	       "on"
#else
	       "off"
#endif
	       );

	/* Cohort + the parent-side knobs that change selection at the
	 * coarse level.  Per-child A/B stamps (redqueen_enabled,
	 * cmp_hint_inject_arm_b, ...) are not parent-visible globals and
	 * are intentionally omitted -- they belong in the per-child
	 * attribution dumps, not this identity line. */
	output(0, "run-id cohort: children=%u alt_op_children=%u "
		  "canary_slots=%u canary_window_iters=%u canary_queue=%s "
		  "transition_coverage=%s transition_reward=%s\n",
	       max_children, alt_op_children,
	       canary_slots, canary_window_iters,
	       canary_queue_disabled ? "off" : "on",
	       runid_transition_coverage_name(),
	       runid_transition_reward_name());

	/* Cold/warm classification of each cross-run carrier.  "disabled"
	 * means the --no-*-warm-start opt-out is in effect (no save and no
	 * load this run); "warm" means the carrier had a non-zero starting
	 * baseline at snapshot time (a prior run's state survived into
	 * this one); "cold" means the carrier started empty (genuine
	 * first-run-on-this-cache-key). */
	kcov_state = runid_warm_state(no_kcov_warm_start,
				      run_start.edges_warm_loaded);
	corpus_state = runid_warm_state(no_warm_start,
					run_start.corpus_entries);
	/* Classify cmp_hints from the post-load pool snapshot, not from
	 * the runtime cmp_records_collected counter -- the latter is zero
	 * at start-snapshot time and would mislabel a warm-loaded run
	 * (e.g. 4636 entries / 290 syscalls reloaded by the persistence
	 * layer) as "cold". */
	cmp_state = runid_warm_state(no_cmp_hints_warm_start,
				     run_start.cmp_hints_loaded_values);
	output(0, "run-id carriers: kcov=%s minicorpus=%s cmp_hints=%s "
		  "kcov_warm_loaded_edges=%lu kcov_warm_loaded_distinct=%lu "
		  "cmp_hints_loaded_values=%lu cmp_hints_loaded_syscalls=%lu\n",
	       kcov_state, corpus_state, cmp_state,
	       run_start.edges_warm_loaded,
	       run_start.distinct_edges_warm_loaded,
	       run_start.cmp_hints_loaded_values,
	       run_start.cmp_hints_loaded_syscalls);

	if (!run_start.captured) {
		/* Reached the shutdown render without ever taking the
		 * start snapshot (early-exit dump path or a regression
		 * in the main_loop hook).  Print the end values alone so
		 * the operator still has the identity block, but suppress
		 * the deltas rather than emit a misleading "start=0
		 * end=N delta=N" line that would re-create the exact
		 * 2026-06-14 trap (mistaking a known-prior carrier for
		 * coverage this run discovered). */
		output(0, "run-id baseline: NOT CAPTURED -- deltas suppressed; "
			  "end edges_found=%lu distinct_edges=%lu "
			  "corpus_entries=%lu\n",
		       end_edges, end_distinct, end_corpus);
		output(0, "===== end run identity =====\n");
		return;
	}

	if (end_edges >= run_start.edges_found)
		edges_delta = end_edges - run_start.edges_found;
	if (end_distinct >= run_start.distinct_edges)
		distinct_delta = end_distinct - run_start.distinct_edges;
	if (end_corpus >= run_start.corpus_entries)
		corpus_delta = end_corpus - run_start.corpus_entries;
	if (now >= run_start.monotonic_at_start)
		elapsed = (long)(now - run_start.monotonic_at_start);

	output(0, "run-id baseline: start edges_found=%lu distinct_edges=%lu "
		  "corpus_entries=%lu\n",
	       run_start.edges_found, run_start.distinct_edges,
	       run_start.corpus_entries);
	output(0, "run-id shutdown: end   edges_found=%lu distinct_edges=%lu "
		  "corpus_entries=%lu elapsed=%lds\n",
	       end_edges, end_distinct, end_corpus, elapsed);
	output(0, "run-id own-start deltas: edges_found=+%lu "
		  "distinct_edges=+%lu corpus_entries=+%lu\n",
	       edges_delta, distinct_delta, corpus_delta);

	output(0, "===== end run identity =====\n");
}

static void dump_stats_runtime_header(void)
{
	time_t start = shm->start_time;
	time_t now = time(NULL);
	long elapsed = (start > 0 && now >= start) ? (long)(now - start) : 0;
	struct tm tm;
	char ts[32];

	if (start > 0 && localtime_r(&start, &tm) != NULL &&
	    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm) > 0) {
		output(1, "runtime: %ldh%02ldm%02lds (since %s)\n",
		       elapsed / 3600,
		       (elapsed / 60) % 60,
		       elapsed % 60,
		       ts);
	}
}

static void dump_stats_per_syscall_tables(void)
{
	unsigned int i;

	if (biarch == true) {
		output(0, "32bit:\n");
		for_each_32bit_syscall(i) {
			dump_entry(syscalls_32bit, i);
		}
		output(0, "64bit:\n");
		for_each_64bit_syscall(i) {
			dump_entry(syscalls_64bit, i);
		}
	} else {
		for_each_syscall(i) {
			dump_entry(syscalls, i);
		}
	}

	stats_emit_header();
}

/*
 * SHADOW-ONLY shutdown attribution for the per-syscall stuck-child
 * accounting (see the comment on shm->stats.syscall_wedge_count[]
 * in include/stats.h).  Renders a
 * top-N row sorted by cumulative wedged microseconds, with the per-
 * syscall event count rendered alongside so the operator can
 * distinguish "one rare syscall that wedges for ages" from "many
 * short wedges in a hot syscall".  Read-only: no live-path decision
 * is taken from either array yet; this dump exists so the next
 * iteration has data to choose throttle / isolation targets from.
 *
 * Biarch table choice follows top_syscalls_periodic_dump() exactly --
 * only the 64-bit table is iterated under biarch because 32-bit nrs
 * collide with 64-bit ones in the same index space and would shadow
 * them in the display.  Empty-block gate: if no wedge has ever been
 * accounted (count_total == 0), the block is skipped entirely
 * rather than emit an all-zero header.
 */
#define WEDGE_TOPN	10

static void dump_stats_top_wedging_syscalls(void)
{
	struct wedge_top_entry {
		unsigned int nr;
		unsigned long count;
		unsigned long long total_us;
	} top[WEDGE_TOPN];
	unsigned int top_count = 0;
	unsigned long count_total = 0;
	unsigned long long us_total = 0;
	unsigned int nr_to_scan;
	bool is32bit;
	unsigned int i;
	int j;

	if (biarch) {
		nr_to_scan = max_nr_64bit_syscalls;
		is32bit = false;
	} else {
		nr_to_scan = max_nr_syscalls;
		is32bit = false;
	}
	if (nr_to_scan > MAX_NR_SYSCALL)
		nr_to_scan = MAX_NR_SYSCALL;

	for (i = 0; i < nr_to_scan; i++) {
		unsigned long c = __atomic_load_n(
			&shm->stats.syscall_wedge_count[i],
			__ATOMIC_RELAXED);
		unsigned long long u = __atomic_load_n(
			&shm->stats.syscall_wedge_total_us[i],
			__ATOMIC_RELAXED);

		if (c == 0 && u == 0)
			continue;

		count_total += c;
		us_total += u;

		/* Insertion sort, descending by total_us, capped at WEDGE_TOPN.
		 * Ties on total_us are broken by event count so a hot syscall
		 * with many quick wedges ranks above a single still-pending
		 * wedge whose duration matches by accident. */
		for (j = (int)top_count;
		     j > 0 && (u > top[j - 1].total_us ||
			       (u == top[j - 1].total_us &&
				c > top[j - 1].count));
		     j--) {
			if (j < WEDGE_TOPN)
				top[j] = top[j - 1];
		}
		if (j < WEDGE_TOPN) {
			top[j].nr = i;
			top[j].count = c;
			top[j].total_us = u;
			if (top_count < WEDGE_TOPN)
				top_count++;
		}
	}

	if (count_total == 0 && us_total == 0)
		return;

	output(0, "Top %u most-wedging syscalls (cumulative; %lu events, "
		"%llu.%03llu s wedged total):\n",
		top_count, count_total,
		us_total / 1000000ULL, (us_total / 1000ULL) % 1000ULL);

	for (j = 0; j < (int)top_count; j++) {
		const char *name = print_syscall_name(top[j].nr, is32bit);
		unsigned long long s = top[j].total_us / 1000000ULL;
		unsigned long long ms = (top[j].total_us / 1000ULL) % 1000ULL;
		unsigned long long avg_us = top[j].count > 0 ?
			(top[j].total_us / top[j].count) : 0;
		unsigned long long avg_s = avg_us / 1000000ULL;
		unsigned long long avg_ms = (avg_us / 1000ULL) % 1000ULL;

		output(0, "    %-24s events=%lu wedged=%llu.%03llus avg=%llu.%03llus\n",
			name, top[j].count, s, ms, avg_s, avg_ms);
	}
}

/*
 * Sister of dump_stats_top_wedging_syscalls() above, keyed by enum
 * child_op_type instead of syscall nr.  Wedging on this fleet is
 * dominated by long-lived non-syscall childops (flock_thrash,
 * futex_storm, memory_pressure, ...) whose inner sites cycle through
 * many syscalls; the per-syscall top-N attributes the wedge cost to
 * whichever syscall happened to be in flight at detection, which
 * mis-names the dominant wedgers.  This block surfaces them by the
 * childop that was running when the stall began.
 *
 * Shares the same duration definition as the per-syscall block --
 * full unreusable-slot time (watchdog grace included), CLOCK_MONOTONIC,
 * clamped >= 0 at the accumulator site (see reap_child() in main.c) --
 * so the per-syscall total and the per-childop total over the run are
 * the same number; the two top-N rows just slice it differently.
 *
 * Empty-block gate: skipped entirely if no wedge has ever been
 * accounted on this axis, so a clean run emits nothing.
 */
static void dump_stats_top_wedging_childops(void)
{
	struct childop_wedge_top_entry {
		unsigned int op;
		unsigned long count;
		unsigned long long total_us;
	} top[WEDGE_TOPN];
	unsigned int top_count = 0;
	unsigned long count_total = 0;
	unsigned long long us_total = 0;
	unsigned int i;
	int j;

	for (i = 0; i < NR_CHILD_OP_TYPES; i++) {
		unsigned long c = __atomic_load_n(
			&shm->stats.childop_wedge_count[i],
			__ATOMIC_RELAXED);
		unsigned long long u = __atomic_load_n(
			&shm->stats.childop_wedge_total_us[i],
			__ATOMIC_RELAXED);

		if (c == 0 && u == 0)
			continue;

		count_total += c;
		us_total += u;

		/* Insertion sort, descending by total_us, capped at
		 * WEDGE_TOPN.  Ties on total_us broken by event count so a
		 * hot childop with many quick wedges ranks above a single
		 * still-pending wedge whose duration matches by accident. */
		for (j = (int)top_count;
		     j > 0 && (u > top[j - 1].total_us ||
			       (u == top[j - 1].total_us &&
				c > top[j - 1].count));
		     j--) {
			if (j < WEDGE_TOPN)
				top[j] = top[j - 1];
		}
		if (j < WEDGE_TOPN) {
			top[j].op = i;
			top[j].count = c;
			top[j].total_us = u;
			if (top_count < WEDGE_TOPN)
				top_count++;
		}
	}

	if (count_total == 0 && us_total == 0)
		return;

	output(0, "Top %u most-wedging childops (cumulative; %lu events, "
		"%llu.%03llu s wedged total):\n",
		top_count, count_total,
		us_total / 1000000ULL, (us_total / 1000ULL) % 1000ULL);

	for (j = 0; j < (int)top_count; j++) {
		const char *name = alt_op_name(
			(enum child_op_type) top[j].op);
		unsigned long long s = top[j].total_us / 1000000ULL;
		unsigned long long ms = (top[j].total_us / 1000ULL) % 1000ULL;
		unsigned long long avg_us = top[j].count > 0 ?
			(top[j].total_us / top[j].count) : 0;
		unsigned long long avg_s = avg_us / 1000000ULL;
		unsigned long long avg_ms = (avg_us / 1000ULL) % 1000ULL;

		output(0, "    %-32s events=%lu wedged=%llu.%03llus avg=%llu.%03llus\n",
			name ? name : "?", top[j].count, s, ms, avg_s, avg_ms);
	}
}

static void dump_stats_fd_tracking(void)
{
	if (parent_stats.fault_injected) {
		stat_row("fault_injection", "armed_fail_nth",  parent_stats.fault_injected);
		stat_row("fault_injection", "returned_enomem", parent_stats.fault_consumed);
	}

	if (shm->stats.fd_stale_detected || shm->stats.fd_closed_tracked ||
	    shm->stats.fd_stale_by_generation ||
	    shm->stats.fd_duped || shm->stats.fd_events_processed ||
	    shm->stats.fd_hash_reinsert_dropped ||
	    shm->stats.local_fd_hash_insert_dropped ||
	    shm->stats.epoll_lazy_armed ||
	    shm->stats.epoll_blocking_poll_skipped ||
	    shm->stats.fd_random_exhausted ||
	    shm->stats.fd_provider_invalid) {
		stat_row("fd_lifecycle", "stale_detected",      shm->stats.fd_stale_detected);
		stat_row("fd_lifecycle", "stale_by_generation", shm->stats.fd_stale_by_generation);
		stat_row("fd_lifecycle", "closed_tracked",      shm->stats.fd_closed_tracked);
		stat_row("fd_lifecycle", "duped",               shm->stats.fd_duped);
		stat_row("fd_lifecycle", "events_processed",    shm->stats.fd_events_processed);
		stat_row("fd_lifecycle", "events_dropped",      shm->stats.fd_events_dropped);
		stat_row("fd_lifecycle", "event_close_count",   shm->stats.fd_event_close_count);
		stat_row("fd_lifecycle", "event_evict_count",   shm->stats.fd_event_evict_count);
		stat_row("fd_lifecycle", "hash_reinsert_dropped", shm->stats.fd_hash_reinsert_dropped);
		stat_row("fd_lifecycle", "local_hash_insert_dropped",
			 shm->stats.local_fd_hash_insert_dropped);
		stat_row("fd_lifecycle", "epoll_lazy_armed",    shm->stats.epoll_lazy_armed);
		stat_row("fd_lifecycle", "epoll_blocking_poll_skipped",
			 shm->stats.epoll_blocking_poll_skipped);
		stat_row("fd_lifecycle", "random_exhausted",    shm->stats.fd_random_exhausted);
		stat_row("fd_lifecycle", "provider_invalid",    shm->stats.fd_provider_invalid);
	}

	/*
	 * Per-provider outstanding-fd gauge.  Only providers whose live
	 * count is non-zero get a row -- a clean run with no leaks emits
	 * nothing; a non-empty block at shutdown surfaces a per-provider
	 * fd leak (CLOSE events lost in the fd_event ring, an OBJ_GLOBAL
	 * registration whose subsequent close() bypassed remove_object_by_fd,
	 * etc.).  The label comes from the registered fd_provider name so
	 * the row matches --enable-fds/--disable-fds syntax; an entry whose
	 * objtype has no matching provider is skipped (defensive: should
	 * not happen, since the bump site fires only on a successful
	 * fd_hash_insert for an is_fd_type() objtype).
	 */
	{
		unsigned int t;

		for (t = 0; t < MAX_OBJECT_TYPES; t++) {
			unsigned long outstanding =
				shm->stats.fd_provider_outstanding[t];
			const char *name;

			if (outstanding == 0)
				continue;

			name = fd_provider_name((enum objecttype) t);
			if (name == NULL)
				continue;

			stat_row("fd_provider_outstanding", name, outstanding);
		}
	}

	/* Producer-side capture count for the typed-scalar bypass push.
	 * Sibling to kcov_shm->propagation_injected (consumer-side); see
	 * the field comment in include/stats.h.  Lives next to the
	 * fd_runtime_* family because its capture site is the same
	 * register_returned_fd dispatch -- the OBJ_KEY_SERIAL branch
	 * mirrors the value into prop_ring after handing it to the typed
	 * registrar. */
	if (shm->stats.propagation_injected_key_scalar) {
		stat_row("propagation", "injected_key_scalar",
			 shm->stats.propagation_injected_key_scalar);
	}
}

static void dump_stats_oracle_anomalies(void)
{
	if (shm->stats.fd_oracle_anomalies)
		stat_row("oracle", "fd_anomalies",   shm->stats.fd_oracle_anomalies);
	if (shm->stats.mmap_oracle_anomalies)
		stat_row("oracle", "mmap_anomalies", shm->stats.mmap_oracle_anomalies);
	if (shm->stats.cred_oracle_anomalies)
		stat_row("oracle", "cred_anomalies", shm->stats.cred_oracle_anomalies);
	if (shm->stats.sched_oracle_anomalies)
		stat_row("oracle", "sched_anomalies", shm->stats.sched_oracle_anomalies);
	if (shm->stats.uid_oracle_anomalies)
		stat_row("oracle", "uid_anomalies",   shm->stats.uid_oracle_anomalies);
	if (shm->stats.gid_oracle_anomalies)
		stat_row("oracle", "gid_anomalies",   shm->stats.gid_oracle_anomalies);
	if (shm->stats.setgroups_oracle_anomalies)
		stat_row("oracle", "setgroups_anomalies", shm->stats.setgroups_oracle_anomalies);
	if (shm->stats.getegid_oracle_anomalies)
		stat_row("oracle", "getegid_anomalies", shm->stats.getegid_oracle_anomalies);
	if (shm->stats.getuid_oracle_anomalies)
		stat_row("oracle", "getuid_anomalies", shm->stats.getuid_oracle_anomalies);
	if (shm->stats.getgid_oracle_anomalies)
		stat_row("oracle", "getgid_anomalies", shm->stats.getgid_oracle_anomalies);
	if (shm->stats.getppid_oracle_anomalies)
		stat_row("oracle", "getppid_anomalies", shm->stats.getppid_oracle_anomalies);
	if (shm->stats.getcwd_oracle_anomalies)
		stat_row("oracle", "getcwd_anomalies", shm->stats.getcwd_oracle_anomalies);
	if (shm->stats.getpid_oracle_anomalies)
		stat_row("oracle", "getpid_anomalies", shm->stats.getpid_oracle_anomalies);
	if (shm->stats.getpgid_oracle_anomalies)
		stat_row("oracle", "getpgid_anomalies", shm->stats.getpgid_oracle_anomalies);
	if (shm->stats.getpgrp_oracle_anomalies)
		stat_row("oracle", "getpgrp_anomalies", shm->stats.getpgrp_oracle_anomalies);
	if (shm->stats.geteuid_oracle_anomalies)
		stat_row("oracle", "geteuid_anomalies", shm->stats.geteuid_oracle_anomalies);
	if (shm->stats.getsid_oracle_anomalies)
		stat_row("oracle", "getsid_anomalies", shm->stats.getsid_oracle_anomalies);
	if (shm->stats.gettid_oracle_anomalies)
		stat_row("oracle", "gettid_anomalies", shm->stats.gettid_oracle_anomalies);
	if (shm->stats.setsid_oracle_anomalies)
		stat_row("oracle", "setsid_anomalies", shm->stats.setsid_oracle_anomalies);
	if (shm->stats.setpgid_oracle_anomalies)
		stat_row("oracle", "setpgid_anomalies", shm->stats.setpgid_oracle_anomalies);
	if (shm->stats.sched_getscheduler_oracle_anomalies)
		stat_row("oracle", "sched_getscheduler_anomalies",
			 shm->stats.sched_getscheduler_oracle_anomalies);
	if (shm->stats.getgroups_oracle_anomalies)
		stat_row("oracle", "getgroups_anomalies", shm->stats.getgroups_oracle_anomalies);
	if (shm->stats.getresuid_oracle_anomalies)
		stat_row("oracle", "getresuid_anomalies", shm->stats.getresuid_oracle_anomalies);
	if (shm->stats.getresgid_oracle_anomalies)
		stat_row("oracle", "getresgid_anomalies", shm->stats.getresgid_oracle_anomalies);
	if (shm->stats.umask_oracle_anomalies)
		stat_row("oracle", "umask_anomalies", shm->stats.umask_oracle_anomalies);
	if (shm->stats.sched_get_priority_max_oracle_anomalies)
		stat_row("oracle", "sched_get_priority_max_anomalies",
			 shm->stats.sched_get_priority_max_oracle_anomalies);
	if (shm->stats.sched_get_priority_min_oracle_anomalies)
		stat_row("oracle", "sched_get_priority_min_anomalies",
			 shm->stats.sched_get_priority_min_oracle_anomalies);
	if (shm->stats.sched_yield_oracle_anomalies)
		stat_row("oracle", "sched_yield_anomalies",
			 shm->stats.sched_yield_oracle_anomalies);
	if (shm->stats.getpagesize_oracle_anomalies)
		stat_row("oracle", "getpagesize_anomalies",
			 shm->stats.getpagesize_oracle_anomalies);
	if (shm->stats.time_oracle_anomalies)
		stat_row("oracle", "time_anomalies",
			 shm->stats.time_oracle_anomalies);
	if (shm->stats.gettimeofday_oracle_anomalies)
		stat_row("oracle", "gettimeofday_anomalies",
			 shm->stats.gettimeofday_oracle_anomalies);
	if (shm->stats.newuname_oracle_anomalies)
		stat_row("oracle", "newuname_anomalies",
			 shm->stats.newuname_oracle_anomalies);
	if (shm->stats.rt_sigpending_oracle_anomalies)
		stat_row("oracle", "rt_sigpending_anomalies",
			 shm->stats.rt_sigpending_oracle_anomalies);
	if (shm->stats.rt_sigprocmask_oracle_anomalies)
		stat_row("oracle", "rt_sigprocmask_anomalies",
			 shm->stats.rt_sigprocmask_oracle_anomalies);
	if (shm->stats.sched_getparam_oracle_anomalies)
		stat_row("oracle", "sched_getparam_anomalies",
			 shm->stats.sched_getparam_oracle_anomalies);
	if (shm->stats.sched_rr_get_interval_oracle_anomalies)
		stat_row("oracle", "sched_rr_get_interval_anomalies",
			 shm->stats.sched_rr_get_interval_oracle_anomalies);
	if (shm->stats.get_robust_list_oracle_anomalies)
		stat_row("oracle", "get_robust_list_anomalies",
			 shm->stats.get_robust_list_oracle_anomalies);
	if (shm->stats.getrlimit_oracle_anomalies)
		stat_row("oracle", "getrlimit_anomalies",
			 shm->stats.getrlimit_oracle_anomalies);
	if (shm->stats.sysinfo_oracle_anomalies)
		stat_row("oracle", "sysinfo_anomalies",
			 shm->stats.sysinfo_oracle_anomalies);
	if (shm->stats.times_oracle_anomalies)
		stat_row("oracle", "times_anomalies",
			 shm->stats.times_oracle_anomalies);
	if (shm->stats.clock_getres_oracle_anomalies)
		stat_row("oracle", "clock_getres_anomalies",
			 shm->stats.clock_getres_oracle_anomalies);
	if (shm->stats.capget_oracle_anomalies)
		stat_row("oracle", "capget_anomalies",
			 shm->stats.capget_oracle_anomalies);
	if (shm->stats.capdrop_oracle_anomalies)
		stat_row("oracle", "capdrop_anomalies",
			 shm->stats.capdrop_oracle_anomalies);
	if (shm->stats.newlstat_oracle_anomalies)
		stat_row("oracle", "newlstat_anomalies",
			 shm->stats.newlstat_oracle_anomalies);
	if (shm->stats.newstat_oracle_anomalies)
		stat_row("oracle", "newstat_anomalies",
			 shm->stats.newstat_oracle_anomalies);
	if (shm->stats.newfstat_oracle_anomalies)
		stat_row("oracle", "newfstat_anomalies",
			 shm->stats.newfstat_oracle_anomalies);
	if (shm->stats.post_handler_untouched_out_buf)
		stat_row("oracle", "untouched_out_buf",
			 shm->stats.post_handler_untouched_out_buf);
	if (shm->stats.newfstatat_oracle_anomalies)
		stat_row("oracle", "newfstatat_anomalies",
			 shm->stats.newfstatat_oracle_anomalies);
	if (shm->stats.statx_oracle_anomalies)
		stat_row("oracle", "statx_anomalies",
			 shm->stats.statx_oracle_anomalies);
	if (shm->stats.fstatfs_oracle_anomalies)
		stat_row("oracle", "fstatfs_anomalies",
			 shm->stats.fstatfs_oracle_anomalies);
	if (shm->stats.fstatfs64_oracle_anomalies)
		stat_row("oracle", "fstatfs64_anomalies",
			 shm->stats.fstatfs64_oracle_anomalies);
	if (shm->stats.statfs_oracle_anomalies)
		stat_row("oracle", "statfs_anomalies",
			 shm->stats.statfs_oracle_anomalies);
	if (shm->stats.statfs64_oracle_anomalies)
		stat_row("oracle", "statfs64_anomalies",
			 shm->stats.statfs64_oracle_anomalies);
	if (shm->stats.uname_oracle_anomalies)
		stat_row("oracle", "uname_anomalies",
			 shm->stats.uname_oracle_anomalies);
	if (shm->stats.lsm_list_modules_oracle_anomalies)
		stat_row("oracle", "lsm_list_modules_anomalies",
			 shm->stats.lsm_list_modules_oracle_anomalies);
	if (shm->stats.listmount_oracle_anomalies)
		stat_row("oracle", "listmount_anomalies",
			 shm->stats.listmount_oracle_anomalies);
	if (shm->stats.statmount_oracle_anomalies)
		stat_row("oracle", "statmount_anomalies",
			 shm->stats.statmount_oracle_anomalies);
	if (shm->stats.statmount_setup_fail)
		stat_row("syscall", "statmount_setup_fail",
			 shm->stats.statmount_setup_fail);
	if (shm->stats.getsockname_oracle_anomalies)
		stat_row("oracle", "getsockname_anomalies",
			 shm->stats.getsockname_oracle_anomalies);
	if (shm->stats.getpeername_oracle_anomalies)
		stat_row("oracle", "getpeername_anomalies",
			 shm->stats.getpeername_oracle_anomalies);
	if (shm->stats.file_getattr_oracle_anomalies)
		stat_row("oracle", "file_getattr_anomalies",
			 shm->stats.file_getattr_oracle_anomalies);
	if (shm->stats.sched_getattr_oracle_anomalies)
		stat_row("oracle", "sched_getattr_anomalies",
			 shm->stats.sched_getattr_oracle_anomalies);
	if (shm->stats.getrusage_oracle_anomalies)
		stat_row("oracle", "getrusage_anomalies",
			 shm->stats.getrusage_oracle_anomalies);
	if (shm->stats.sigpending_oracle_anomalies)
		stat_row("oracle", "sigpending_anomalies",
			 shm->stats.sigpending_oracle_anomalies);
	if (shm->stats.getcpu_oracle_anomalies)
		stat_row("oracle", "getcpu_anomalies",
			 shm->stats.getcpu_oracle_anomalies);
	if (shm->stats.clock_gettime_oracle_anomalies)
		stat_row("oracle", "clock_gettime_anomalies",
			 shm->stats.clock_gettime_oracle_anomalies);
	if (shm->stats.get_mempolicy_oracle_anomalies)
		stat_row("oracle", "get_mempolicy_anomalies",
			 shm->stats.get_mempolicy_oracle_anomalies);
	if (shm->stats.lsm_get_self_attr_oracle_anomalies)
		stat_row("oracle", "lsm_get_self_attr_anomalies",
			 shm->stats.lsm_get_self_attr_oracle_anomalies);
	if (shm->stats.prlimit64_oracle_anomalies)
		stat_row("oracle", "prlimit64_anomalies",
			 shm->stats.prlimit64_oracle_anomalies);
	if (shm->stats.sigaltstack_oracle_anomalies)
		stat_row("oracle", "sigaltstack_anomalies",
			 shm->stats.sigaltstack_oracle_anomalies);
	if (shm->stats.olduname_oracle_anomalies)
		stat_row("oracle", "olduname_anomalies",
			 shm->stats.olduname_oracle_anomalies);
	if (shm->stats.lookup_dcookie_oracle_anomalies)
		stat_row("oracle", "lookup_dcookie_anomalies",
			 shm->stats.lookup_dcookie_oracle_anomalies);
	if (shm->stats.getxattr_oracle_anomalies)
		stat_row("oracle", "getxattr_anomalies",
			 shm->stats.getxattr_oracle_anomalies);
	if (shm->stats.lgetxattr_oracle_anomalies)
		stat_row("oracle", "lgetxattr_anomalies",
			 shm->stats.lgetxattr_oracle_anomalies);
	if (shm->stats.fgetxattr_oracle_anomalies)
		stat_row("oracle", "fgetxattr_anomalies",
			 shm->stats.fgetxattr_oracle_anomalies);
	if (shm->stats.listxattrat_oracle_anomalies)
		stat_row("oracle", "listxattrat_anomalies",
			 shm->stats.listxattrat_oracle_anomalies);
	if (shm->stats.flistxattr_oracle_anomalies)
		stat_row("oracle", "flistxattr_anomalies",
			 shm->stats.flistxattr_oracle_anomalies);
	if (shm->stats.listxattr_oracle_anomalies)
		stat_row("oracle", "listxattr_anomalies",
			 shm->stats.listxattr_oracle_anomalies);
	if (shm->stats.llistxattr_oracle_anomalies)
		stat_row("oracle", "llistxattr_anomalies",
			 shm->stats.llistxattr_oracle_anomalies);
	if (shm->stats.readlink_oracle_anomalies)
		stat_row("oracle", "readlink_anomalies",
			 shm->stats.readlink_oracle_anomalies);
	if (shm->stats.readlinkat_oracle_anomalies)
		stat_row("oracle", "readlinkat_anomalies",
			 shm->stats.readlinkat_oracle_anomalies);
	if (shm->stats.sysfs_oracle_anomalies)
		stat_row("oracle", "sysfs_anomalies",
			 shm->stats.sysfs_oracle_anomalies);
}

static void dump_stats_fuzzer_subsystems(void)
{
	if (shm->stats.procfs_writes_open_fail || shm->stats.procfs_writes_write_fail ||
	    shm->stats.procfs_writes_write_ok ||
	    shm->stats.sysfs_writes_open_fail || shm->stats.sysfs_writes_write_fail ||
	    shm->stats.sysfs_writes_write_ok ||
	    shm->stats.debugfs_writes_open_fail || shm->stats.debugfs_writes_write_fail ||
	    shm->stats.debugfs_writes_write_ok) {
		stat_row("vfs_writes", "procfs_open_fail",   shm->stats.procfs_writes_open_fail);
		stat_row("vfs_writes", "procfs_write_fail",  shm->stats.procfs_writes_write_fail);
		stat_row("vfs_writes", "procfs_write_ok",    shm->stats.procfs_writes_write_ok);
		stat_row("vfs_writes", "sysfs_open_fail",    shm->stats.sysfs_writes_open_fail);
		stat_row("vfs_writes", "sysfs_write_fail",   shm->stats.sysfs_writes_write_fail);
		stat_row("vfs_writes", "sysfs_write_ok",     shm->stats.sysfs_writes_write_ok);
		stat_row("vfs_writes", "debugfs_open_fail",  shm->stats.debugfs_writes_open_fail);
		stat_row("vfs_writes", "debugfs_write_fail", shm->stats.debugfs_writes_write_fail);
		stat_row("vfs_writes", "debugfs_write_ok",   shm->stats.debugfs_writes_write_ok);
	}

	if (shm->stats.memory_pressure_runs)
		stat_row("memory_pressure", "runs_madv_pageout", shm->stats.memory_pressure_runs);

	stat_category_emit_text(&sched_cycler_category);

	stat_category_emit_text(&userns_fuzzer_category);

	stat_category_emit_text(&userns_bootstrap_category);

	stat_category_emit_text(&barrier_racer_category);

	if (shm->stats.genetlink_families_discovered ||
	    shm->stats.genetlink_msgs_sent              ||
	    shm->stats.genetlink_missing_producer       ||
	    shm->stats.genetlink_discovery_io_err       ||
	    shm->stats.genetlink_discovery_nlerr) {
		stat_row("genetlink_fuzzer", "families_discovered", shm->stats.genetlink_families_discovered);
		stat_row("genetlink_fuzzer", "msgs_sent",           shm->stats.genetlink_msgs_sent);
		stat_row("genetlink_fuzzer", "eperm",               shm->stats.genetlink_eperm);
		stat_row("genetlink_fuzzer", "stale_seq_drops",     shm->stats.genetlink_stale_seq_drops);
		stat_row("genetlink_fuzzer", "missing_producer",    shm->stats.genetlink_missing_producer);
		stat_row("genetlink_fuzzer", "discovery_io_err",    shm->stats.genetlink_discovery_io_err);
		stat_row("genetlink_fuzzer", "discovery_nlerr",     shm->stats.genetlink_discovery_nlerr);
	}

	if (shm->stats.genl_family_calls_devlink   ||
	    shm->stats.genl_family_calls_nl80211   ||
	    shm->stats.genl_family_calls_taskstats ||
	    shm->stats.genl_family_calls_ethtool   ||
	    shm->stats.genl_family_calls_mptcp_pm  ||
	    shm->stats.genl_family_calls_tipc      ||
	    shm->stats.genl_family_calls_wireguard ||
	    shm->stats.genl_family_calls_netlabel  ||
	    shm->stats.genl_family_calls_team      ||
	    shm->stats.genl_family_calls_hsr       ||
	    shm->stats.genl_family_calls_fou       ||
	    shm->stats.genl_family_calls_psample   ||
	    shm->stats.genl_family_calls_ila       ||
	    shm->stats.genl_family_calls_ioam6     ||
	    shm->stats.genl_family_calls_seg6      ||
	    shm->stats.genl_family_calls_thermal   ||
	    shm->stats.genl_family_calls_ipvs) {
		stat_row("genl_family_calls", "devlink",   shm->stats.genl_family_calls_devlink);
		stat_row("genl_family_calls", "nl80211",   shm->stats.genl_family_calls_nl80211);
		stat_row("genl_family_calls", "taskstats", shm->stats.genl_family_calls_taskstats);
		stat_row("genl_family_calls", "ethtool",   shm->stats.genl_family_calls_ethtool);
		stat_row("genl_family_calls", "mptcp_pm",  shm->stats.genl_family_calls_mptcp_pm);
		stat_row("genl_family_calls", "tipc",      shm->stats.genl_family_calls_tipc);
		stat_row("genl_family_calls", "wireguard", shm->stats.genl_family_calls_wireguard);
		stat_row("genl_family_calls", "netlabel",  shm->stats.genl_family_calls_netlabel);
		stat_row("genl_family_calls", "team",      shm->stats.genl_family_calls_team);
		stat_row("genl_family_calls", "hsr",       shm->stats.genl_family_calls_hsr);
		stat_row("genl_family_calls", "fou",       shm->stats.genl_family_calls_fou);
		stat_row("genl_family_calls", "psample",   shm->stats.genl_family_calls_psample);
		stat_row("genl_family_calls", "ila",       shm->stats.genl_family_calls_ila);
		stat_row("genl_family_calls", "ioam6",     shm->stats.genl_family_calls_ioam6);
		stat_row("genl_family_calls", "seg6",      shm->stats.genl_family_calls_seg6);
		stat_row("genl_family_calls", "thermal",   shm->stats.genl_family_calls_thermal);
		stat_row("genl_family_calls", "ipvs",      shm->stats.genl_family_calls_ipvs);
	}

	if (shm->stats.nfnl_subsys_calls_ctnetlink     ||
	    shm->stats.nfnl_subsys_calls_ctnetlink_exp ||
	    shm->stats.nfnl_subsys_calls_nftables      ||
	    shm->stats.nfnl_subsys_calls_ipset) {
		stat_row("nfnl_subsys_calls", "ctnetlink",     shm->stats.nfnl_subsys_calls_ctnetlink);
		stat_row("nfnl_subsys_calls", "ctnetlink_exp", shm->stats.nfnl_subsys_calls_ctnetlink_exp);
		stat_row("nfnl_subsys_calls", "nftables",      shm->stats.nfnl_subsys_calls_nftables);
		stat_row("nfnl_subsys_calls", "ipset",         shm->stats.nfnl_subsys_calls_ipset);
	}

	if (shm->stats.netlink_nested_attrs_emitted)
		stat_row("netlink_generator", "nested_attrs_emitted", shm->stats.netlink_nested_attrs_emitted);

	if (shm->stats.kvm_vcpu_ioctls_dispatched)
		stat_row("kvm", "vcpu_ioctls_dispatched", shm->stats.kvm_vcpu_ioctls_dispatched);

	stat_category_emit_text(&perf_event_chains_category);

	if (shm->stats.tracefs_kprobe_writes_open_fail || shm->stats.tracefs_kprobe_writes_write_fail ||
	    shm->stats.tracefs_kprobe_writes_write_ok ||
	    shm->stats.tracefs_uprobe_writes_open_fail || shm->stats.tracefs_uprobe_writes_write_fail ||
	    shm->stats.tracefs_uprobe_writes_write_ok ||
	    shm->stats.tracefs_filter_writes_open_fail || shm->stats.tracefs_filter_writes_write_fail ||
	    shm->stats.tracefs_filter_writes_write_ok ||
	    shm->stats.tracefs_event_enable_writes_open_fail || shm->stats.tracefs_event_enable_writes_write_fail ||
	    shm->stats.tracefs_event_enable_writes_write_ok ||
	    shm->stats.tracefs_misc_writes_open_fail || shm->stats.tracefs_misc_writes_write_fail ||
	    shm->stats.tracefs_misc_writes_write_ok) {
		stat_row("tracefs_fuzzer", "kprobe_open_fail",         shm->stats.tracefs_kprobe_writes_open_fail);
		stat_row("tracefs_fuzzer", "kprobe_write_fail",        shm->stats.tracefs_kprobe_writes_write_fail);
		stat_row("tracefs_fuzzer", "kprobe_write_ok",          shm->stats.tracefs_kprobe_writes_write_ok);
		stat_row("tracefs_fuzzer", "uprobe_open_fail",         shm->stats.tracefs_uprobe_writes_open_fail);
		stat_row("tracefs_fuzzer", "uprobe_write_fail",        shm->stats.tracefs_uprobe_writes_write_fail);
		stat_row("tracefs_fuzzer", "uprobe_write_ok",          shm->stats.tracefs_uprobe_writes_write_ok);
		stat_row("tracefs_fuzzer", "filter_open_fail",         shm->stats.tracefs_filter_writes_open_fail);
		stat_row("tracefs_fuzzer", "filter_write_fail",        shm->stats.tracefs_filter_writes_write_fail);
		stat_row("tracefs_fuzzer", "filter_write_ok",          shm->stats.tracefs_filter_writes_write_ok);
		stat_row("tracefs_fuzzer", "event_enable_open_fail",   shm->stats.tracefs_event_enable_writes_open_fail);
		stat_row("tracefs_fuzzer", "event_enable_write_fail",  shm->stats.tracefs_event_enable_writes_write_fail);
		stat_row("tracefs_fuzzer", "event_enable_write_ok",    shm->stats.tracefs_event_enable_writes_write_ok);
		stat_row("tracefs_fuzzer", "misc_open_fail",           shm->stats.tracefs_misc_writes_open_fail);
		stat_row("tracefs_fuzzer", "misc_write_fail",          shm->stats.tracefs_misc_writes_write_fail);
		stat_row("tracefs_fuzzer", "misc_write_ok",            shm->stats.tracefs_misc_writes_write_ok);
	}

	stat_category_emit_text(&bpf_lifecycle_category);

	if (shm->stats.bpf_maps_provided || shm->stats.bpf_progs_provided) {
		stat_row("bpf_fd_provider", "maps_provided",  shm->stats.bpf_maps_provided);
		stat_row("bpf_fd_provider", "progs_provided", shm->stats.bpf_progs_provided);
	}

	if (shm->stats.ebpf_gen_map_fd_substituted) {
		stat_row("ebpf_gen", "map_fd_substituted",
			 shm->stats.ebpf_gen_map_fd_substituted);
	}

	if (shm->stats.ebpf_gen_helper_call_emitted) {
		stat_row("ebpf_gen", "helper_call_emitted",
			 shm->stats.ebpf_gen_helper_call_emitted);
	}

	if (shm->stats.ebpf_gen_map_value_deref_emitted) {
		stat_row("ebpf_gen", "map_value_deref_emitted",
			 shm->stats.ebpf_gen_map_value_deref_emitted);
		stat_row("ebpf_gen", "map_value_deref_read",
			 shm->stats.ebpf_gen_map_value_deref_read);
		stat_row("ebpf_gen", "map_value_deref_write",
			 shm->stats.ebpf_gen_map_value_deref_write);
	}

	if (shm->stats.recipe_runs) {
		stat_row("recipe_runner", "runs",        shm->stats.recipe_runs);
		stat_row("recipe_runner", "completed",   shm->stats.recipe_completed);
		stat_row("recipe_runner", "partial",     shm->stats.recipe_partial);
		stat_row("recipe_runner", "unsupported", shm->stats.recipe_unsupported);
		recipe_runner_dump_stats();
	}

	if (shm->stats.iouring_recipes_runs) {
		stat_row("iouring_recipes", "runs",      shm->stats.iouring_recipes_runs);
		stat_row("iouring_recipes", "completed", shm->stats.iouring_recipes_completed);
		stat_row("iouring_recipes", "partial",   shm->stats.iouring_recipes_partial);
		stat_row("iouring_recipes", "enosys",    shm->stats.iouring_recipes_enosys);
		iouring_recipes_dump_stats();
	}

	if (shm->stats.iouring_eventfd_register_ok ||
	    shm->stats.iouring_eventfd_register_fail) {
		stat_row("iouring_eventfd", "register_ok",
			 shm->stats.iouring_eventfd_register_ok);
		stat_row("iouring_eventfd", "register_fail",
			 shm->stats.iouring_eventfd_register_fail);
		stat_row("iouring_eventfd", "recursive_runs",
			 shm->stats.iouring_eventfd_recursive_runs);
		stat_row("iouring_eventfd", "recursive_cqes",
			 shm->stats.iouring_eventfd_recursive_cqes);
	}

	if (shm->stats.zombies_reaped || shm->stats.zombies_timed_out ||
	    shm->stats.zombie_slots_pending) {
		stat_row("zombie_slots", "pending",   shm->stats.zombie_slots_pending);
		stat_row("zombie_slots", "reaped",    shm->stats.zombies_reaped);
		stat_row("zombie_slots", "timed_out", shm->stats.zombies_timed_out);
	}
}

static void dump_stats_corruption_and_pool(void)
{
	if (shm->stats.fd_event_ring_corrupted)
		stat_row("corruption", "fd_event_ring_noncanon", shm->stats.fd_event_ring_corrupted);
	if (shm->stats.fd_event_ring_overwritten)
		stat_row("corruption", "fd_event_ring_canary",   shm->stats.fd_event_ring_overwritten);
	if (shm->stats.stats_ring_corrupted)
		stat_row("corruption", "stats_ring_noncanon",    shm->stats.stats_ring_corrupted);
	if (shm->stats.stats_ring_overwritten)
		stat_row("corruption", "stats_ring_canary",      shm->stats.stats_ring_overwritten);
	if (shm->stats.fd_event_payload_corrupt)
		stat_row("corruption", "fd_event_payload",       shm->stats.fd_event_payload_corrupt);
	if (parent_stats.deferred_free_corrupt_ptr)
		stat_row("corruption", "deferred_free_corrupt_ptr", parent_stats.deferred_free_corrupt_ptr);
	if (parent_stats.post_handler_corrupt_ptr)
		stat_row("corruption", "post_handler_corrupt_ptr", parent_stats.post_handler_corrupt_ptr);
	/*
	 * Standalone grep-friendly cumulative line.  The stat_row above
	 * is gated on non-zero and the per-handler attribution block
	 * elsewhere repeats the bare token "post_handler_corrupt_ptr"
	 * as narrative, so `grep -c post_handler_corrupt_ptr out.log`
	 * counts occurrences, not the counter -- a triage trap.  Emit
	 * one line per window with a distinctive _cumulative suffix so
	 * operators can do `grep post_handler_corrupt_ptr_cumulative
	 * out.log | tail -1` for the current total, or grep -c against
	 * the suffix to count windows.
	 */
	output(0, "[main] post_handler_corrupt_ptr_cumulative=%lu\n",
	       parent_stats.post_handler_corrupt_ptr);
	/*
	 * TRINITY_CORRUPT_ATTRIB per-call-site breakdown.  Gated on the
	 * env-var-latched bool so production dumps stay terse; when on,
	 * emits one stat_row per named site plus a computed "post_generic"
	 * row carrying the residual headline - sum(named).  A non-trivial
	 * post_generic value is the lead for the next call-site sweep --
	 * the producer is some legacy post_handler_corrupt_ptr_bump() macro
	 * caller that hasn't been categorised yet.  Reads shm->stats via
	 * RELAXED atomic loads since children are concurrent writers.
	 */
	if (corrupt_ptr_attrib_active()) {
		unsigned long named_sum = 0;
		unsigned long total = parent_stats.post_handler_corrupt_ptr;
		unsigned int i;

		for (i = 0; i < CORRUPT_PTR_SITE__COUNT; i++) {
			unsigned long v;
			char metric[64];

			v = __atomic_load_n(&shm->stats.corrupt_ptr_site_count[i],
					    __ATOMIC_RELAXED);
			named_sum += v;
			snprintf(metric, sizeof(metric),
				 "corrupt_ptr_site:%s",
				 corrupt_ptr_site_names[i]);
			stat_row("corruption", metric, v);
			output(0, "[main] %s_cumulative=%lu\n", metric, v);
		}
		/* Anything in the headline not claimed by a named site:
		 * the legacy post_handler_corrupt_ptr_bump(rec, NULL) callers
		 * in syscalls (the per-handler oracle bumps that weren't
		 * routed through _at()).  Saturate to zero if named_sum
		 * outruns the headline due to non-atomic reads of the two
		 * counters at slightly different moments. */
		stat_row("corruption", "corrupt_ptr_site:post_generic",
			 total > named_sum ? total - named_sum : 0);
		output(0, "[main] corrupt_ptr_site:post_generic_cumulative=%lu (headline=%lu named_sum=%lu)\n",
		       total > named_sum ? total - named_sum : 0,
		       total, named_sum);
	}
	if (parent_stats.arg_shadow_stomp)
		stat_row("corruption", "arg_shadow_stomp", parent_stats.arg_shadow_stomp);
	if (parent_stats.deferred_free_reject)
		stat_row("corruption", "deferred_free_reject",   parent_stats.deferred_free_reject);
	if (parent_stats.deferred_free_reject_pathname)
		stat_row("corruption", "deferred_free_reject_pathname", parent_stats.deferred_free_reject_pathname);
	if (parent_stats.deferred_free_reject_iovec)
		stat_row("corruption", "deferred_free_reject_iovec", parent_stats.deferred_free_reject_iovec);
	if (parent_stats.deferred_free_reject_sockaddr)
		stat_row("corruption", "deferred_free_reject_sockaddr", parent_stats.deferred_free_reject_sockaddr);
	if (parent_stats.deferred_free_reject_other)
		stat_row("corruption", "deferred_free_reject_other", parent_stats.deferred_free_reject_other);
	if (shm->stats.deferred_free_reject_misaligned)
		stat_row("corruption", "deferred_free_reject_misaligned",     shm->stats.deferred_free_reject_misaligned);
	if (shm->stats.deferred_free_reject_corrupt_shape)
		stat_row("corruption", "deferred_free_reject_corrupt_shape",  shm->stats.deferred_free_reject_corrupt_shape);
	if (shm->stats.deferred_free_reject_non_heap)
		stat_row("corruption", "deferred_free_reject_non_heap",       shm->stats.deferred_free_reject_non_heap);
	if (shm->stats.deferred_free_reject_untracked)
		stat_row("corruption", "deferred_free_reject_untracked",      shm->stats.deferred_free_reject_untracked);
	if (shm->stats.nested_scrub_reject_untracked)
		stat_row("corruption", "nested_scrub_reject_untracked",       shm->stats.nested_scrub_reject_untracked);
	if (shm->stats.deferred_free_reject_shared_region)
		stat_row("corruption", "deferred_free_reject_shared_region",  shm->stats.deferred_free_reject_shared_region);
	if (shm->stats.deferred_free_outstanding_vmas)
		stat_row("corruption", "deferred_free_outstanding_vmas",      shm->stats.deferred_free_outstanding_vmas);
	if (shm->stats.deferred_free_vma_fallback_immediate)
		stat_row("corruption", "deferred_free_vma_fallback_immediate", shm->stats.deferred_free_vma_fallback_immediate);
	if (shm->stats.deferred_free_enomem_drain)
		stat_row("corruption", "deferred_free_enomem_drain",          shm->stats.deferred_free_enomem_drain);
	if (shm->stats.deferred_free_rw_restore_enomem)
		stat_row("corruption", "deferred_free_rw_restore_enomem",     shm->stats.deferred_free_rw_restore_enomem);
	if (shm->stats.deferred_free_pre_dispatch_leaked)
		stat_row("corruption", "deferred_free_pre_dispatch_leaked",   shm->stats.deferred_free_pre_dispatch_leaked);
	if (shm->stats.ring_evict_leaked)
		stat_row("corruption", "ring_evict_leaked",                   shm->stats.ring_evict_leaked);
	if (shm->stats.deferred_free_ring_owned_skip)
		stat_row("corruption", "deferred_free_ring_owned_skip",       shm->stats.deferred_free_ring_owned_skip);
	if (shm->stats.deferred_free_double_admit_skip)
		stat_row("corruption", "deferred_free_double_admit_skip",     shm->stats.deferred_free_double_admit_skip);
	if (shm->stats.alloc_track_refresh_ring_owned_skip)
		stat_row("corruption", "alloc_track_refresh_ring_owned_skip", shm->stats.alloc_track_refresh_ring_owned_skip);
	if (shm->stats.alloc_track_refresh_unverified_skip)
		stat_row("corruption", "alloc_track_refresh_unverified_skip", shm->stats.alloc_track_refresh_unverified_skip);
	if (parent_stats.snapshot_non_heap_reject)
		stat_row("corruption", "snapshot_non_heap_reject", parent_stats.snapshot_non_heap_reject);
	if (parent_stats.lock_word_scribbled)
		stat_row("corruption", "lock_word_scribbled",   parent_stats.lock_word_scribbled);
	if (shm->stats.lock_held_scribble)
		stat_row("corruption", "lock_held_scribble",    shm->stats.lock_held_scribble);
	if (shm->stats.rec_canary_stomped)
		stat_row("corruption", "rec_canary_stomped",     shm->stats.rec_canary_stomped);
	if (shm->stats.mut_attrib_inversion_caught)
		stat_row("corruption", "mut_attrib_inversion_caught",
			 shm->stats.mut_attrib_inversion_caught);
	if (shm->stats.rzs_blanket_reject)
		stat_row("corruption", "rzs_blanket_reject",     shm->stats.rzs_blanket_reject);
	if (shm->stats.retfd_blanket_reject)
		stat_row("corruption", "retfd_blanket_reject",   shm->stats.retfd_blanket_reject);
	if (shm->stats.arena_ptr_stale_caught_arg)
		stat_row("corruption", "arena_ptr_stale_caught_arg",
			 shm->stats.arena_ptr_stale_caught_arg);
	if (shm->stats.arena_ptr_stale_caught_post_state)
		stat_row("corruption", "arena_ptr_stale_caught_post_state",
			 shm->stats.arena_ptr_stale_caught_post_state);
	/*
	 * Standalone grep-friendly cumulative lines for the arena_ptr_stale
	 * pair.  The stat_rows above are gated on non-zero, and the JSON +
	 * defense_counters[] registrations repeat the bare counter tokens as
	 * narrative, so `grep -c arena_ptr_stale_caught_arg out.log` counts
	 * occurrences rather than the counter itself -- the same triage trap
	 * post_handler_corrupt_ptr_cumulative was added to close.  Emit one
	 * line per window per counter (even at zero so trend tracking has a
	 * t=0 anchor) with a distinctive _cumulative suffix; operators can
	 * `grep <counter>_cumulative out.log | tail -1` for the current
	 * total or grep -c the suffix to count windows.
	 */
	output(0, "[main] arena_ptr_stale_caught_arg_cumulative=%lu\n",
	       shm->stats.arena_ptr_stale_caught_arg);
	output(0, "[main] arena_ptr_stale_caught_post_state_cumulative=%lu\n",
	       shm->stats.arena_ptr_stale_caught_post_state);
	if (shm->stats.sibling_mprotect_failed)
		stat_row("corruption", "sibling_mprotect_failed", shm->stats.sibling_mprotect_failed);
	{
		/* Per-field divergence-sentinel rows: one stat_row per
		 * non-zero field shard so the operator sees which
		 * monitored field actually drifted rather than a lumped
		 * headline number.  Names match the defense_counters[]
		 * registration above so periodic and end-of-run views
		 * align. */
		static const struct {
			enum sentinel_field field;
			const char *name;
		} divergence_sentinel_rows[] = {
			{ SF_UNAME_SYSNAME,	"divergence_sentinel_anomalies_sysname"   },
			{ SF_UNAME_RELEASE,	"divergence_sentinel_anomalies_release"   },
			{ SF_UNAME_VERSION,	"divergence_sentinel_anomalies_version"   },
			{ SF_UNAME_MACHINE,	"divergence_sentinel_anomalies_machine"   },
			{ SF_SYSINFO_TOTALRAM,	"divergence_sentinel_anomalies_totalram"  },
			{ SF_SYSINFO_TOTALSWAP,	"divergence_sentinel_anomalies_totalswap" },
			{ SF_SYSINFO_TOTALHIGH,	"divergence_sentinel_anomalies_totalhigh" },
			{ SF_SYSINFO_MEM_UNIT,	"divergence_sentinel_anomalies_mem_unit"  },
		};
		unsigned int s;

		for (s = 0; s < ARRAY_SIZE(divergence_sentinel_rows); s++) {
			enum sentinel_field f = divergence_sentinel_rows[s].field;
			unsigned long v = shm->stats.divergence_sentinel_anomalies[f];

			if (v == 0)
				continue;
			stat_row("corruption",
				 divergence_sentinel_rows[s].name, v);
		}
	}
	if (shm->stats.divergence_sentinel_expected_drift)
		stat_row("corruption", "divergence_sentinel_expected_drift",
			 shm->stats.divergence_sentinel_expected_drift);
	if (shm->stats.destroy_object_idx_corrupt)
		stat_row("corruption", "destroy_object_idx",     shm->stats.destroy_object_idx_corrupt);
	if (shm->stats.global_obj_uaf_caught)
		stat_row("corruption", "global_obj_uaf_caught",  shm->stats.global_obj_uaf_caught);
	if (shm->stats.maps_pool_draw_exhausted)
		stat_row("pool", "maps_pool_draw_exhausted",   shm->stats.maps_pool_draw_exhausted);
	if (shm->stats.maps_reject_pool_empty)
		stat_row("pool", "maps_reject_pool_empty",     shm->stats.maps_reject_pool_empty);
	if (shm->stats.maps_reject_bogus_obj_ptr)
		stat_row("pool", "maps_reject_bogus_obj_ptr",  shm->stats.maps_reject_bogus_obj_ptr);
	if (shm->stats.maps_reject_alloc_track_miss)
		stat_row("pool", "maps_reject_alloc_track_miss", shm->stats.maps_reject_alloc_track_miss);
	if (shm->stats.maps_reject_alloc_track_miss_anon)
		stat_row("pool", "maps_reject_alloc_track_miss_anon",
			 shm->stats.maps_reject_alloc_track_miss_anon);
	if (shm->stats.maps_reject_alloc_track_miss_file)
		stat_row("pool", "maps_reject_alloc_track_miss_file",
			 shm->stats.maps_reject_alloc_track_miss_file);
	if (shm->stats.maps_reject_alloc_track_miss_testfile)
		stat_row("pool", "maps_reject_alloc_track_miss_testfile",
			 shm->stats.maps_reject_alloc_track_miss_testfile);
	if (shm->stats.maps_reject_size_zero)
		stat_row("pool", "maps_reject_size_zero",      shm->stats.maps_reject_size_zero);
	if (shm->stats.maps_reject_size_too_large)
		stat_row("pool", "maps_reject_size_too_large", shm->stats.maps_reject_size_too_large);
	if (shm->stats.chain_replay_len_corrupt)
		stat_row("corruption", "chain_replay_len_corrupt", shm->stats.chain_replay_len_corrupt);
	if (shm->stats.pagecache_canary_corrupt_caught)
		stat_row("oracle", "pagecache_canary_corrupt_caught",
			 shm->stats.pagecache_canary_corrupt_caught);
	if (shm->stats.objpool_array_stale_caught)
		stat_row("corruption", "objpool_array_stale_caught",
			 shm->stats.objpool_array_stale_caught);

	/* Derived ratio: avg get_map_handle() retry-loop attempts per
	 * successful pick.  The counter-pair comment in include/stats.h
	 * documents this as the realised cost the 1000-iter retry budget
	 * exists to amortise -- a value approaching the budget means the
	 * loop is dominated by the reject path and the side-index work is
	 * justified.  Rendered separately for the general get_map_handle()
	 * path and the get_map_with_prot() outer prot-filter retry, since
	 * the prot filter compounds prot reject on top of pool-pick reject
	 * and carries a different cost curve.  Skipped when the success
	 * denominator is zero. */
	{
		unsigned long s  = shm->stats.maps_pick_successes;
		unsigned long a  = shm->stats.maps_pick_attempts_sum;
		unsigned long ps = shm->stats.maps_pick_with_prot_successes;
		unsigned long pa = shm->stats.maps_pick_with_prot_attempts_sum;
		char val[32];

		if (s > 0) {
			unsigned long milli = ((a % s) * 1000UL) / s;

			snprintf(val, sizeof(val), "%lu.%03lu", a / s, milli);
			output(0, STATS_HDR_FMT, "pool",
			       "maps_pick_attempts_per_success", val);
		}
		if (ps > 0) {
			unsigned long milli = ((pa % ps) * 1000UL) / ps;

			snprintf(val, sizeof(val), "%lu.%03lu",
				 pa / ps, milli);
			output(0, STATS_HDR_FMT, "pool",
			       "maps_pick_with_prot_attempts_per_success",
			       val);
		}
	}
}

static void dump_stats_childop_ranked_tables(void)
{
	{
		unsigned int op;
		char metric[40];

		for (op = 0; op < NR_CHILD_OP_TYPES; op++) {
			if (shm->stats.taint_transitions[op] == 0)
				continue;
			snprintf(metric, sizeof(metric), "%s",
				 alt_op_name((enum child_op_type)op));
			stat_row("taint_transitions", metric,
				 shm->stats.taint_transitions[op]);
		}

		for (op = 0; op < NR_CHILD_OP_TYPES; op++) {
			if (shm->stats.pool_race_aborted[op] == 0)
				continue;
			snprintf(metric, sizeof(metric), "%s",
				 alt_op_name((enum child_op_type)op));
			stat_row("pool_race_aborted", metric,
				 shm->stats.pool_race_aborted[op]);
		}

		/* Per-childop edge-discovery attribution: rendered sorted by
		 * count descending so the operator sees the dominant alt-op
		 * coverage contributors first.  CHILD_OP_SYSCALL is skipped
		 * because the syscall path attributes its edges via the
		 * explorer/bandit strategy counters; including it here would
		 * double-count against KCOV total. */
		{
			struct { unsigned int op; unsigned long count; }
				ranked[NR_CHILD_OP_TYPES];
			unsigned int nranked = 0, ri, rj;

			for (op = CHILD_OP_SYSCALL + 1;
			     op < NR_CHILD_OP_TYPES; op++) {
				unsigned long v =
					shm->stats.childop_edges_discovered[op];
				if (v == 0)
					continue;
				ranked[nranked].op = op;
				ranked[nranked].count = v;
				nranked++;
			}
			for (ri = 1; ri < nranked; ri++) {
				for (rj = ri; rj > 0 &&
				     ranked[rj].count > ranked[rj - 1].count;
				     rj--) {
					unsigned int to = ranked[rj].op;
					unsigned long tc = ranked[rj].count;
					ranked[rj] = ranked[rj - 1];
					ranked[rj - 1].op = to;
					ranked[rj - 1].count = tc;
				}
			}
			for (ri = 0; ri < nranked; ri++) {
				snprintf(metric, sizeof(metric), "%s",
					 alt_op_name((enum child_op_type)ranked[ri].op));
				stat_row("childop_edges_discovered",
					 metric, ranked[ri].count);
			}
		}

		/* Per-childop NEW-EDGE-CALL count: parallel ranked dump
		 * to childop_edges_discovered above so the operator can
		 * see both the edge total (above) and the productive-call
		 * count (here) side-by-side.  Same edge/call mismatch
		 * matters for the plateau classifier's Rule 2 ratio --
		 * the call counter here is the apples-to-apples
		 * comparator against the syscall-path bandit/explorer
		 * call counters. */
		{
			struct { unsigned int op; unsigned long count; }
				ranked[NR_CHILD_OP_TYPES];
			unsigned int nranked = 0, ri, rj;

			for (op = CHILD_OP_SYSCALL + 1;
			     op < NR_CHILD_OP_TYPES; op++) {
				unsigned long v =
					shm->stats.childop_calls_with_edges[op];
				if (v == 0)
					continue;
				ranked[nranked].op = op;
				ranked[nranked].count = v;
				nranked++;
			}
			for (ri = 1; ri < nranked; ri++) {
				for (rj = ri; rj > 0 &&
				     ranked[rj].count > ranked[rj - 1].count;
				     rj--) {
					unsigned int to = ranked[rj].op;
					unsigned long tc = ranked[rj].count;
					ranked[rj] = ranked[rj - 1];
					ranked[rj - 1].op = to;
					ranked[rj - 1].count = tc;
				}
			}
			for (ri = 0; ri < nranked; ri++) {
				snprintf(metric, sizeof(metric), "%s",
					 alt_op_name((enum child_op_type)ranked[ri].op));
				stat_row("childop_calls_with_edges",
					 metric, ranked[ri].count);
			}
		}

		/* Per-childop "last successful dispatch" fleet-clock
		 * timestamp, rendered alongside the per-op edge / call
		 * tables above so the operator sees calls, productive
		 * calls, and last-success-ts side-by-side per op.  Sorted
		 * by timestamp descending -- the most recently active op
		 * lands first, the oldest survivors trail it, and ops
		 * whose stamp is far behind shm_published->fleet_op_count
		 * are the dormancy candidates.  0 means "never
		 * succeeded" and is skipped (rendered as absent), matching
		 * the skip-zero convention in the two ranked dumps above.
		 * CHILD_OP_SYSCALL is skipped for the same reason as the
		 * sibling tables: the syscall path attributes its own
		 * activity via parent_stats.op_count / strategy counters
		 * and never bumps the per-childop arrays. */
		{
			struct { unsigned int op; unsigned long count; }
				ranked[NR_CHILD_OP_TYPES];
			unsigned int nranked = 0, ri, rj;

			for (op = CHILD_OP_SYSCALL + 1;
			     op < NR_CHILD_OP_TYPES; op++) {
				unsigned long v =
					shm->stats.childop_last_success_ts[op];
				if (v == 0)
					continue;
				ranked[nranked].op = op;
				ranked[nranked].count = v;
				nranked++;
			}
			for (ri = 1; ri < nranked; ri++) {
				for (rj = ri; rj > 0 &&
				     ranked[rj].count > ranked[rj - 1].count;
				     rj--) {
					unsigned int to = ranked[rj].op;
					unsigned long tc = ranked[rj].count;
					ranked[rj] = ranked[rj - 1];
					ranked[rj - 1].op = to;
					ranked[rj - 1].count = tc;
				}
			}
			for (ri = 0; ri < nranked; ri++) {
				snprintf(metric, sizeof(metric), "%s",
					 alt_op_name((enum child_op_type)ranked[ri].op));
				stat_row("childop_last_success_ts",
					 metric, ranked[ri].count);
			}
		}

		/* Per-childop setup-accepted yield: counts invocations that
		 * cleared the childop's one-shot setup / capability /
		 * namespace probe and reached the ready-to-exercise point.
		 * Read alongside childop_invocations[] to compute the
		 * setup-yield ratio per op.  Stays at 0 until per-childop
		 * producers are wired; until then the per-op dump simply
		 * omits the row (skip-zero, matching the sibling tables).
		 * CHILD_OP_SYSCALL is skipped for the same reason as above. */
		{
			struct { unsigned int op; unsigned long count; }
				ranked[NR_CHILD_OP_TYPES];
			unsigned int nranked = 0, ri, rj;

			for (op = CHILD_OP_SYSCALL + 1;
			     op < NR_CHILD_OP_TYPES; op++) {
				unsigned long v =
					shm->stats.childop_setup_accepted[op];
				if (v == 0)
					continue;
				ranked[nranked].op = op;
				ranked[nranked].count = v;
				nranked++;
			}
			for (ri = 1; ri < nranked; ri++) {
				for (rj = ri; rj > 0 &&
				     ranked[rj].count > ranked[rj - 1].count;
				     rj--) {
					unsigned int to = ranked[rj].op;
					unsigned long tc = ranked[rj].count;
					ranked[rj] = ranked[rj - 1];
					ranked[rj - 1].op = to;
					ranked[rj - 1].count = tc;
				}
			}
			for (ri = 0; ri < nranked; ri++) {
				snprintf(metric, sizeof(metric), "%s",
					 alt_op_name((enum child_op_type)ranked[ri].op));
				stat_row("childop_setup_accepted",
					 metric, ranked[ri].count);
			}
		}

		/* Per-childop data-path entry count: counts invocations that
		 * crossed from setup into the kernel-facing data path.
		 * setup_accepted - data_path is the count of invocations
		 * that accepted setup but bailed before exercising the
		 * kernel.  Stays at 0 until per-childop producers are wired.
		 * CHILD_OP_SYSCALL is skipped for the same reason as above. */
		{
			struct { unsigned int op; unsigned long count; }
				ranked[NR_CHILD_OP_TYPES];
			unsigned int nranked = 0, ri, rj;

			for (op = CHILD_OP_SYSCALL + 1;
			     op < NR_CHILD_OP_TYPES; op++) {
				unsigned long v =
					shm->stats.childop_data_path[op];
				if (v == 0)
					continue;
				ranked[nranked].op = op;
				ranked[nranked].count = v;
				nranked++;
			}
			for (ri = 1; ri < nranked; ri++) {
				for (rj = ri; rj > 0 &&
				     ranked[rj].count > ranked[rj - 1].count;
				     rj--) {
					unsigned int to = ranked[rj].op;
					unsigned long tc = ranked[rj].count;
					ranked[rj] = ranked[rj - 1];
					ranked[rj - 1].op = to;
					ranked[rj - 1].count = tc;
				}
			}
			for (ri = 0; ri < nranked; ri++) {
				snprintf(metric, sizeof(metric), "%s",
					 alt_op_name((enum child_op_type)ranked[ri].op));
				stat_row("childop_data_path",
					 metric, ranked[ri].count);
			}
		}

		/* Per-childop setup-bound scorecard: for ops that were
		 * invoked at all, rank ASCENDING by the setup-yield ratio
		 * setup_accepted / invocations, rendered as a permille
		 * (0..1000) integer to avoid float in the stats path.  A
		 * low ratio means many invocations bailed before clearing
		 * setup -- those ops want environment / capability / probe
		 * attention.  Skip-zero is implicit via the
		 * childop_invocations[op] > 0 filter, which also guards
		 * the divide.  CHILD_OP_SYSCALL is skipped for the same
		 * reason as the sibling tables. */
		{
			struct { unsigned int op; unsigned long ratio; }
				ranked[NR_CHILD_OP_TYPES];
			unsigned int nranked = 0, ri, rj;

			for (op = CHILD_OP_SYSCALL + 1;
			     op < NR_CHILD_OP_TYPES; op++) {
				unsigned long inv =
					shm->stats.childop_invocations[op];
				unsigned long acc;

				if (inv == 0)
					continue;
				acc = shm->stats.childop_setup_accepted[op];
				ranked[nranked].op = op;
				ranked[nranked].ratio = acc * 1000UL / inv;
				nranked++;
			}
			for (ri = 1; ri < nranked; ri++) {
				for (rj = ri; rj > 0 &&
				     ranked[rj].ratio < ranked[rj - 1].ratio;
				     rj--) {
					unsigned int to = ranked[rj].op;
					unsigned long tr = ranked[rj].ratio;
					ranked[rj] = ranked[rj - 1];
					ranked[rj - 1].op = to;
					ranked[rj - 1].ratio = tr;
				}
			}
			for (ri = 0; ri < nranked; ri++) {
				unsigned long r = ranked[ri].ratio;

				/* Some childops bump setup_accepted more than
				 * once per dispatch, so acc can exceed inv and
				 * the raw ratio can exceed 1000.  Clamp at the
				 * render site to preserve the documented
				 * 0..1000 permille invariant; the ordering
				 * across over-the-cap ops is not meaningful
				 * (they are all "setup never bailed"). */
				if (r > 1000UL)
					r = 1000UL;
				snprintf(metric, sizeof(metric), "%s",
					 alt_op_name((enum child_op_type)ranked[ri].op));
				stat_row("childop_setup_bound_permille",
					 metric, r);
			}
		}

		/* Per-childop data-path-cold scorecard: for ops that
		 * reached the kernel data path at all, rank ASCENDING by
		 * calls_with_edges / data_path, rendered as a permille
		 * (0..1000) integer to avoid float in the stats path.  A
		 * low ratio means many kernel-facing calls but no new
		 * edges -- those ops want generator / state work or
		 * demotion.  Skip-zero is implicit via the
		 * childop_data_path[op] > 0 filter, which also guards the
		 * divide.  CHILD_OP_SYSCALL is skipped for the same
		 * reason as the sibling tables. */
		{
			struct { unsigned int op; unsigned long ratio; }
				ranked[NR_CHILD_OP_TYPES];
			unsigned int nranked = 0, ri, rj;

			for (op = CHILD_OP_SYSCALL + 1;
			     op < NR_CHILD_OP_TYPES; op++) {
				unsigned long dp =
					shm->stats.childop_data_path[op];
				unsigned long ce;

				if (dp == 0)
					continue;
				ce = shm->stats.childop_calls_with_edges[op];
				ranked[nranked].op = op;
				ranked[nranked].ratio = ce * 1000UL / dp;
				nranked++;
			}
			for (ri = 1; ri < nranked; ri++) {
				for (rj = ri; rj > 0 &&
				     ranked[rj].ratio < ranked[rj - 1].ratio;
				     rj--) {
					unsigned int to = ranked[rj].op;
					unsigned long tr = ranked[rj].ratio;
					ranked[rj] = ranked[rj - 1];
					ranked[rj - 1].op = to;
					ranked[rj - 1].ratio = tr;
				}
			}
			for (ri = 0; ri < nranked; ri++) {
				snprintf(metric, sizeof(metric), "%s",
					 alt_op_name((enum child_op_type)ranked[ri].op));
				stat_row("childop_data_path_cold_permille",
					 metric, ranked[ri].ratio);
			}
		}

		/* Per-childop missing Step-B yield producer map: emit a row
		 * for each op that has been dispatched at least once but
		 * still has no setup-accepted producer wired -- i.e.
		 * childop_invocations[op] > 0 AND
		 * childop_setup_accepted[op] == 0.  These are the ops that
		 * silently skip the setup/data-path scorecards because no
		 * Step-B producer is bumping setup_accepted on the hot path.
		 * The value rendered is the invocations count so the
		 * operator can see how much dispatch pressure the missing
		 * producer is masking.  Self-maintains as Step-B producers
		 * land: rows disappear once setup_accepted[op] starts
		 * moving.  CHILD_OP_SYSCALL is skipped for the same reason
		 * as the sibling tables. */
		for (op = CHILD_OP_SYSCALL + 1;
		     op < NR_CHILD_OP_TYPES; op++) {
			unsigned long inv =
				shm->stats.childop_invocations[op];
			if (inv == 0)
				continue;
			if (shm->stats.childop_setup_accepted[op] != 0)
				continue;
			snprintf(metric, sizeof(metric), "%s",
				 alt_op_name((enum child_op_type)op));
			stat_row("childop_missing_producer", metric, inv);
		}

		/* Per-childop one-shot latch reason: rendered as the integer
		 * enum childop_latch_reason code (see include/child.h).  No
		 * string table is materialised at the dump layer -- the
		 * operator decodes.  0 (CHILDOP_LATCH_NONE) is skipped so
		 * the per-op dump only emits rows for ops that actually
		 * latched themselves off.  CHILD_OP_SYSCALL is skipped for
		 * the same reason as above. */
		for (op = CHILD_OP_SYSCALL + 1;
		     op < NR_CHILD_OP_TYPES; op++) {
			unsigned long v =
				shm->stats.childop_latch_reason[op];
			if (v == 0)
				continue;
			snprintf(metric, sizeof(metric), "%s",
				 alt_op_name((enum child_op_type)op));
			stat_row("childop_latch_reason", metric, v);
		}

		/* SHADOW score-driven recommendation counters bumped from
		 * close_window_and_decide() in child-canary.c.  Divergence
		 * between these and the live promote/demote count
		 * (canary_op_state.total_demotions / total_promotions, surfaced
		 * via canary_queue_summary()) is the signal the 75.2.B
		 * enforcement work needs before it can take over the picker;
		 * surfacing them here keeps the dump self-contained.  Skip-
		 * zero, CHILD_OP_SYSCALL-skipped (matches the surrounding
		 * per-childop arrays). */
		for (op = CHILD_OP_SYSCALL + 1;
		     op < NR_CHILD_OP_TYPES; op++) {
			unsigned long v =
				shm->stats.childop_would_demote[op];
			if (v == 0)
				continue;
			snprintf(metric, sizeof(metric), "%s",
				 alt_op_name((enum child_op_type)op));
			stat_row("childop_would_demote", metric, v);
		}
		for (op = CHILD_OP_SYSCALL + 1;
		     op < NR_CHILD_OP_TYPES; op++) {
			unsigned long v =
				shm->stats.childop_would_promote[op];
			if (v == 0)
				continue;
			snprintf(metric, sizeof(metric), "%s",
				 alt_op_name((enum child_op_type)op));
			stat_row("childop_would_promote", metric, v);
		}
	}
}

static void dump_stats_shared_buffer_misc(void)
{
	if (parent_stats.shared_buffer_redirected)
		stat_row("shared_buffer", "args_redirected",     parent_stats.shared_buffer_redirected);
	if (parent_stats.libc_heap_redirected)
		stat_row("shared_buffer", "libc_heap_redirected", parent_stats.libc_heap_redirected);
	if (parent_stats.libc_heap_embedded_redirected)
		stat_row("shared_buffer", "libc_heap_embedded_redirected",
			 parent_stats.libc_heap_embedded_redirected);
	if (parent_stats.asb_relocate_readable_skip)
		stat_row("shared_buffer", "asb_relocate_readable_skip",
			 parent_stats.asb_relocate_readable_skip);
	if (parent_stats.asb_relocate_copy_fault)
		stat_row("shared_buffer", "asb_relocate_copy_fault",
			 parent_stats.asb_relocate_copy_fault);
	if (parent_stats.heap_pointer_outside_cache)
		stat_row("shared_buffer", "heap_pointer_outside_cache",
			 parent_stats.heap_pointer_outside_cache);
	if (parent_stats.heap_brk_stale_window_hit)
		stat_row("shared_buffer", "heap_brk_stale_window_hit",
			 parent_stats.heap_brk_stale_window_hit);
	if (parent_stats.range_overlaps_shared_rejects) {
		stat_row("shared_buffer", "range_overlaps_shared_rejects",
			 parent_stats.range_overlaps_shared_rejects);
		if (verbosity > 1)
			dump_range_overlaps_shared_top_offenders();
	}
	if (shm->stats.shared_region_overflow)
		stat_row("shared_buffer", "shared_region_overflow",
			 shm->stats.shared_region_overflow);
	if (parent_stats.get_writable_address_scribbled_shm_range)
		stat_row("shared_buffer", "get_writable_address_scribbled_shm_range",
			 parent_stats.get_writable_address_scribbled_shm_range);
	if (parent_stats.get_writable_address_scribbled_mprotect_mmap)
		stat_row("shared_buffer", "get_writable_address_scribbled_mprotect_mmap",
			 parent_stats.get_writable_address_scribbled_mprotect_mmap);
	if (parent_stats.get_writable_address_scribbled_mprotect_shm)
		stat_row("shared_buffer", "get_writable_address_scribbled_mprotect_shm",
			 parent_stats.get_writable_address_scribbled_mprotect_shm);
	if (parent_stats.get_writable_address_scribbled_postmp_mmap)
		stat_row("shared_buffer", "get_writable_address_scribbled_postmp_mmap",
			 parent_stats.get_writable_address_scribbled_postmp_mmap);
	if (parent_stats.get_writable_address_scribbled_postmp_shm)
		stat_row("shared_buffer", "get_writable_address_scribbled_postmp_shm",
			 parent_stats.get_writable_address_scribbled_postmp_shm);
	if (parent_stats.get_writable_address_enomem_exhausted)
		stat_row("shared_buffer", "get_writable_address_enomem_exhausted",
			 parent_stats.get_writable_address_enomem_exhausted);
	if (parent_stats.get_writable_address_bookkeeping_ro_fault)
		stat_row("shared_buffer", "get_writable_address_bookkeeping_ro_fault",
			 parent_stats.get_writable_address_bookkeeping_ro_fault);
	if (parent_stats.mm_gate_post_slip)
		stat_row("shared_buffer", "mm_gate_post_slip",
			 parent_stats.mm_gate_post_slip);
	if (parent_stats.children_recycled_on_storm)
		stat_row("corruption", "children_recycled_on_storm",
			 parent_stats.children_recycled_on_storm);
	if (parent_stats.watchdog_fd_evict)
		stat_row("watchdog", "watchdog_fd_evict",
			 parent_stats.watchdog_fd_evict);

	if (verbosity > 1)
		dump_syscall_category_histogram();
}

static void dump_stats_strategy_summary(void)
{
	if (shm->stats.bandit_cmp_reward_added)
		stat_row("strategy", "bandit_cmp_reward_added",
			 shm->stats.bandit_cmp_reward_added);
	if (shm->stats.frontier_strategy_picks)
		stat_row("strategy", "frontier_strategy_picks",
			 shm->stats.frontier_strategy_picks);
	if (shm->stats.frontier_live_picks)
		stat_row("strategy", "frontier_live_picks",
			 shm->stats.frontier_live_picks);
	if (shm->stats.frontier_silent_picks)
		stat_row("strategy", "frontier_silent_picks",
			 shm->stats.frontier_silent_picks);
	/* SHADOW-ONLY observability companions to frontier_silent_picks:
	 * the candidate count (how many threshold-crossings the silent
	 * regime has produced) and the threshold itself, emitted side by
	 * side so the operator can interpret the count without consulting
	 * the source.  Neither value is read by the live picker math. */
	if (shm->stats.frontier_shadow_decay_candidates)
		stat_row("strategy", "frontier_shadow_decay_candidates",
			 shm->stats.frontier_shadow_decay_candidates);
	stat_row("strategy", "frontier_shadow_decay_streak_threshold",
		 FRONTIER_SHADOW_DECAY_STREAK);
	/* Tightened decay predicate (sibling of the looser counter above):
	 * adds the no-CMP-novelty + no-errno-shift UNLESS clause to the
	 * threshold-crossing test, and tallies the projected demote count
	 * across all silent-regime picks past the threshold.  The (looser
	 * candidates / candidates) ratio tells the operator what fraction
	 * of N-silent crossings the CMP/errno tightening would have spared;
	 * the would_skip / silent_picks ratio is the projected pick share a
	 * live silent-decay variant would demote. */
	if (shm->stats.frontier_decay_candidates)
		stat_row("strategy", "frontier_decay_candidates",
			 shm->stats.frontier_decay_candidates);
	if (shm->stats.frontier_decay_would_skip)
		stat_row("strategy", "frontier_decay_would_skip",
			 shm->stats.frontier_decay_would_skip);
	/* Arm-B-only live reject count for the silent-streak decay above.
	 * Pairs with frontier_decay_would_skip (both arms) as the headline
	 * arm-B behaviour delta; normalise against the Arm-B silent-pick
	 * throughput recoverable from frontier_silent_picks and the
	 * frontier_silent_decay_arm_{a,b}_children cohort split in kcov_shm. */
	if (shm->stats.frontier_silent_decay_live_rejects)
		stat_row("strategy", "frontier_silent_decay_live_rejects",
			 shm->stats.frontier_silent_decay_live_rejects);
	/* SHADOW-ONLY LIVE-regime cooldown projections.  Sibling block to
	 * the silent-streak decay rows above: candidates is the distinct
	 * cooldown-episode count (one bump per FRONTIER_LIVE_MISS_COOLDOWN
	 * crossing per syscall); would_skip is the projected demote count a
	 * live cooldown variant of the picker would produce, normalised
	 * against frontier_live_picks for the projected reclaim fraction.
	 * The threshold is emitted alongside so the operator can interpret
	 * the candidate count without consulting the source, matching the
	 * frontier_shadow_decay_streak_threshold row above. */
	if (shm->stats.frontier_live_cooldown_candidates)
		stat_row("strategy", "frontier_live_cooldown_candidates",
			 shm->stats.frontier_live_cooldown_candidates);
	if (shm->stats.frontier_live_would_skip)
		stat_row("strategy", "frontier_live_would_skip",
			 shm->stats.frontier_live_would_skip);
	stat_row("strategy", "frontier_live_miss_cooldown_threshold",
		 FRONTIER_LIVE_MISS_COOLDOWN);
	/* Did-decay observability counter for the --frontier-live-cooldown
	 * lever.  One bump per (nr, rotation) where the early ring-decay
	 * halved a non-zero cached sum.  Read alongside
	 * frontier_live_would_skip (F3 projection) to compare the projected
	 * vs the actually-applied cooldown volume; the ratio reflects how
	 * often the rotation-time decay catches a syscall the per-pick F3
	 * projection had already counted as a candidate. */
	if (shm->stats.frontier_live_cooldown_decays)
		stat_row("strategy", "frontier_live_cooldown_decays",
			 shm->stats.frontier_live_cooldown_decays);
	/* Blanket LIVE-regime probabilistic pick-reject (safe down-
	 * payment).  Reclaims ~1 / FRONTIER_LIVE_DECAY_REJECT_DENOM of
	 * LIVE-ring picks unconditionally; the reject rate against
	 * accepted picks is rejects / (rejects + frontier_live_picks)
	 * and should converge to 1 / REJECT_DENOM.  Read alongside
	 * frontier_live_would_skip (the F3 SHADOW projection) to gauge
	 * the headroom a targeted variant of this reject would unlock. */
	if (shm->stats.frontier_live_decay_live_rejects)
		stat_row("strategy", "frontier_live_decay_live_rejects",
			 shm->stats.frontier_live_decay_live_rejects);
	/* SHADOW + per-child A/B errno-plateau decay (silent-regime accept
	 * site): would_skip is the both-arms shadow demote count, live_
	 * rejects is the arm-B-only actual demote count, overlap_silent is
	 * the both-arms shadow count of picks where the consecutive-silent
	 * shadow predicate ALSO fires.  Emitted side by side with the
	 * silent-streak shadow rows above so the operator can read the
	 * orthogonal coverage (would_skip - overlap_silent) at a glance. */
	if (shm->stats.frontier_errno_decay_would_skip)
		stat_row("strategy", "frontier_errno_decay_would_skip",
			 shm->stats.frontier_errno_decay_would_skip);
	if (shm->stats.frontier_errno_decay_live_rejects)
		stat_row("strategy", "frontier_errno_decay_live_rejects",
			 shm->stats.frontier_errno_decay_live_rejects);
	if (shm->stats.frontier_errno_decay_overlap_silent)
		stat_row("strategy", "frontier_errno_decay_overlap_silent",
			 shm->stats.frontier_errno_decay_overlap_silent);
	/* SHADOW-ONLY A/B scoring for the frontier-blend cold-weight
	 * blend.  Emitted as a sibling block to the silent-decay shadow
	 * counters above; the picker still consumes the OLD weight from
	 * frontier_cold_weight() and these counters expose how often the
	 * blended formula would have steered differently.  See the
	 * struct-field comments in include/stats.h for semantics. */
	if (shm->stats.frontier_blend_samples) {
		stat_row("strategy", "frontier_blend_samples",
			 shm->stats.frontier_blend_samples);
		stat_row("strategy", "frontier_blend_new_lower",
			 shm->stats.frontier_blend_new_lower);
		stat_row("strategy", "frontier_blend_new_higher",
			 shm->stats.frontier_blend_new_higher);
		stat_row("strategy", "frontier_blend_new_equal",
			 shm->stats.frontier_blend_new_equal);
		stat_row("strategy", "frontier_blend_old_weight_sum",
			 shm->stats.frontier_blend_old_weight_sum);
		stat_row("strategy", "frontier_blend_new_weight_sum",
			 shm->stats.frontier_blend_new_weight_sum);
	}
	if (shm->stats.frontier_underflow_prevented)
		stat_row("strategy", "frontier_underflow_prevented",
			 shm->stats.frontier_underflow_prevented);
	if (shm->stats.frontier_intervention_pulls)
		stat_row("strategy", "frontier_intervention_pulls",
			 shm->stats.frontier_intervention_pulls);
	if (shm->stats.frontier_intervention_cold_skipped)
		stat_row("strategy", "frontier_intervention_cold_skipped",
			 shm->stats.frontier_intervention_cold_skipped);
	if (shm->stats.plateau_forced_windows)
		stat_row("strategy", "plateau_forced_windows",
			 shm->stats.plateau_forced_windows);
	/* SHADOW-ONLY wall-lever.  eligible_total / would_suppress_
	 * total expose the data-driven gate's projected reclaim share on every
	 * plateau-active pick; baseline_calls is the fleet mean per_syscall_
	 * calls the predicate scaled WALL_LEVER_HIGH_MULT against.  See the
	 * struct-field comment in include/stats.h. */
	if (shm->stats.wall_lever_eligible_total) {
		stat_row("strategy", "wall_lever_eligible_total",
			 shm->stats.wall_lever_eligible_total);
		stat_row("strategy", "wall_lever_would_suppress_total",
			 shm->stats.wall_lever_would_suppress_total);
		stat_row("strategy", "wall_lever_baseline_calls",
			 __atomic_load_n(&shm->wall_lever_baseline_calls,
					 __ATOMIC_RELAXED));

		/* Top-N per-syscall would-suppress breakdown.  The aggregate
		 * total above is the headline reclaim projection a live
		 * variant would produce; this block exposes WHICH syscalls
		 * the projection is attributable to, so the budget can be
		 * audited by-syscall (against the existing top edge / pick
		 * blocks) BEFORE any live suppression is enabled.  Mirrors
		 * the absolute-totals top-N shape and biarch table choice
		 * the per-syscall edge top-N in dump_stats() already uses:
		 * under biarch only the 64-bit table is iterated -- 32-bit
		 * nrs collide with 64-bit ones in the same index space and
		 * would shadow them in the display. */
		{
			unsigned int top_nr[TOP_SYSCALLS_DUMP_TOPN];
			unsigned long top_vals[TOP_SYSCALLS_DUMP_TOPN];
			unsigned int top_count = 0;
			unsigned int nr_to_scan;
			const struct syscalltable *table;
			unsigned int i;
			int j;

			if (biarch) {
				nr_to_scan = max_nr_64bit_syscalls;
				table = syscalls_64bit;
			} else {
				nr_to_scan = max_nr_syscalls;
				table = syscalls;
			}
			if (nr_to_scan > MAX_NR_SYSCALL)
				nr_to_scan = MAX_NR_SYSCALL;

			memset(top_vals, 0, sizeof(top_vals));
			for (i = 0; i < nr_to_scan; i++) {
				unsigned long v = __atomic_load_n(
					&shm->stats.wall_lever_would_suppress[i],
					__ATOMIC_RELAXED);

				if (v == 0)
					continue;
				topn_push(top_vals, top_nr, &top_count,
					  TOP_SYSCALLS_DUMP_TOPN, v, i);
			}

			if (top_count > 0) {
				output(0, "Top wall-lever would-suppress "
					  "syscalls (shadow-only):\n");
				for (j = 0; j < (int)top_count; j++) {
					struct syscallentry *entry =
						table[top_nr[j]].entry;
					const char *name = entry ? entry->name
								 : "???";

					output(0, "  %-24s %lu\n",
					       name, top_vals[j]);
				}
			}
		}
	}
	/* Unconditional wall-lever would-suppress observability.  The
	 * sibling block above only renders when the predicate has
	 * registered at least one eligible pick (wall_lever_eligible_total
	 * != 0); this block surfaces the running would-suppress total and
	 * its top-N per-syscall breakdown on EVERY dump so the projected
	 * reclaim share + by-syscall attribution stay visible on runs
	 * where the eligibility gate has not triggered yet.  Skip-zero on
	 * the per-syscall scan + a top_count guard on the header suppress
	 * the empty top-N; the scalar total renders unconditionally so a
	 * 0 is an active "nothing accumulated" signal rather than silence.
	 * Mirrors the biarch table choice + topn_push idiom used above. */
	stat_row("strategy", "wall_lever_would_suppress_total",
		 shm->stats.wall_lever_would_suppress_total);
	{
		unsigned int top_nr[TOP_SYSCALLS_DUMP_TOPN];
		unsigned long top_vals[TOP_SYSCALLS_DUMP_TOPN];
		unsigned int top_count = 0;
		unsigned int nr_to_scan;
		const struct syscalltable *table;
		unsigned int i;
		int j;

		if (biarch) {
			nr_to_scan = max_nr_64bit_syscalls;
			table = syscalls_64bit;
		} else {
			nr_to_scan = max_nr_syscalls;
			table = syscalls;
		}
		if (nr_to_scan > MAX_NR_SYSCALL)
			nr_to_scan = MAX_NR_SYSCALL;

		memset(top_vals, 0, sizeof(top_vals));
		for (i = 0; i < nr_to_scan; i++) {
			unsigned long v = __atomic_load_n(
				&shm->stats.wall_lever_would_suppress[i],
				__ATOMIC_RELAXED);

			if (v == 0)
				continue;
			topn_push(top_vals, top_nr, &top_count,
				  TOP_SYSCALLS_DUMP_TOPN, v, i);
		}

		if (top_count > 0) {
			output(0, "Top wall-lever would-suppress "
				  "syscalls (running, shadow-only):\n");
			for (j = 0; j < (int)top_count; j++) {
				struct syscallentry *entry =
					table[top_nr[j]].entry;
				const char *name = entry ? entry->name
							 : "???";

				output(0, "  %-24s %lu\n",
				       name, top_vals[j]);
			}
		}
	}
	if (shm->stats.strategy_explorer_picks)
		stat_row("strategy", "strategy_explorer_picks",
			 shm->stats.strategy_explorer_picks);

	dump_strategy_stats();
}

static void dump_stats_childop_runs_local(void)
{
	stat_category_emit_text(&refcount_audit_category);

	if (shm->stats.fs_lifecycle_tmpfs   || shm->stats.fs_lifecycle_ramfs   ||
	    shm->stats.fs_lifecycle_rdonly  || shm->stats.fs_lifecycle_overlay ||
	    shm->stats.fs_lifecycle_quota   || shm->stats.fs_lifecycle_bind    ||
	    shm->stats.fs_lifecycle_unsupported) {
		stat_row("fs_lifecycle", "tmpfs",       shm->stats.fs_lifecycle_tmpfs);
		stat_row("fs_lifecycle", "ramfs",       shm->stats.fs_lifecycle_ramfs);
		stat_row("fs_lifecycle", "rdonly",      shm->stats.fs_lifecycle_rdonly);
		stat_row("fs_lifecycle", "overlay",     shm->stats.fs_lifecycle_overlay);
		stat_row("fs_lifecycle", "quota",       shm->stats.fs_lifecycle_quota);
		stat_row("fs_lifecycle", "bind",        shm->stats.fs_lifecycle_bind);
		stat_row("fs_lifecycle", "unsupported", shm->stats.fs_lifecycle_unsupported);
	}

	stat_category_emit_text(&signal_storm_category);

	if (shm->stats.futex_storm_runs)
		output(0, "\nfutex storm: runs:%lu inner_crashed:%lu iters:%lu\n",
			shm->stats.futex_storm_runs,
			shm->stats.futex_storm_inner_crashed,
			shm->stats.futex_storm_iters);

	stat_category_emit_text(&pipe_thrash_category);

	stat_category_emit_text(&fork_storm_category);

	stat_category_emit_text(&cpu_hotplug_rider_category);

	stat_category_emit_text(&pidfd_storm_category);

	stat_category_emit_text(&madvise_cycler_category);

	stat_category_emit_text(&keyring_spam_category);

	stat_category_emit_text(&vdso_mremap_race_category);

	stat_category_emit_text(&flock_thrash_category);

	stat_category_emit_text(&xattr_thrash_category);

	stat_category_emit_text(&epoll_volatility_category);

	stat_category_emit_text(&cgroup_churn_category);

	stat_category_emit_text(&mount_churn_category);

	stat_category_emit_text(&umount_race_category);

	stat_category_emit_text(&statmount_idmap_category);

	stat_category_emit_text(&uffd_churn_category);

	stat_category_emit_text(&iouring_flood_category);

	stat_category_emit_text(&close_racer_category);
}

static void __cold dump_stats_childop_runs_network(void)
{
	stat_category_emit_text(&socket_family_chain_category);

	stat_category_emit_text(&socket_family_grammar_category);

	stat_category_emit_text(&tls_rotate_category);

	if (shm->stats.packet_fanout_runs) {
		stat_row("packet_fanout_thrash", "runs",             shm->stats.packet_fanout_runs);
		stat_row("packet_fanout_thrash", "setup_failed",     shm->stats.packet_fanout_setup_failed);
		stat_row("packet_fanout_thrash", "ring_failed",      shm->stats.packet_fanout_ring_failed);
		stat_row("packet_fanout_thrash", "rings_installed",  shm->stats.packet_fanout_rings_installed);
		stat_row("packet_fanout_thrash", "mmap_failed",      shm->stats.packet_fanout_mmap_failed);
		stat_row("packet_fanout_thrash", "joins",            shm->stats.packet_fanout_joins);
		stat_row("packet_fanout_thrash", "rejoins_ok",       shm->stats.packet_fanout_rejoins_ok);
		stat_row("packet_fanout_thrash", "rejoins_rejected", shm->stats.packet_fanout_rejoins_rejected);
	}

	if (shm->stats.eth_emitter_runs) {
		stat_row("eth_emitter", "runs",               shm->stats.eth_emitter_runs);
		stat_row("eth_emitter", "setup_failed",       shm->stats.eth_emitter_setup_failed);
		stat_row("eth_emitter", "short",              shm->stats.eth_emitter_short);
		stat_row("eth_emitter", "sends_ok",           shm->stats.eth_emitter_sends_ok);
		stat_row("eth_emitter", "sends_failed",       shm->stats.eth_emitter_sends_failed);
		stat_row("eth_emitter", "tmpl_arp",           shm->stats.eth_emitter_per_tmpl[0]);
		stat_row("eth_emitter", "tmpl_ipv4_frag_zero", shm->stats.eth_emitter_per_tmpl[1]);
		stat_row("eth_emitter", "tmpl_ipv6_na",       shm->stats.eth_emitter_per_tmpl[2]);
		stat_row("eth_emitter", "tmpl_vlan_qinq",     shm->stats.eth_emitter_per_tmpl[3]);
		stat_row("eth_emitter", "tmpl_bad_ethertype", shm->stats.eth_emitter_per_tmpl[4]);
	}

	if (shm->stats.iouring_multishot_runs) {
		stat_row("iouring_net_multishot", "runs",             shm->stats.iouring_multishot_runs);
		stat_row("iouring_net_multishot", "setup_failed",     shm->stats.iouring_multishot_setup_failed);
		stat_row("iouring_net_multishot", "pbuf_ring_ok",     shm->stats.iouring_multishot_pbuf_ring_ok);
		stat_row("iouring_net_multishot", "pbuf_legacy_ok",   shm->stats.iouring_multishot_pbuf_legacy_ok);
		stat_row("iouring_net_multishot", "armed",            shm->stats.iouring_multishot_armed);
		stat_row("iouring_net_multishot", "packets_sent",     shm->stats.iouring_multishot_packets_sent);
		stat_row("iouring_net_multishot", "completions",      shm->stats.iouring_multishot_completions);
		stat_row("iouring_net_multishot", "cancel_submitted", shm->stats.iouring_multishot_cancel_submitted);
		stat_row("iouring_net_multishot", "napi_register_ok",   shm->stats.iouring_napi_register_ok);
		stat_row("iouring_net_multishot", "napi_register_fail", shm->stats.iouring_napi_register_fail);
		stat_row("iouring_net_multishot", "napi_unregister_ok", shm->stats.iouring_napi_unregister_ok);
		stat_row("iouring_net_multishot", "napi_unregister_fail", shm->stats.iouring_napi_unregister_fail);
	}

	stat_category_emit_text(&tcp_ao_rotate_category);

	stat_category_emit_text(&tcp_md5_listener_race_category);

	stat_category_emit_text(&ipv6_pmtu_race_category);

	stat_category_emit_text(&vrf_fib_churn_category);

	stat_category_emit_text(&mpls_route_churn_category);

	stat_category_emit_text(&netlink_monitor_race_category);

	stat_category_emit_text(&tipc_link_churn_category);

	stat_category_emit_text(&tls_ulp_churn_category);

	stat_category_emit_text(&vxlan_encap_churn_category);

	stat_category_emit_text(&ovs_tunnel_vport_churn_category);

	if (shm->stats.bridge_fdb_stp_runs) {
		stat_row("bridge_fdb_stp", "runs",            shm->stats.bridge_fdb_stp_runs);
		stat_row("bridge_fdb_stp", "setup_failed",    shm->stats.bridge_fdb_stp_setup_failed);
		stat_row("bridge_fdb_stp", "bridge_create_ok", shm->stats.bridge_fdb_stp_bridge_create_ok);
		stat_row("bridge_fdb_stp", "veth_create_ok",  shm->stats.bridge_fdb_stp_veth_create_ok);
		stat_row("bridge_fdb_stp", "raw_send_ok",     shm->stats.bridge_fdb_stp_raw_send_ok);
		stat_row("bridge_fdb_stp", "stp_toggle_ok",   shm->stats.bridge_fdb_stp_stp_toggle_ok);
		stat_row("bridge_fdb_stp", "fdb_del_ok",      shm->stats.bridge_fdb_stp_fdb_del_ok);
		stat_row("bridge_fdb_stp", "link_del_ok",     shm->stats.bridge_fdb_stp_link_del_ok);
		stat_row("bridge_fdb_stp", "vlan_mass_runs",  shm->stats.bridge_vlan_mass_runs);
		stat_row("bridge_fdb_stp", "vlan_mass_max_n", shm->stats.bridge_vlan_mass_max_n);
		stat_row("bridge_fdb_stp", "vlan_mass_enotbufs", shm->stats.bridge_vlan_mass_enotbufs);
	}

	stat_category_emit_text(&bridge_conntrack_churn_category);

	if (shm->stats.nftables_churn_runs) {
		stat_row("nftables_churn", "runs",             shm->stats.nftables_churn_runs);
		stat_row("nftables_churn", "setup_failed",     shm->stats.nftables_churn_setup_failed);
		stat_row("nftables_churn", "table_create_ok",  shm->stats.nftables_churn_table_create_ok);
		stat_row("nftables_churn", "set_create_ok",    shm->stats.nftables_churn_set_create_ok);
		stat_row("nftables_churn", "chain_create_ok",  shm->stats.nftables_churn_chain_create_ok);
		stat_row("nftables_churn", "rule_create_ok",   shm->stats.nftables_churn_rule_create_ok);
		stat_row("nftables_churn", "packet_sent_ok",   shm->stats.nftables_churn_packet_sent_ok);
		stat_row("nftables_churn", "rule_insert_ok",   shm->stats.nftables_churn_rule_insert_ok);
		stat_row("nftables_churn", "rule_del_ok",      shm->stats.nftables_churn_rule_del_ok);
		stat_row("nftables_churn", "table_del_ok",     shm->stats.nftables_churn_table_del_ok);
		stat_row("nftables_churn", "payload_expr_emit",shm->stats.nftables_churn_payload_expr_emit);
		stat_row("nftables_churn", "objref_expr_emit", shm->stats.nftables_churn_objref_expr_emit);
		stat_row("nftables_churn", "compat_validate_install_ok",     shm->stats.nft_compat_validate_install_ok);
		stat_row("nftables_churn", "compat_validate_install_fail",   shm->stats.nft_compat_validate_install_fail);
		stat_row("nftables_churn", "compat_validate_unsupported",    shm->stats.nft_compat_validate_unsupported);
		stat_row("nftables_churn", "compat_validate_per_hook_pairs", shm->stats.nft_compat_validate_per_hook_pairs);
		stat_row("nftables_churn", "dormant_abort_iters", shm->stats.nft_dormant_abort_iters);
		stat_row("nftables_churn", "dormant_abort_eperm", shm->stats.nft_dormant_abort_eperm);
		stat_row("nftables_churn", "dormant_abort_emsg",  shm->stats.nft_dormant_abort_emsg);
		stat_row("nftables_churn", "dormant_abort_ok",    shm->stats.nft_dormant_abort_ok);
		stat_row("nftables_churn", "xt_ct_iters",         shm->stats.xt_ct_iters);
		stat_row("nftables_churn", "xt_ct_eperm",         shm->stats.xt_ct_eperm);
		stat_row("nftables_churn", "xt_ct_unsupported",   shm->stats.xt_ct_unsupported);
		stat_row("nftables_churn", "xt_ct_set_ok",        shm->stats.xt_ct_set_ok);
		stat_row("nftables_churn", "xt_ct_get_ok",        shm->stats.xt_ct_get_ok);
		stat_row("nftables_churn", "xt_ct_v2_seen",       shm->stats.xt_ct_v2_seen);
		stat_row("nftables_churn", "fwd_loop_runs",             shm->stats.nft_fwd_loop_runs);
		stat_row("nftables_churn", "fwd_loop_ns_setup_failed",  shm->stats.nft_fwd_loop_ns_setup_failed);
		stat_row("nftables_churn", "fwd_loop_probe_sent_ok",    shm->stats.nft_fwd_loop_probe_sent_ok);
		stat_row("nftables_churn", "fwd_loop_completed_ok",     shm->stats.nft_fwd_loop_completed_ok);
		stat_row("nftables_churn", "l4frag_iters",              shm->stats.nft_l4frag_iters);
		stat_row("nftables_churn", "l4frag_install_ok",         shm->stats.nft_l4frag_install_ok);
		stat_row("nftables_churn", "l4frag_rule_ok",            shm->stats.nft_l4frag_rule_ok);
		stat_row("nftables_churn", "l4frag_send_ok",            shm->stats.nft_l4frag_send_ok);
		stat_row("nftables_churn", "l4frag_send_failed",        shm->stats.nft_l4frag_send_failed);
	}

	if (shm->stats.tc_qdisc_churn_runs) {
		stat_row("tc_qdisc_churn", "runs",              shm->stats.tc_qdisc_churn_runs);
		stat_row("tc_qdisc_churn", "setup_failed",      shm->stats.tc_qdisc_churn_setup_failed);
		stat_row("tc_qdisc_churn", "link_create_ok",    shm->stats.tc_qdisc_churn_link_create_ok);
		stat_row("tc_qdisc_churn", "qdisc_create_ok",   shm->stats.tc_qdisc_churn_qdisc_create_ok);
		stat_row("tc_qdisc_churn", "tclass_create_ok",  shm->stats.tc_qdisc_churn_tclass_create_ok);
		stat_row("tc_qdisc_churn", "tfilter_create_ok", shm->stats.tc_qdisc_churn_tfilter_create_ok);
		stat_row("tc_qdisc_churn", "packet_sent_ok",    shm->stats.tc_qdisc_churn_packet_sent_ok);
		stat_row("tc_qdisc_churn", "qdisc_replace_ok",  shm->stats.tc_qdisc_churn_qdisc_replace_ok);
		stat_row("tc_qdisc_churn", "tfilter_del_ok",    shm->stats.tc_qdisc_churn_tfilter_del_ok);
		stat_row("tc_qdisc_churn", "qdisc_del_ok",      shm->stats.tc_qdisc_churn_qdisc_del_ok);
		stat_row("tc_qdisc_churn", "link_del_ok",       shm->stats.tc_qdisc_churn_link_del_ok);
		stat_row("tc_qdisc_churn", "peek_stack_runs",         shm->stats.tc_qdisc_peek_stack_runs);
		stat_row("tc_qdisc_churn", "peek_stack_install_ok",   shm->stats.tc_qdisc_peek_stack_install_ok);
		stat_row("tc_qdisc_churn", "peek_stack_install_fail", shm->stats.tc_qdisc_peek_stack_install_fail);
		stat_row("tc_qdisc_churn", "peek_stack_burst_ok",     shm->stats.tc_qdisc_peek_stack_burst_ok);
		stat_row("tc_qdisc_churn", "bridge_parent_runs",      shm->stats.tc_qdisc_churn_bridge_parent_runs);
		stat_row("tc_qdisc_churn", "bridge_dellink_race_ok",  shm->stats.tc_qdisc_churn_bridge_dellink_race_ok);
	}

	if (shm->stats.tc_mirred_blockcast_runs) {
		stat_row("tc_mirred_blockcast", "runs",            shm->stats.tc_mirred_blockcast_runs);
		stat_row("tc_mirred_blockcast", "setup_failed",    shm->stats.tc_mirred_blockcast_setup_failed);
		stat_row("tc_mirred_blockcast", "qdisc_ok",        shm->stats.tc_mirred_blockcast_qdisc_ok);
		stat_row("tc_mirred_blockcast", "qdisc_fail",      shm->stats.tc_mirred_blockcast_qdisc_fail);
		stat_row("tc_mirred_blockcast", "filter_ok",       shm->stats.tc_mirred_blockcast_filter_ok);
		stat_row("tc_mirred_blockcast", "filter_fail",     shm->stats.tc_mirred_blockcast_filter_fail);
		stat_row("tc_mirred_blockcast", "packet_sent_ok",  shm->stats.tc_mirred_blockcast_packet_sent_ok);
	}

	if (shm->stats.xfrm_churn_runs) {
		stat_row("xfrm_churn", "runs",          shm->stats.xfrm_churn_runs);
		stat_row("xfrm_churn", "setup_failed",  shm->stats.xfrm_churn_setup_failed);
		stat_row("xfrm_churn", "sa_added",      shm->stats.xfrm_churn_sa_added);
		stat_row("xfrm_churn", "sa_updated",    shm->stats.xfrm_churn_sa_updated);
		stat_row("xfrm_churn", "sa_deleted",    shm->stats.xfrm_churn_sa_deleted);
		stat_row("xfrm_churn", "pol_added",     shm->stats.xfrm_churn_pol_added);
		stat_row("xfrm_churn", "pol_deleted",   shm->stats.xfrm_churn_pol_deleted);
		stat_row("xfrm_churn", "esp_sent",      shm->stats.xfrm_churn_esp_sent);
		stat_row("xfrm_churn", "pfkey_send_ok", shm->stats.xfrm_churn_pfkey_send_ok);
		stat_row("xfrm_churn", "ah_esn_setup_ok",    shm->stats.xfrm_ah_esn_setup_ok);
		stat_row("xfrm_churn", "ah_esn_setup_fail",  shm->stats.xfrm_ah_esn_setup_fail);
		stat_row("xfrm_churn", "ah_esn_async_runs",  shm->stats.xfrm_ah_esn_async_runs);
		stat_row("xfrm_churn", "ah_esn_delsa_races", shm->stats.xfrm_ah_esn_delsa_races);
		stat_row("xfrm_churn", "compat_sweep_runs",  shm->stats.xfrm_compat_sweep_runs);
		stat_row("xfrm_churn", "compat_sends_ok",    shm->stats.xfrm_compat_sends_ok);
		stat_row("xfrm_churn", "compat_sends_failed", shm->stats.xfrm_compat_sends_failed);
		stat_row("xfrm_churn", "compat_replies_seen", shm->stats.xfrm_compat_replies_seen);
	}

	stat_category_emit_text(&ublk_lifecycle_category);

	stat_category_emit_text(&pci_bind_category);

	if (shm->stats.accept_unblocker_connects_fired ||
	    shm->stats.accept_unblocker_loopback_only_skipped ||
	    shm->stats.accept_unblocker_probe_failed) {
		stat_row("accept_unblocker", "connects_fired",
			 shm->stats.accept_unblocker_connects_fired);
		stat_row("accept_unblocker", "loopback_only_skipped",
			 shm->stats.accept_unblocker_loopback_only_skipped);
		stat_row("accept_unblocker", "probe_failed",
			 shm->stats.accept_unblocker_probe_failed);
	}

	if (shm->stats.pipe_waker_bytes_written ||
	    shm->stats.pipe_waker_no_target ||
	    shm->stats.pipe_waker_write_failed) {
		stat_row("pipe_waker", "bytes_written",
			 shm->stats.pipe_waker_bytes_written);
		stat_row("pipe_waker", "no_target",
			 shm->stats.pipe_waker_no_target);
		stat_row("pipe_waker", "write_failed",
			 shm->stats.pipe_waker_write_failed);
	}

	if (shm->stats.nat_t_churn_runs) {
		stat_row("nat_t_churn", "runs",              shm->stats.nat_t_churn_runs);
		stat_row("nat_t_churn", "setup_failed",      shm->stats.nat_t_churn_setup_failed);
		stat_row("nat_t_churn", "sa_added",          shm->stats.nat_t_churn_sa_added);
		stat_row("nat_t_churn", "sa_deleted",        shm->stats.nat_t_churn_sa_deleted);
		stat_row("nat_t_churn", "frames_sent",       shm->stats.nat_t_churn_frames_sent);
		stat_row("nat_t_churn", "xfrm6_setup_ok",    shm->stats.nat_t_xfrm6_setup_ok);
		stat_row("nat_t_churn", "xfrm6_setup_fail",  shm->stats.nat_t_xfrm6_setup_fail);
		stat_row("nat_t_churn", "xfrm6_sendto_runs", shm->stats.nat_t_xfrm6_sendto_runs);
		stat_row("nat_t_churn", "xfrm6_delsa_races", shm->stats.nat_t_xfrm6_delsa_races);
	}

	stat_category_emit_text(&bpf_cgroup_attach_category);

	if (shm->stats.mptcp_pm_churn_runs) {
		stat_row("mptcp_pm_churn", "runs",            shm->stats.mptcp_pm_churn_runs);
		stat_row("mptcp_pm_churn", "setup_failed",    shm->stats.mptcp_pm_churn_setup_failed);
		stat_row("mptcp_pm_churn", "sock_mptcp_ok",   shm->stats.mptcp_pm_churn_sock_mptcp_ok);
		stat_row("mptcp_pm_churn", "addr_added_ok",   shm->stats.mptcp_pm_churn_addr_added_ok);
		stat_row("mptcp_pm_churn", "addr_removed_ok", shm->stats.mptcp_pm_churn_addr_removed_ok);
		stat_row("mptcp_pm_churn", "send_ok",         shm->stats.mptcp_pm_churn_send_ok);
		stat_row("mptcp_pm_churn", "setsockopt_unsupported",   shm->stats.mptcp_setsockopt_unsupported);
		stat_row("mptcp_pm_churn", "setsockopt_master_set",    shm->stats.mptcp_setsockopt_master_set);
		stat_row("mptcp_pm_churn", "setsockopt_master_fail",   shm->stats.mptcp_setsockopt_master_fail);
		stat_row("mptcp_pm_churn", "getsockopt_verify_ok",     shm->stats.mptcp_getsockopt_verify_ok);
		stat_row("mptcp_pm_churn", "getsockopt_verify_drift",  shm->stats.mptcp_getsockopt_verify_drift);
		stat_row("mptcp_pm_churn", "sockopt_sweep_runs",       shm->stats.mptcp_sockopt_sweep_runs);
		stat_row("mptcp_pm_churn", "sockopt_set_ok",           shm->stats.mptcp_sockopt_set_ok);
		stat_row("mptcp_pm_churn", "sockopt_set_failed",       shm->stats.mptcp_sockopt_set_failed);
		stat_row("mptcp_pm_churn", "sockopt_subflow_added",    shm->stats.mptcp_sockopt_subflow_added);
		stat_row("mptcp_pm_churn", "sockopt_readback_ok",      shm->stats.mptcp_sockopt_readback_ok);
		stat_row("mptcp_pm_churn", "sockopt_inherit_mismatch", shm->stats.mptcp_sockopt_inherit_mismatch);
		stat_row("mptcp_pm_churn", "sockopt_unsupported_latched", shm->stats.mptcp_sockopt_unsupported_latched);
	}

	if (shm->stats.devlink_port_churn_iterations ||
	    shm->stats.devlink_port_churn_create_skipped) {
		stat_row("devlink_port_churn", "iterations",     shm->stats.devlink_port_churn_iterations);
		stat_row("devlink_port_churn", "split_ok",       shm->stats.devlink_port_churn_split_ok);
		stat_row("devlink_port_churn", "split_fail",     shm->stats.devlink_port_churn_split_fail);
		stat_row("devlink_port_churn", "reload_ok",      shm->stats.devlink_port_churn_reload_ok);
		stat_row("devlink_port_churn", "reload_fail",    shm->stats.devlink_port_churn_reload_fail);
		stat_row("devlink_port_churn", "create_skipped", shm->stats.devlink_port_churn_create_skipped);
	}

	stat_category_emit_text(&handshake_req_abort_category);

	stat_category_emit_text(&nf_conntrack_helper_churn_category);

	stat_category_emit_text(&af_unix_scm_rights_gc_category);

	stat_category_emit_text(&af_unix_peek_race_category);

	stat_category_emit_text(&sysv_shm_orphan_race_category);

	stat_category_emit_text(&qrtr_bind_race_category);

	stat_category_emit_text(&pfkey_spd_walk_category);

	stat_category_emit_text(&l2tp_ifname_race_category);

	stat_category_emit_text(&netns_teardown_category);

	stat_category_emit_text(&tcp_ulp_swap_churn_category);

	stat_category_emit_text(&msg_zerocopy_churn_category);

	stat_category_emit_text(&setsockopt_pairing_category);

	stat_category_emit_text(&iouring_send_zc_churn_category);

	if (shm->stats.vsock_transport_churn_runs) {
		stat_row("vsock_transport_churn", "runs",           shm->stats.vsock_transport_churn_runs);
		stat_row("vsock_transport_churn", "setup_failed",   shm->stats.vsock_transport_churn_setup_failed);
		stat_row("vsock_transport_churn", "bind_ok",        shm->stats.vsock_transport_churn_bind_ok);
		stat_row("vsock_transport_churn", "connect_ok",     shm->stats.vsock_transport_churn_connect_ok);
		stat_row("vsock_transport_churn", "send_ok",        shm->stats.vsock_transport_churn_send_ok);
		stat_row("vsock_transport_churn", "buffer_size_ok", shm->stats.vsock_transport_churn_buffer_size_ok);
		stat_row("vsock_transport_churn", "timeout_ok",     shm->stats.vsock_transport_churn_timeout_ok);
		stat_row("vsock_transport_churn", "get_cid_ok",     shm->stats.vsock_transport_churn_get_cid_ok);
		stat_row("vsock_transport_churn", "seq_eom_runs",         shm->stats.vsock_seq_eom_runs);
		stat_row("vsock_transport_churn", "seq_eom_sends_ok",     shm->stats.vsock_seq_eom_sends_ok);
		stat_row("vsock_transport_churn", "seq_eom_sends_failed", shm->stats.vsock_seq_eom_sends_failed);
		stat_row("vsock_transport_churn", "seq_eom_skipped",      shm->stats.vsock_seq_eom_skipped);
	}

	stat_category_emit_text(&bridge_vlan_churn_category);

	stat_category_emit_text(&igmp_mld_source_churn_category);

	if (shm->stats.psp_key_rotate_runs) {
		stat_row("psp_key_rotate", "runs",              shm->stats.psp_key_rotate_runs);
		stat_row("psp_key_rotate", "setup_failed",      shm->stats.psp_key_rotate_setup_failed);
		stat_row("psp_key_rotate", "netdev_create_ok",  shm->stats.psp_key_rotate_netdev_create_ok);
		stat_row("psp_key_rotate", "family_resolve_ok", shm->stats.psp_key_rotate_family_resolve_ok);
		stat_row("psp_key_rotate", "dev_get_ok",        shm->stats.psp_key_rotate_dev_get_ok);
		stat_row("psp_key_rotate", "key_install_ok",    shm->stats.psp_key_rotate_key_install_ok);
		stat_row("psp_key_rotate", "spi_set_ok",        shm->stats.psp_key_rotate_spi_set_ok);
		stat_row("psp_key_rotate", "send_ok",           shm->stats.psp_key_rotate_send_ok);
		stat_row("psp_key_rotate", "rotate_ok",         shm->stats.psp_key_rotate_rotate_ok);
		stat_row("psp_key_rotate", "spi_switch_ok",     shm->stats.psp_key_rotate_spi_switch_ok);
		stat_row("psp_key_rotate", "shutdown_ok",       shm->stats.psp_key_rotate_shutdown_ok);
	}

	if (shm->stats.psp_devlink_port_churn_runs) {
		stat_row("psp_devlink_port_churn", "runs",                 shm->stats.psp_devlink_port_churn_runs);
		stat_row("psp_devlink_port_churn", "port_add_ok",          shm->stats.psp_devlink_port_churn_port_add_ok);
		stat_row("psp_devlink_port_churn", "port_del_ok",          shm->stats.psp_devlink_port_churn_port_del_ok);
		stat_row("psp_devlink_port_churn", "vf_spawn_ok",          shm->stats.psp_devlink_port_churn_vf_spawn_ok);
		stat_row("psp_devlink_port_churn", "unsupported_latched",  shm->stats.psp_devlink_port_churn_unsupported_latched);
	}

	stat_category_emit_text(&veth_asymmetric_xdp_category);

	stat_category_emit_text(&ip6erspan_netns_migrate_category);

	stat_category_emit_text(&ip6gre_bond_lapb_stack_category);

	stat_category_emit_text(&wireguard_decrypt_flood_category);

	stat_category_emit_text(&blkdev_lifecycle_race_category);

	stat_category_emit_text(&iscsi_target_probe_category);

	stat_category_emit_text(&iscsi_login_walker_category);

	if (shm->stats.ipvs_sysctl_writer_runs) {
		stat_row("ipvs_sysctl_writer", "runs",                shm->stats.ipvs_sysctl_writer_runs);
		stat_row("ipvs_sysctl_writer", "writes_ok",           shm->stats.ipvs_sysctl_writer_writes_ok);
		stat_row("ipvs_sysctl_writer", "writes_failed",       shm->stats.ipvs_sysctl_writer_writes_failed);
		stat_row("ipvs_sysctl_writer", "unsupported_latched", shm->stats.ipvs_sysctl_writer_unsupported_latched);
	}

	stat_category_emit_text(&ipv6_ndisc_proxy_category);

	if (shm->stats.ipfrag_source_runs) {
		stat_row("ipfrag_source_churn", "runs",            shm->stats.ipfrag_source_runs);
		stat_row("ipfrag_source_churn", "packets_sent_ok", shm->stats.ipfrag_packets_sent_ok);
		stat_row("ipfrag_source_churn", "send_failed",     shm->stats.ipfrag_send_failed);
		stat_row("ipfrag_source_churn", "unique_srcs",     shm->stats.ipfrag_unique_srcs);
	}

	stat_category_emit_text(&rtnl_vf_broadcast_getlink_category);

	if (shm->stats.obscure_af_churn_runs) {
		static const char * const ap_names[] = {
			"sendmsg_no_bind",
			"bind_then_sendmsg",
			"connect_no_listen",
			"ioctl_rotation",
			"setsockopt_zero_len",
			"close_via_dup",
		};
		char key[64];
		unsigned int ap;

		stat_row("obscure_af_churn", "runs",         shm->stats.obscure_af_churn_runs);
		stat_row("obscure_af_churn", "no_viable_pf", shm->stats.obscure_af_churn_no_viable_pf);

		for (ap = 0; ap < ARRAY_SIZE(ap_names); ap++) {
			snprintf(key, sizeof(key), "%s_runs", ap_names[ap]);
			stat_row("obscure_af_churn", key,
				 shm->stats.obscure_af_churn_pattern_runs[ap]);
			snprintf(key, sizeof(key), "%s_kernel_rejected", ap_names[ap]);
			stat_row("obscure_af_churn", key,
				 shm->stats.obscure_af_churn_pattern_kernel_rejected[ap]);
			snprintf(key, sizeof(key), "%s_unexpected_success", ap_names[ap]);
			stat_row("obscure_af_churn", key,
				 shm->stats.obscure_af_churn_pattern_unexpected_success[ap]);
		}
	}

	stat_category_emit_text(&flowtable_encap_vlan_category);

	if (shm->stats.rxrpc_sendmsg_cmsg_runs) {
		static const char * const rxrpc_cmsg_slot_names[8] = {
			"user_call_id",
			"abort",
			"accept",
			"exclusive_call",
			"upgrade_service",
			"tx_length",
			"set_call_timeout",
			"charge_accept",
		};
		char key[64];
		unsigned int slot;

		stat_row("rxrpc_sendmsg_cmsg_churn", "runs",          shm->stats.rxrpc_sendmsg_cmsg_runs);
		stat_row("rxrpc_sendmsg_cmsg_churn", "socket_failed", shm->stats.rxrpc_sendmsg_cmsg_socket_failed);
		stat_row("rxrpc_sendmsg_cmsg_churn", "sendmsg_ok",    shm->stats.rxrpc_sendmsg_cmsg_sendmsg_ok);
		stat_row("rxrpc_sendmsg_cmsg_churn", "sendmsg_fail",  shm->stats.rxrpc_sendmsg_cmsg_sendmsg_fail);
		for (slot = 0; slot < 8U; slot++) {
			snprintf(key, sizeof(key), "cmsg_sent_%s",
				 rxrpc_cmsg_slot_names[slot]);
			stat_row("rxrpc_sendmsg_cmsg_churn", key,
				 shm->stats.rxrpc_sendmsg_cmsg_sent[slot]);
		}
	}

	if (shm->stats.tty_ldisc_churn_runs) {
		char key[64];
		unsigned int slot;

		stat_row("tty_ldisc_churn", "runs",             shm->stats.tty_ldisc_churn_runs);
		stat_row("tty_ldisc_churn", "setup_failed",     shm->stats.tty_ldisc_churn_setup_failed);
		stat_row("tty_ldisc_churn", "ldisc_set_ok",     shm->stats.tty_ldisc_churn_ldisc_set_ok);
		stat_row("tty_ldisc_churn", "ldisc_set_failed", shm->stats.tty_ldisc_churn_ldisc_set_failed);
		stat_row("tty_ldisc_churn", "write_ok",         shm->stats.tty_ldisc_churn_write_ok);
		stat_row("tty_ldisc_churn", "read_ok",          shm->stats.tty_ldisc_churn_read_ok);
		for (slot = 0; slot < 25U; slot++) {
			if (shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[slot] == 0)
				continue;
			snprintf(key, sizeof(key), "ldisc_set_ok_n%u", slot);
			stat_row("tty_ldisc_churn", key,
				 shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[slot]);
		}
	}

	if (shm->stats.afxdp_churn_runs) {
		stat_row("afxdp_churn", "runs",            shm->stats.afxdp_churn_runs);
		stat_row("afxdp_churn", "setup_failed",    shm->stats.afxdp_churn_setup_failed);
		stat_row("afxdp_churn", "umem_reg_ok",     shm->stats.afxdp_churn_umem_reg_ok);
		stat_row("afxdp_churn", "rings_setup_ok",  shm->stats.afxdp_churn_rings_setup_ok);
		stat_row("afxdp_churn", "prog_load_ok",    shm->stats.afxdp_churn_prog_load_ok);
		stat_row("afxdp_churn", "map_create_ok",   shm->stats.afxdp_churn_map_create_ok);
		stat_row("afxdp_churn", "map_update_ok",   shm->stats.afxdp_churn_map_update_ok);
		stat_row("afxdp_churn", "bind_ok",         shm->stats.afxdp_churn_bind_ok);
		stat_row("afxdp_churn", "link_attach_ok",  shm->stats.afxdp_churn_link_attach_ok);
		stat_row("afxdp_churn", "netlink_attach_ok", shm->stats.afxdp_churn_netlink_attach_ok);
		stat_row("afxdp_churn", "attach_failed",   shm->stats.afxdp_churn_attach_failed);
		stat_row("afxdp_churn", "send_ok",         shm->stats.afxdp_churn_send_ok);
		stat_row("afxdp_churn", "recv_ok",         shm->stats.afxdp_churn_recv_ok);
		stat_row("afxdp_churn", "map_delete_ok",   shm->stats.afxdp_churn_map_delete_ok);
		stat_row("afxdp_churn", "munmap_race_ok",  shm->stats.afxdp_churn_munmap_race_ok);
		stat_row("afxdp_churn", "xsg_iters",         shm->stats.afxdp_xsg_iters);
		stat_row("afxdp_churn", "tx_metadata_iters", shm->stats.afxdp_tx_metadata_iters);
		stat_row("afxdp_churn", "tun_bind_iters",    shm->stats.afxdp_tun_bind_iters);
		stat_row("afxdp_churn", "xsg_bind_failed",   shm->stats.afxdp_xsg_bind_failed);
		stat_row("afxdp_churn", "tx_md_bind_failed", shm->stats.afxdp_tx_md_bind_failed);
	}

	if (shm->stats.kvm_run_invocations) {
		stat_row("kvm_run_churn", "invocations",        shm->stats.kvm_run_invocations);
		stat_row("kvm_run_churn", "exit_io",            shm->stats.kvm_run_exit_io);
		stat_row("kvm_run_churn", "exit_mmio",          shm->stats.kvm_run_exit_mmio);
		stat_row("kvm_run_churn", "exit_hlt",           shm->stats.kvm_run_exit_hlt);
		stat_row("kvm_run_churn", "exit_shutdown",      shm->stats.kvm_run_exit_shutdown);
		stat_row("kvm_run_churn", "exit_fail_entry",    shm->stats.kvm_run_exit_fail_entry);
		stat_row("kvm_run_churn", "exit_internal_error", shm->stats.kvm_run_exit_internal_error);
		stat_row("kvm_run_churn", "exit_intr",          shm->stats.kvm_run_exit_intr);
		stat_row("kvm_run_churn", "exit_other",         shm->stats.kvm_run_exit_other);
		stat_row("kvm_run_churn", "errors",             shm->stats.kvm_run_errors);
		stat_row("kvm_run_churn", "gpc_memslot_race_runs",         shm->stats.kvm_gpc_memslot_race_runs);
		stat_row("kvm_run_churn", "gpc_memslot_race_deletes",      shm->stats.kvm_gpc_memslot_race_deletes);
		stat_row("kvm_run_churn", "gpc_memslot_race_unsupported",  shm->stats.kvm_gpc_memslot_race_unsupported);
	}

	if (shm->stats.nl80211_runs) {
		stat_row("nl80211_churn", "runs",                  shm->stats.nl80211_runs);
		stat_row("nl80211_churn", "setup_failed",          shm->stats.nl80211_setup_failed);
		stat_row("nl80211_churn", "scan_triggered",        shm->stats.nl80211_scan_triggered);
		stat_row("nl80211_churn", "connect_attempted",     shm->stats.nl80211_connect_attempted);
		stat_row("nl80211_churn", "connect_succeeded",     shm->stats.nl80211_connect_succeeded);
		stat_row("nl80211_churn", "disconnect_attempted",  shm->stats.nl80211_disconnect_attempted);
		stat_row("nl80211_churn", "regdom_changed",        shm->stats.nl80211_regdom_changed);
		stat_row("nl80211_churn", "iface_created",         shm->stats.nl80211_iface_created);
		stat_row("nl80211_churn", "iface_destroyed",       shm->stats.nl80211_iface_destroyed);
		stat_row("nl80211_churn", "bursts_sent",           shm->stats.nl80211_bursts_sent);
		stat_row("nl80211_churn", "pmsr_runs",             shm->stats.nl80211_pmsr_runs);
		stat_row("nl80211_churn", "pmsr_ok",               shm->stats.nl80211_pmsr_ok);
		stat_row("nl80211_churn", "admin_gate_runs",       shm->stats.nl80211_admin_gate_runs);
		stat_row("nl80211_churn", "admin_gate_eperm_ok",   shm->stats.nl80211_admin_gate_eperm_ok);
		stat_row("nl80211_churn", "admin_gate_unexpected", shm->stats.nl80211_admin_gate_unexpected);
	}

	stat_category_emit_text(&splice_protocols_category);

	stat_category_emit_text(&rxrpc_key_install_category);

	stat_category_emit_text(&af_alg_weak_cipher_probe_category);

	if (shm->stats.af_alg_probe_runs || shm->stats.af_alg_probe_unsupported) {
		unsigned int tmpl;

		stat_row("af_alg_probe", "runs",         shm->stats.af_alg_probe_runs);
		stat_row("af_alg_probe", "unsupported",  shm->stats.af_alg_probe_unsupported);
		stat_row("af_alg_probe", "accept_total", shm->stats.af_alg_probe_accept_total);
		stat_row("af_alg_probe", "reject_total", shm->stats.af_alg_probe_reject_total);
		for (tmpl = 0; tmpl < NR_AF_ALG_PROBE_TEMPLATES; tmpl++) {
			char metric[64];
			const char *label = af_alg_probe_template_label(tmpl);

			snprintf(metric, sizeof(metric), "%s.accept", label);
			stat_row("af_alg_probe", metric, shm->stats.af_alg_probe_accept[tmpl]);
			snprintf(metric, sizeof(metric), "%s.reject", label);
			stat_row("af_alg_probe", metric, shm->stats.af_alg_probe_reject[tmpl]);
		}
	}

	if (shm->stats.af_alg_recvmsg_runs) {
		stat_row("af_alg_recvmsg_churn", "runs",               shm->stats.af_alg_recvmsg_runs);
		stat_row("af_alg_recvmsg_churn", "setkey_sent",        shm->stats.af_alg_recvmsg_setkey_sent);
		stat_row("af_alg_recvmsg_churn", "iv_sent",            shm->stats.af_alg_recvmsg_iv_sent);
		stat_row("af_alg_recvmsg_churn", "oob_iov",            shm->stats.af_alg_recvmsg_oob_iov);
		stat_row("af_alg_recvmsg_churn", "zerolen",            shm->stats.af_alg_recvmsg_zerolen);
		stat_row("af_alg_recvmsg_churn", "oversize",           shm->stats.af_alg_recvmsg_oversize);
		stat_row("af_alg_recvmsg_churn", "empty_cmsg_no_more", shm->stats.af_alg_recvmsg_empty_cmsg_no_more);
		stat_row("af_alg_recvmsg_churn", "unsupported",        shm->stats.af_alg_recvmsg_unsupported);
	}
}

/* Helpers shared by the "Top remote-edge producers" view in
 * dump_stats_kcov_block().  The view emits one row per top syscall
 * AND one row per top childop with the same column shape, so both
 * the flag-lookup and the yield-format live here to keep the two
 * render loops free of duplicated logic. */
static void remote_edge_row_flags(char *buf, size_t bufsz,
				  unsigned long row_remote_ecount,
				  unsigned long max_remote_ecount)
{
	/* HEAVY: row carries >= 50% of the leader's remote eCount.
	 * One max is computed across BOTH the syscall and childop
	 * scans before render, so the H mark means the same thing
	 * in either sub-table. */
	bool heavy = (max_remote_ecount > 0) &&
		     (row_remote_ecount * 2 >= max_remote_ecount);

	snprintf(buf, bufsz, "%s", heavy ? "H" : "-");
}

static void remote_edge_format_yield(char *buf, size_t bufsz,
				     unsigned long edge_calls,
				     unsigned long calls)
{
	unsigned long milli;

	if (calls == 0) {
		snprintf(buf, bufsz, "%s", "  --");
		return;
	}
	milli = (edge_calls * 1000UL) / calls;
	if (milli > 1000)
		milli = 1000;
	snprintf(buf, bufsz, "%lu.%03lu", milli / 1000, milli % 1000);
}

static void __cold dump_stats_kcov_block(void)
{
	unsigned int i;

	if (kcov_shm != NULL) {
		unsigned int top_nr[10];
		unsigned long top_edges[10];
		unsigned int top_count = 0;
		unsigned int cold_count = 0;
		unsigned int j;

		unsigned long kc_edges       = __atomic_load_n(&kcov_shm->edges_found,            __ATOMIC_RELAXED);
		/* See per-child kcov stats migration in stats_ring.h:
		 * total_pcs / total_calls / remote_calls read from
		 * parent_stats.  kcov_shm->total_calls is kept as the
		 * stamp source for last_edge_at[] / last_efault_at[];
		 * the other two shm fields are no longer bumped. */
		unsigned long kc_pcs         = parent_stats.total_pcs;
		unsigned long kc_calls       = parent_stats.total_calls;
		unsigned long kc_remote      = parent_stats.remote_calls;
		unsigned long kc_cmp_records = __atomic_load_n(&kcov_shm->cmp_records_collected,  __ATOMIC_RELAXED);
		unsigned long kc_cmp_trunc   = __atomic_load_n(&kcov_shm->cmp_trace_truncated,    __ATOMIC_RELAXED);
		unsigned long kc_dedup_overflow    = __atomic_load_n(&kcov_shm->dedup_probe_overflow,   __ATOMIC_RELAXED);
		unsigned long kc_dedup_max_probe   = __atomic_load_n(&kcov_shm->dedup_max_probe_seen,   __ATOMIC_RELAXED);
		unsigned long kc_cmp_bloom_skipped = __atomic_load_n(&kcov_shm->cmp_hints_bloom_skipped, __ATOMIC_RELAXED);
		unsigned long kc_cmp_strip_skipped = __atomic_load_n(&kcov_shm->cmp_hints_strip_skipped, __ATOMIC_RELAXED);
		unsigned long kc_cmp_unique  = __atomic_load_n(&kcov_shm->cmp_hints_unique_inserts, __ATOMIC_RELAXED);
		unsigned long kc_cmp_save_reject_nonconst      = __atomic_load_n(&kcov_shm->cmp_hints_save_reject_nonconst,      __ATOMIC_RELAXED);
		unsigned long kc_cmp_save_reject_uninteresting = __atomic_load_n(&kcov_shm->cmp_hints_save_reject_uninteresting, __ATOMIC_RELAXED);
		unsigned long kc_cmp_save_reject_sentinel      = __atomic_load_n(&kcov_shm->cmp_hints_save_reject_sentinel,      __ATOMIC_RELAXED);
		unsigned long kc_cmp_save_reject_dup           = __atomic_load_n(&kcov_shm->cmp_hints_save_reject_dup,           __ATOMIC_RELAXED);
		unsigned long kc_cmp_save_reject_cap           = __atomic_load_n(&kcov_shm->cmp_hints_save_reject_cap,           __ATOMIC_RELAXED);

		stat_row("kcov_coverage", "unique_edges",          kc_edges);
		stat_row("kcov_coverage", "total_pcs",             kc_pcs);
		stat_row("kcov_coverage", "total_calls",           kc_calls);
		stat_row("kcov_coverage", "remote_calls",          kc_remote);
		stat_row("kcov_coverage", "cmp_records_collected", kc_cmp_records);

		/* Shadow transition-coverage globals.  See the
		 * kcov_transition_coverage_mode enum + KCOV_NUM_TRANSITIONS
		 * comments in include/kcov.h for the design; this block
		 * surfaces the two run-wide counters so PC vs transition
		 * yield can be compared side-by-side without parsing a
		 * separate log channel.  Both stay at zero when the mode is
		 * OFF, so the early-out below keeps the stats stream quiet
		 * for runs that opted out. */
		{
			unsigned long kc_tedges = __atomic_load_n(
				&kcov_shm->transition_edges_found,
				__ATOMIC_RELAXED);
			unsigned long kc_tdistinct = __atomic_load_n(
				&kcov_shm->transition_distinct_edges,
				__ATOMIC_RELAXED);

			if (kc_tedges > 0)
				stat_row("kcov_coverage",
					 "transition_edges_found",
					 kc_tedges);
			if (kc_tdistinct > 0)
				stat_row("kcov_coverage",
					 "transition_distinct_edges",
					 kc_tdistinct);
		}
		if (kc_cmp_trunc > 0)
			stat_row("kcov_coverage", "cmp_trace_truncated", kc_cmp_trunc);
		if (kc_dedup_overflow > 0)
			stat_row("kcov_coverage", "dedup_probe_overflow", kc_dedup_overflow);
		if (kc_dedup_max_probe > 0)
			stat_row("kcov_coverage", "dedup_max_probe_seen", kc_dedup_max_probe);
		if (kc_cmp_bloom_skipped > 0)
			stat_row("kcov_coverage", "cmp_hints_bloom_skipped", kc_cmp_bloom_skipped);
		if (kc_cmp_strip_skipped > 0)
			stat_row("kcov_coverage", "cmp_hints_strip_skipped", kc_cmp_strip_skipped);
		if (kc_cmp_unique > 0)
			stat_row("kcov_coverage", "cmp_hints_unique_inserts", kc_cmp_unique);
		if (kc_cmp_save_reject_nonconst > 0)
			stat_row("kcov_coverage", "cmp_hints_save_reject_nonconst", kc_cmp_save_reject_nonconst);
		if (kc_cmp_save_reject_uninteresting > 0)
			stat_row("kcov_coverage", "cmp_hints_save_reject_uninteresting", kc_cmp_save_reject_uninteresting);
		if (kc_cmp_save_reject_sentinel > 0)
			stat_row("kcov_coverage", "cmp_hints_save_reject_sentinel", kc_cmp_save_reject_sentinel);
		if (kc_cmp_save_reject_dup > 0)
			stat_row("kcov_coverage", "cmp_hints_save_reject_dup", kc_cmp_save_reject_dup);
		if (kc_cmp_save_reject_cap > 0)
			stat_row("kcov_coverage", "cmp_hints_save_reject_cap", kc_cmp_save_reject_cap);

		/* CMP-hint freshness / tier observability rollup.  See the
		 * counter-block comment in include/kcov.h next to
		 * cmp_hint_tier_recent_wins for the per-counter semantics.
		 * Gates on a non-zero summed value so a run that never
		 * exercised the consumer path stays silent in stats.  Per-
		 * bucket detail rendered as a compact tier_age_<n> row
		 * family so a downstream stats consumer can index by
		 * bucket without parsing a sub-structured value. */
		{
			unsigned long kc_tier_r_wins = __atomic_load_n(
				&kcov_shm->cmp_hint_tier_recent_wins,
				__ATOMIC_RELAXED);
			unsigned long kc_tier_r_misses = __atomic_load_n(
				&kcov_shm->cmp_hint_tier_recent_misses,
				__ATOMIC_RELAXED);
			unsigned long kc_tier_d_wins = __atomic_load_n(
				&kcov_shm->cmp_hint_tier_durable_wins,
				__ATOMIC_RELAXED);
			unsigned long kc_tier_d_misses = __atomic_load_n(
				&kcov_shm->cmp_hint_tier_durable_misses,
				__ATOMIC_RELAXED);
			unsigned long sum = kc_tier_r_wins + kc_tier_r_misses
					  + kc_tier_d_wins + kc_tier_d_misses;
			unsigned int b;

			if (sum > 0) {
				stat_row("kcov_coverage",
					 "cmp_hint_tier_recent_wins",
					 kc_tier_r_wins);
				stat_row("kcov_coverage",
					 "cmp_hint_tier_recent_misses",
					 kc_tier_r_misses);
				stat_row("kcov_coverage",
					 "cmp_hint_tier_durable_wins",
					 kc_tier_d_wins);
				stat_row("kcov_coverage",
					 "cmp_hint_tier_durable_misses",
					 kc_tier_d_misses);

				for (b = 0; b < CMP_HINT_AGE_BUCKETS; b++) {
					char key[64];
					unsigned long v_consumed =
						__atomic_load_n(&kcov_shm->cmp_hint_durable_consumed_age[b],
								__ATOMIC_RELAXED);
					unsigned long v_wins =
						__atomic_load_n(&kcov_shm->cmp_hint_durable_age_wins[b],
								__ATOMIC_RELAXED);
					unsigned long v_misses =
						__atomic_load_n(&kcov_shm->cmp_hint_durable_age_misses[b],
								__ATOMIC_RELAXED);

					if ((v_consumed | v_wins | v_misses) == 0)
						continue;
					snprintf(key, sizeof(key),
						 "cmp_hint_durable_consumed_age_%u", b);
					stat_row("kcov_coverage", key, v_consumed);
					snprintf(key, sizeof(key),
						 "cmp_hint_durable_age_wins_%u", b);
					stat_row("kcov_coverage", key, v_wins);
					snprintf(key, sizeof(key),
						 "cmp_hint_durable_age_misses_%u", b);
					stat_row("kcov_coverage", key, v_misses);
				}
			}
		}

		{
			/* total_warm_known_hits migrated off the kcov_shm
			 * atomic onto the per-child staged counter drained
			 * into parent_stats; the shm field is write-dead but
			 * kept for shared-mapping ABI stability.  See
			 * stats_ring.h. */
			unsigned long warm_known = parent_stats.total_warm_known_hits;
			if (warm_known > 0)
				stat_row("kcov_coverage", "warm_known_hits", warm_known);
		}

		{
			unsigned long rx_attempts = __atomic_load_n(&kcov_shm->reexec_attempts, __ATOMIC_RELAXED);
			unsigned long rx_attribution_found = __atomic_load_n(&kcov_shm->reexec_attribution_found, __ATOMIC_RELAXED);
			unsigned long rx_attribution_ambiguous = __atomic_load_n(&kcov_shm->reexec_attribution_ambiguous, __ATOMIC_RELAXED);
			unsigned long rx_attribution_width_match = __atomic_load_n(&kcov_shm->reexec_attribution_width_match, __ATOMIC_RELAXED);
			unsigned long rx_new_cmps_total = __atomic_load_n(&kcov_shm->reexec_new_cmps_total, __ATOMIC_RELAXED);
			unsigned long rx_skipped_destructive = __atomic_load_n(&kcov_shm->reexec_skipped_destructive, __ATOMIC_RELAXED);
			unsigned long rx_skipped_validate_silent = __atomic_load_n(&kcov_shm->reexec_skipped_validate_silent, __ATOMIC_RELAXED);
			unsigned long rx_window_cap_hit = __atomic_load_n(&kcov_shm->reexec_window_cap_hit, __ATOMIC_RELAXED);
			unsigned long rx_parent_calls_enabled = __atomic_load_n(&kcov_shm->cmp_parent_calls_enabled, __ATOMIC_RELAXED);
			unsigned long rx_parent_calls_control = __atomic_load_n(&kcov_shm->cmp_parent_calls_control, __ATOMIC_RELAXED);
			unsigned long rx_parent_new_cmps_enabled = __atomic_load_n(&kcov_shm->cmp_parent_new_cmps_enabled, __ATOMIC_RELAXED);
			unsigned long rx_parent_new_cmps_control = __atomic_load_n(&kcov_shm->cmp_parent_new_cmps_control, __ATOMIC_RELAXED);
			unsigned long rx_gate_skip_in_reexec = __atomic_load_n(&kcov_shm->reexec_gate_skip_in_reexec, __ATOMIC_RELAXED);
			unsigned long rx_gate_skip_disabled = __atomic_load_n(&kcov_shm->reexec_gate_skip_disabled, __ATOMIC_RELAXED);
			unsigned long rx_gate_skip_mode = __atomic_load_n(&kcov_shm->reexec_gate_skip_mode, __ATOMIC_RELAXED);
			unsigned long rx_gate_skip_chain_mid = __atomic_load_n(&kcov_shm->reexec_gate_skip_chain_mid, __ATOMIC_RELAXED);
			unsigned long rx_gate_skip_no_new_cmp = __atomic_load_n(&kcov_shm->reexec_gate_skip_no_new_cmp, __ATOMIC_RELAXED);
			unsigned long rx_gate_skip_no_pending = __atomic_load_n(&kcov_shm->reexec_gate_skip_no_pending, __ATOMIC_RELAXED);
			unsigned long rx_gate_skip_rate = __atomic_load_n(&kcov_shm->reexec_gate_skip_rate, __ATOMIC_RELAXED);
			unsigned long rx_gate_pass = __atomic_load_n(&kcov_shm->reexec_gate_pass, __ATOMIC_RELAXED);

			if (rx_attempts > 0)
				stat_row("kcov_coverage", "reexec_attempts", rx_attempts);
			if (rx_attribution_found > 0)
				stat_row("kcov_coverage", "reexec_attribution_found", rx_attribution_found);
			if (rx_attribution_ambiguous > 0)
				stat_row("kcov_coverage", "reexec_attribution_ambiguous", rx_attribution_ambiguous);
			if (rx_attribution_width_match > 0)
				stat_row("kcov_coverage", "reexec_attribution_width_match", rx_attribution_width_match);
			if (rx_new_cmps_total > 0)
				stat_row("kcov_coverage", "reexec_new_cmps_total", rx_new_cmps_total);
			if (rx_skipped_destructive > 0)
				stat_row("kcov_coverage", "reexec_skipped_destructive", rx_skipped_destructive);
			if (rx_skipped_validate_silent > 0)
				stat_row("kcov_coverage", "reexec_skipped_validate_silent", rx_skipped_validate_silent);
			if (rx_window_cap_hit > 0)
				stat_row("kcov_coverage", "reexec_window_cap_hit", rx_window_cap_hit);
			if (rx_parent_calls_enabled > 0)
				stat_row("kcov_coverage", "cmp_parent_calls_enabled", rx_parent_calls_enabled);
			if (rx_parent_calls_control > 0)
				stat_row("kcov_coverage", "cmp_parent_calls_control", rx_parent_calls_control);
			if (rx_parent_new_cmps_enabled > 0)
				stat_row("kcov_coverage", "cmp_parent_new_cmps_enabled", rx_parent_new_cmps_enabled);
			if (rx_parent_new_cmps_control > 0)
				stat_row("kcov_coverage", "cmp_parent_new_cmps_control", rx_parent_new_cmps_control);
			if (rx_gate_skip_in_reexec > 0)
				stat_row("kcov_coverage", "reexec_gate_skip_in_reexec", rx_gate_skip_in_reexec);
			if (rx_gate_skip_disabled > 0)
				stat_row("kcov_coverage", "reexec_gate_skip_disabled", rx_gate_skip_disabled);
			if (rx_gate_skip_mode > 0)
				stat_row("kcov_coverage", "reexec_gate_skip_mode", rx_gate_skip_mode);
			if (rx_gate_skip_chain_mid > 0)
				stat_row("kcov_coverage", "reexec_gate_skip_chain_mid", rx_gate_skip_chain_mid);
			if (rx_gate_skip_no_new_cmp > 0)
				stat_row("kcov_coverage", "reexec_gate_skip_no_new_cmp", rx_gate_skip_no_new_cmp);
			if (rx_gate_skip_no_pending > 0)
				stat_row("kcov_coverage", "reexec_gate_skip_no_pending", rx_gate_skip_no_pending);
			if (rx_gate_skip_rate > 0)
				stat_row("kcov_coverage", "reexec_gate_skip_rate", rx_gate_skip_rate);
			if (rx_gate_pass > 0)
				stat_row("kcov_coverage", "reexec_gate_pass", rx_gate_pass);
		}

		{
			unsigned long fx_scanned = __atomic_load_n(&kcov_shm->cmp_field_attribution_scanned, __ATOMIC_RELAXED);
			unsigned long fx_found = __atomic_load_n(&kcov_shm->cmp_field_attribution_found, __ATOMIC_RELAXED);
			unsigned long fx_pool_full = __atomic_load_n(&kcov_shm->cmp_field_attribution_pool_full, __ATOMIC_RELAXED);
			unsigned long fx_bad_ptr = __atomic_load_n(&kcov_shm->cmp_field_attribution_arg_skipped_bad_ptr, __ATOMIC_RELAXED);
			unsigned long fx_short_alloc = __atomic_load_n(&kcov_shm->cmp_field_attribution_arg_skipped_short_alloc, __ATOMIC_RELAXED);
			unsigned long fx_ts_bad_ptr = __atomic_load_n(&kcov_shm->cmp_field_timespec_skipped_bad_ptr, __ATOMIC_RELAXED);

			if (fx_scanned > 0)
				stat_row("kcov_coverage", "cmp_field_attribution_scanned", fx_scanned);
			if (fx_found > 0)
				stat_row("kcov_coverage", "cmp_field_attribution_found", fx_found);
			if (fx_pool_full > 0)
				stat_row("kcov_coverage", "cmp_field_attribution_pool_full", fx_pool_full);
			if (fx_bad_ptr > 0)
				stat_row("kcov_coverage", "cmp_field_attribution_arg_skipped_bad_ptr", fx_bad_ptr);
			if (fx_short_alloc > 0)
				stat_row("kcov_coverage", "cmp_field_attribution_arg_skipped_short_alloc", fx_short_alloc);
			if (fx_ts_bad_ptr > 0)
				stat_row("kcov_coverage", "cmp_field_timespec_skipped_bad_ptr", fx_ts_bad_ptr);
		}

		{
			unsigned long rc_inserts = __atomic_load_n(&kcov_shm->cmp_recent_inserts, __ATOMIC_RELAXED);
			unsigned long rc_evicts = __atomic_load_n(&kcov_shm->cmp_recent_evicts, __ATOMIC_RELAXED);
			unsigned long rc_would_pick = __atomic_load_n(&kcov_shm->cmp_recent_would_pick, __ATOMIC_RELAXED);
			unsigned long rc_would_miss = __atomic_load_n(&kcov_shm->cmp_recent_would_miss, __ATOMIC_RELAXED);
			unsigned long rc_live_picks = __atomic_load_n(&kcov_shm->cmp_recent_live_picks, __ATOMIC_RELAXED);

			if (rc_inserts > 0)
				stat_row("kcov_coverage", "cmp_recent_inserts", rc_inserts);
			if (rc_evicts > 0)
				stat_row("kcov_coverage", "cmp_recent_evicts", rc_evicts);
			if (rc_would_pick > 0)
				stat_row("kcov_coverage", "cmp_recent_would_pick", rc_would_pick);
			if (rc_would_miss > 0)
				stat_row("kcov_coverage", "cmp_recent_would_miss", rc_would_miss);
			if (rc_live_picks > 0)
				stat_row("kcov_coverage", "cmp_recent_live_picks", rc_live_picks);
		}

		/* Find top 10 edge-producing syscalls via insertion sort. */
		unsigned int nr_syscalls_to_scan = biarch ? max_nr_64bit_syscalls : max_nr_syscalls;
		if (nr_syscalls_to_scan > MAX_NR_SYSCALL)
			nr_syscalls_to_scan = MAX_NR_SYSCALL;
		const struct syscalltable *table = biarch ? syscalls_64bit : syscalls;

		memset(top_edges, 0, sizeof(top_edges));
		for (i = 0; i < nr_syscalls_to_scan; i++) {
			unsigned long edges = __atomic_load_n(&kcov_shm->per_syscall_edges[i], __ATOMIC_RELAXED);

			if (edges == 0)
				continue;

			if (kcov_syscall_is_cold(i))
				cold_count++;

			topn_push(top_edges, top_nr, &top_count, 10, edges, i);
		}

		if (top_count > 0) {
			output(0, "Top edge-producing syscalls:\n");
			for (j = 0; j < top_count; j++) {
				struct syscallentry *entry = table[top_nr[j]].entry;
				const char *name = entry ? entry->name : "???";

				output(0, "  %-24s %lu\n", name, top_edges[j]);
			}
		}

		/* Top-N by per-interval edge growth (delta since last dump_stats). */
		{
			unsigned int delta_nr[10];
			unsigned long delta_edges[10];
			unsigned int delta_count = 0;
			bool any_delta = false;

			memset(delta_edges, 0, sizeof(delta_edges));
			for (i = 0; i < nr_syscalls_to_scan; i++) {
				unsigned long prev = kcov_shm->per_syscall_edges_previous[i];
				unsigned long curr = __atomic_load_n(&kcov_shm->per_syscall_edges[i], __ATOMIC_RELAXED);
				unsigned long delta = (curr > prev) ? curr - prev : 0;

				if (delta > 0)
					any_delta = true;

				if (delta == 0)
					continue;

				topn_push(delta_edges, delta_nr, &delta_count, 10, delta, i);
			}

			if (any_delta && delta_count > 0) {
				output(0, "Top syscalls by recent edge growth:\n");
				for (j = 0; j < delta_count; j++) {
					struct syscallentry *entry = table[delta_nr[j]].entry;
					const char *name = entry ? entry->name : "???";

					output(0, "  %-24s +%lu\n", name, delta_edges[j]);
				}
			}

			/* Snapshot current counts for the next interval. */
			for (i = 0; i < nr_syscalls_to_scan; i++)
				kcov_shm->per_syscall_edges_previous[i] =
					__atomic_load_n(&kcov_shm->per_syscall_edges[i], __ATOMIC_RELAXED);
		}

		/* Shadow transition coverage: top-N by real transition-slot
		 * count (cumulative since process start, not since the last
		 * dump) and top-N by per-interval call-count delta.  Printed
		 * directly beside the PC top-N blocks above so the two
		 * signals can be compared at a glance — a syscall that
		 * appears in the transition top-N but not in the PC top-N is
		 * a candidate for the "new control-flow path through warm
		 * code" pattern that the PC bitmap misses by design.  Both
		 * blocks are silent when transition coverage is OFF: the per-
		 * syscall arrays stay zero, so the any_* gates skip the
		 * headers. */
		{
			unsigned int tr_top_nr[10];
			unsigned long tr_top_edges[10];
			unsigned int tr_top_count = 0;
			bool any_tr = false;

			memset(tr_top_edges, 0, sizeof(tr_top_edges));
			for (i = 0; i < nr_syscalls_to_scan; i++) {
				unsigned long tedges = __atomic_load_n(
					&kcov_shm->per_syscall_transition_edges_real[i],
					__ATOMIC_RELAXED);

				if (tedges == 0)
					continue;
				any_tr = true;
				topn_push(tr_top_edges, tr_top_nr, &tr_top_count,
					  10, tedges, i);
			}

			if (any_tr && tr_top_count > 0) {
				output(0, "Top transition-producing syscalls (shadow):\n");
				for (j = 0; j < tr_top_count; j++) {
					struct syscallentry *entry = table[tr_top_nr[j]].entry;
					const char *name = entry ? entry->name : "???";

					output(0, "  %-24s %lu\n",
					       name, tr_top_edges[j]);
				}
			}
		}

		{
			unsigned int tr_delta_nr[10];
			unsigned long tr_delta_edges[10];
			unsigned int tr_delta_count = 0;
			bool any_tr_delta = false;

			memset(tr_delta_edges, 0, sizeof(tr_delta_edges));
			for (i = 0; i < nr_syscalls_to_scan; i++) {
				unsigned long prev = kcov_shm->per_syscall_transition_edges_previous[i];
				unsigned long curr = __atomic_load_n(
					&kcov_shm->per_syscall_transition_edges[i],
					__ATOMIC_RELAXED);
				unsigned long delta = (curr > prev) ? curr - prev : 0;

				if (delta > 0)
					any_tr_delta = true;
				if (delta == 0)
					continue;

				topn_push(tr_delta_edges, tr_delta_nr,
					  &tr_delta_count, 10, delta, i);
			}

			if (any_tr_delta && tr_delta_count > 0) {
				output(0, "Top syscalls by recent transition growth (shadow):\n");
				for (j = 0; j < tr_delta_count; j++) {
					struct syscallentry *entry = table[tr_delta_nr[j]].entry;
					const char *name = entry ? entry->name : "???";

					output(0, "  %-24s +%lu\n",
					       name, tr_delta_edges[j]);
				}
			}

			for (i = 0; i < nr_syscalls_to_scan; i++)
				kcov_shm->per_syscall_transition_edges_previous[i] =
					__atomic_load_n(
						&kcov_shm->per_syscall_transition_edges[i],
						__ATOMIC_RELAXED);
		}

		/* Sibling of "Top syscalls by recent edge growth": top-N by
		 * delta of per_syscall_cmp_inserts since the last dump_stats().
		 * A syscall whose CMP-insert rate is high while its edge-growth
		 * rate is flat is producing CMP signal that is not turning into
		 * coverage -- the CMP-rising-PC-flat plateau pattern. */
		{
			unsigned int cmp_delta_nr[10];
			unsigned long cmp_delta_inserts[10];
			unsigned int cmp_delta_count = 0;
			bool any_cmp_delta = false;

			memset(cmp_delta_inserts, 0, sizeof(cmp_delta_inserts));
			for (i = 0; i < nr_syscalls_to_scan; i++) {
				unsigned long prev = kcov_shm->per_syscall_cmp_inserts_previous[i];
				unsigned long curr = __atomic_load_n(&kcov_shm->per_syscall_cmp_inserts[i], __ATOMIC_RELAXED);
				unsigned long delta = (curr > prev) ? curr - prev : 0;

				if (delta > 0)
					any_cmp_delta = true;

				if (delta == 0)
					continue;

				topn_push(cmp_delta_inserts, cmp_delta_nr, &cmp_delta_count, 10, delta, i);
			}

			if (any_cmp_delta && cmp_delta_count > 0) {
				output(0, "Top syscalls by CMP unique inserts (since last dump):\n");
				for (j = 0; j < cmp_delta_count; j++) {
					struct syscallentry *entry = table[cmp_delta_nr[j]].entry;
					const char *name = entry ? entry->name : "???";

					output(0, "  %-24s +%lu\n", name, cmp_delta_inserts[j]);
				}
			}

			for (i = 0; i < nr_syscalls_to_scan; i++)
				kcov_shm->per_syscall_cmp_inserts_previous[i] =
					__atomic_load_n(&kcov_shm->per_syscall_cmp_inserts[i], __ATOMIC_RELAXED);
		}

		if (cold_count > 0) {
			output(0, "Cold syscalls (need better sanitise): %u\n", cold_count);
			for (i = 0; i < nr_syscalls_to_scan; i++) {
				struct syscallentry *entry;

				unsigned long slot_edges = __atomic_load_n(&kcov_shm->per_syscall_edges[i], __ATOMIC_RELAXED);

				if (slot_edges == 0)
					continue;
				if (!kcov_syscall_is_cold(i))
					continue;

				entry = table[i].entry;
				output(0, "  %-24s (edges:%lu, last new @ call %lu)\n",
					entry ? entry->name : "???",
					slot_edges,
					kcov_shm->last_edge_at[i]);
			}
		}

		/* Per-syscall errno histogram.  Sibling to the top edge-
		 * producing / cold-syscalls tables above: same MAX_NR_SYSCALL-
		 * indexed walk, same all-zero-row skip, same column-width
		 * convention as the "Top edge-producing syscalls" block.  Eight
		 * buckets in dump order: success, EFAULT, EINVAL, ENOSYS,
		 * EPERM, EBADF, EAGAIN, other.  Bumped from handle_syscall_ret()
		 * next to where the existing entry->failures / entry->errnos[]
		 * tallies are updated.  Sort order matches the top-edges block:
		 * descending by total syscall activity (sum of all eight
		 * buckets) so the syscalls doing the most work appear first. */
		{
			unsigned int errno_top_nr[10];
			unsigned long errno_top_total[10];
			unsigned long errno_top_buckets[10][ERRNO_BUCKET_NR];
			unsigned int errno_top_count = 0;

			memset(errno_top_total, 0, sizeof(errno_top_total));
			memset(errno_top_buckets, 0, sizeof(errno_top_buckets));

			for (i = 0; i < nr_syscalls_to_scan; i++) {
				unsigned long buckets[ERRNO_BUCKET_NR];
				unsigned long total = 0;
				unsigned int b;

				for (b = 0; b < ERRNO_BUCKET_NR; b++) {
					buckets[b] = __atomic_load_n(&kcov_shm->per_syscall_errno[i][b],
								     __ATOMIC_RELAXED);
					total += buckets[b];
				}

				/* Skip rows where all eight buckets are zero --
				 * mirrors the top-edges block's `edges == 0`
				 * skip.  A syscall that was never attempted (or
				 * was attempted but never reached AFTER) contributes
				 * nothing and would just be table noise. */
				if (total == 0)
					continue;

				/* Insertion sort, same shape as the top-edges block. */
				for (j = errno_top_count;
				     j > 0 && total > errno_top_total[j - 1]; j--) {
					if (j < 10) {
						errno_top_total[j] = errno_top_total[j - 1];
						errno_top_nr[j] = errno_top_nr[j - 1];
						memcpy(errno_top_buckets[j],
						       errno_top_buckets[j - 1],
						       sizeof(errno_top_buckets[j]));
					}
				}
				if (j < 10) {
					errno_top_total[j] = total;
					errno_top_nr[j] = i;
					memcpy(errno_top_buckets[j], buckets,
					       sizeof(errno_top_buckets[j]));
					if (errno_top_count < 10)
						errno_top_count++;
				}
			}

			if (errno_top_count > 0) {
				output(0, "Top syscalls by errno-histogram activity:\n");
				output(0, "  %-24s %10s %8s %8s %8s %8s %8s %8s %8s\n",
				       "syscall", "ok", "EFAULT", "EINVAL",
				       "ENOSYS", "EPERM", "EBADF", "EAGAIN", "other");
				for (j = 0; j < errno_top_count; j++) {
					struct syscallentry *entry = table[errno_top_nr[j]].entry;
					const char *name = entry ? entry->name : "???";

					output(0, "  %-24s %10lu %8lu %8lu %8lu %8lu %8lu %8lu %8lu\n",
					       name,
					       errno_top_buckets[j][ERRNO_BUCKET_SUCCESS],
					       errno_top_buckets[j][ERRNO_BUCKET_EFAULT],
					       errno_top_buckets[j][ERRNO_BUCKET_EINVAL],
					       errno_top_buckets[j][ERRNO_BUCKET_ENOSYS],
					       errno_top_buckets[j][ERRNO_BUCKET_EPERM],
					       errno_top_buckets[j][ERRNO_BUCKET_EBADF],
					       errno_top_buckets[j][ERRNO_BUCKET_EAGAIN],
					       errno_top_buckets[j][ERRNO_BUCKET_OTHER]);
				}
			}
		}

		/* Credential-class oracle dump.  Always-on observability:
		 * per-class call / success / EPERM / EINVAL / throttled
		 * counts so the operator can spot a class burning attempts
		 * with zero successes (the diagnostic signature the throttle
		 * exists to fix) without grepping the per-syscall errno
		 * histogram for the nine credential names by hand.  The
		 * `throttled` column is bumped only when --cred-throttle is
		 * on and the gate fired; non-zero values double as a "flag
		 * was active and engaged" indicator.  Silent when no class
		 * has any activity. */
		{
			bool any = false;
			unsigned int c;

			for (c = 0; c < CRED_CLASS_NR; c++) {
				if (__atomic_load_n(&shm->stats.cred_class_calls[c],
						    __ATOMIC_RELAXED) != 0) {
					any = true;
					break;
				}
			}
			if (any) {
				output(0, "Credential-class oracle (--cred-throttle %s):\n",
				       cred_throttle ? "ON" : "OFF");
				output(0, "  %-12s %10s %10s %10s %10s %10s\n",
				       "class", "calls", "success",
				       "EPERM", "EINVAL", "throttled");
				for (c = 0; c < CRED_CLASS_NR; c++) {
					unsigned long calls = __atomic_load_n(
						&shm->stats.cred_class_calls[c],
						__ATOMIC_RELAXED);
					unsigned long succ = __atomic_load_n(
						&shm->stats.cred_class_success[c],
						__ATOMIC_RELAXED);
					unsigned long eperm = __atomic_load_n(
						&shm->stats.cred_class_eperm[c],
						__ATOMIC_RELAXED);
					unsigned long einval = __atomic_load_n(
						&shm->stats.cred_class_einval[c],
						__ATOMIC_RELAXED);
					unsigned long thr = __atomic_load_n(
						&shm->stats.cred_class_throttled[c],
						__ATOMIC_RELAXED);

					if (calls == 0 && thr == 0)
						continue;
					output(0, "  %-12s %10lu %10lu %10lu %10lu %10lu\n",
					       cred_class_name[c], calls,
					       succ, eperm, einval, thr);
				}
			}
		}

		/* per-syscall +
		 * per-childop local-vs-remote PC yield, top-N by combined
		 * call count.  Lets the operator see whether a static
		 * remote-sampling policy is spending samples on a mode that
		 * yields no fresh edges -- the global remote_calls counter
		 * above can't answer that question.  Silent when no slot has
		 * any combined activity; columns: calls / edge-calls /
		 * raw-edge-count per mode. */
		{
			unsigned int lr_top_nr[10];
			unsigned long lr_top_total[10];
			unsigned int lr_top_count = 0;

			memset(lr_top_total, 0, sizeof(lr_top_total));
			for (i = 0; i < nr_syscalls_to_scan; i++) {
				unsigned long lc = __atomic_load_n(
					&kcov_shm->local_pc_calls[i],
					__ATOMIC_RELAXED);
				unsigned long rc = __atomic_load_n(
					&kcov_shm->remote_pc_calls[i],
					__ATOMIC_RELAXED);
				unsigned long tot = lc + rc;

				if (tot == 0)
					continue;
				topn_push(lr_top_total, lr_top_nr,
					  &lr_top_count, 10, tot, i);
			}
			if (lr_top_count > 0) {
				output(0, "Local vs remote PC yield per syscall (top by combined calls):\n");
				output(0, "  %-24s %10s %10s %10s %10s %10s %10s\n",
				       "syscall",
				       "loc_calls", "loc_eCalls", "loc_eCount",
				       "rem_calls", "rem_eCalls", "rem_eCount");
				for (j = 0; j < lr_top_count; j++) {
					struct syscallentry *entry =
						table[lr_top_nr[j]].entry;
					const char *name = entry ? entry->name : "???";
					unsigned int nr = lr_top_nr[j];
					unsigned long lc = __atomic_load_n(
						&kcov_shm->local_pc_calls[nr],
						__ATOMIC_RELAXED);
					unsigned long lec = __atomic_load_n(
						&kcov_shm->local_pc_edge_calls[nr],
						__ATOMIC_RELAXED);
					unsigned long len_ = __atomic_load_n(
						&kcov_shm->local_pc_edge_count[nr],
						__ATOMIC_RELAXED);
					unsigned long rc = __atomic_load_n(
						&kcov_shm->remote_pc_calls[nr],
						__ATOMIC_RELAXED);
					unsigned long rec = __atomic_load_n(
						&kcov_shm->remote_pc_edge_calls[nr],
						__ATOMIC_RELAXED);
					unsigned long ren = __atomic_load_n(
						&kcov_shm->remote_pc_edge_count[nr],
						__ATOMIC_RELAXED);

					output(0, "  %-24s %10lu %10lu %10lu %10lu %10lu %10lu\n",
					       name, lc, lec, len_, rc, rec, ren);
				}
			}
		}
		{
			unsigned int lr_top_op[10];
			unsigned long lr_top_total[10];
			unsigned int lr_top_count = 0;
			unsigned int op;

			memset(lr_top_total, 0, sizeof(lr_top_total));
			for (op = 0; op < KCOV_CHILDOP_NR_MAX; op++) {
				unsigned long lc = __atomic_load_n(
					&kcov_shm->childop_local_pc_calls[op],
					__ATOMIC_RELAXED);
				unsigned long rc = __atomic_load_n(
					&kcov_shm->childop_remote_pc_calls[op],
					__ATOMIC_RELAXED);
				unsigned long tot = lc + rc;

				if (tot == 0)
					continue;
				topn_push(lr_top_total, lr_top_op,
					  &lr_top_count, 10, tot, op);
			}
			if (lr_top_count > 0) {
				output(0, "Local vs remote PC yield per childop (top by combined calls):\n");
				output(0, "  %-24s %10s %10s %10s %10s %10s %10s\n",
				       "childop",
				       "loc_calls", "loc_eCalls", "loc_eCount",
				       "rem_calls", "rem_eCalls", "rem_eCount");
				for (j = 0; j < lr_top_count; j++) {
					unsigned int op_id = lr_top_op[j];
					char opname[64];
					unsigned long lc = __atomic_load_n(
						&kcov_shm->childop_local_pc_calls[op_id],
						__ATOMIC_RELAXED);
					unsigned long lec = __atomic_load_n(
						&kcov_shm->childop_local_pc_edge_calls[op_id],
						__ATOMIC_RELAXED);
					unsigned long len_ = __atomic_load_n(
						&kcov_shm->childop_local_pc_edge_count[op_id],
						__ATOMIC_RELAXED);
					unsigned long rc = __atomic_load_n(
						&kcov_shm->childop_remote_pc_calls[op_id],
						__ATOMIC_RELAXED);
					unsigned long rec = __atomic_load_n(
						&kcov_shm->childop_remote_pc_edge_calls[op_id],
						__ATOMIC_RELAXED);
					unsigned long ren = __atomic_load_n(
						&kcov_shm->childop_remote_pc_edge_count[op_id],
						__ATOMIC_RELAXED);

					snprintf(opname, sizeof(opname), "%s",
						 alt_op_name((enum child_op_type)op_id));
					output(0, "  %-24s %10lu %10lu %10lu %10lu %10lu %10lu\n",
					       opname, lc, lec, len_, rc, rec, ren);
				}
			}
		}

		/* Per-syscall + per-childop view of remote-edge yield,
		 * sorted by REMOTE edge count.  The combined-calls block
		 * above ranks by traffic; this one ranks by what actually
		 * fell out of remote-mode collection so the operator can
		 * see which slots are paying the cost of remote sampling
		 * vs. which are silent on that arm.  Render-only over the
		 * existing per_syscall/childop local|remote counters.  The
		 * flag column tags rows whose remote eCount is >= 50% of
		 * the leader across both sub-tables (HEAVY); the rate
		 * columns show local and remote edge-call yield (edge
		 * calls per call). */
		{
			unsigned int re_top_nr[10];
			unsigned long re_top_rec[10];
			unsigned int re_top_count = 0;
			unsigned int op_top_id[10];
			unsigned long op_top_rec[10];
			unsigned int op_top_count = 0;
			unsigned long max_rec = 0;
			unsigned int op;

			memset(re_top_rec, 0, sizeof(re_top_rec));
			memset(op_top_rec, 0, sizeof(op_top_rec));

			for (i = 0; i < nr_syscalls_to_scan; i++) {
				unsigned long rec = __atomic_load_n(
					&kcov_shm->remote_pc_edge_count[i],
					__ATOMIC_RELAXED);

				if (rec == 0)
					continue;
				if (rec > max_rec)
					max_rec = rec;
				topn_push(re_top_rec, re_top_nr,
					  &re_top_count, 10, rec, i);
			}
			for (op = 0; op < KCOV_CHILDOP_NR_MAX; op++) {
				unsigned long rec = __atomic_load_n(
					&kcov_shm->childop_remote_pc_edge_count[op],
					__ATOMIC_RELAXED);

				if (rec == 0)
					continue;
				if (rec > max_rec)
					max_rec = rec;
				topn_push(op_top_rec, op_top_id,
					  &op_top_count, 10, rec, op);
			}

			if (re_top_count > 0 || op_top_count > 0) {
				output(0, "Top remote-edge producers (by rem_eCount):\n");
				output(0, "  %-2s %-24s %10s %10s %10s %10s %10s %10s %6s %6s\n",
				       "fl", "entry",
				       "loc_calls", "loc_eCalls", "loc_eCount",
				       "rem_calls", "rem_eCalls", "rem_eCount",
				       "loc_r", "rem_r");
			}

			for (j = 0; j < re_top_count; j++) {
				struct syscallentry *entry =
					table[re_top_nr[j]].entry;
				const char *name = entry ? entry->name : "???";
				unsigned int nr = re_top_nr[j];
				unsigned long lc = __atomic_load_n(
					&kcov_shm->local_pc_calls[nr],
					__ATOMIC_RELAXED);
				unsigned long lec = __atomic_load_n(
					&kcov_shm->local_pc_edge_calls[nr],
					__ATOMIC_RELAXED);
				unsigned long len_ = __atomic_load_n(
					&kcov_shm->local_pc_edge_count[nr],
					__ATOMIC_RELAXED);
				unsigned long rc = __atomic_load_n(
					&kcov_shm->remote_pc_calls[nr],
					__ATOMIC_RELAXED);
				unsigned long rec = __atomic_load_n(
					&kcov_shm->remote_pc_edge_calls[nr],
					__ATOMIC_RELAXED);
				unsigned long ren = re_top_rec[j];
				char fbuf[4], lrate[8], rrate[8];

				remote_edge_row_flags(fbuf, sizeof(fbuf),
						      ren, max_rec);
				remote_edge_format_yield(lrate, sizeof(lrate),
							 lec, lc);
				remote_edge_format_yield(rrate, sizeof(rrate),
							 rec, rc);
				output(0, "  %-2s %-24s %10lu %10lu %10lu %10lu %10lu %10lu %6s %6s\n",
				       fbuf, name, lc, lec, len_,
				       rc, rec, ren, lrate, rrate);
			}
			for (j = 0; j < op_top_count; j++) {
				unsigned int op_id = op_top_id[j];
				const char *opname = alt_op_name(
					(enum child_op_type)op_id);
				unsigned long lc = __atomic_load_n(
					&kcov_shm->childop_local_pc_calls[op_id],
					__ATOMIC_RELAXED);
				unsigned long lec = __atomic_load_n(
					&kcov_shm->childop_local_pc_edge_calls[op_id],
					__ATOMIC_RELAXED);
				unsigned long len_ = __atomic_load_n(
					&kcov_shm->childop_local_pc_edge_count[op_id],
					__ATOMIC_RELAXED);
				unsigned long rc = __atomic_load_n(
					&kcov_shm->childop_remote_pc_calls[op_id],
					__ATOMIC_RELAXED);
				unsigned long rec = __atomic_load_n(
					&kcov_shm->childop_remote_pc_edge_calls[op_id],
					__ATOMIC_RELAXED);
				unsigned long ren = op_top_rec[j];
				char fbuf[4], lrate[8], rrate[8];

				remote_edge_row_flags(fbuf, sizeof(fbuf),
						      ren, max_rec);
				remote_edge_format_yield(lrate, sizeof(lrate),
							 lec, lc);
				remote_edge_format_yield(rrate, sizeof(rrate),
							 rec, rc);
				output(0, "  %-2s %-24s %10lu %10lu %10lu %10lu %10lu %10lu %6s %6s\n",
				       fbuf, opname, lc, lec, len_,
				       rc, rec, ren, lrate, rrate);
			}
		}

		/* Per-syscall view of slots whose edge-producing calls
		 * arrived EXCLUSIVELY on the remote arm (loc_eCalls == 0
		 * && rem_eCalls > 0), sorted by remote edges per remote
		 * edge-producing call.  The rem_eCount-ranked block above
		 * pulls in any slot the remote arm produces on, including
		 * the ones the local arm also finds, so a slot whose
		 * entire edge signal comes from remote sampling can be
		 * drowned out there.  This block lists those slots in
		 * isolation and orders by yield density (rem_eCount /
		 * rem_eCalls), giving a direct read on which
		 * exclusively-remote syscalls are paying for the cost of
		 * remote-mode collection.  Render-only over the existing
		 * per-syscall local|remote counters; no new shm. */
		{
			unsigned int ro_top_nr[10];
			unsigned long ro_top_rate[10];
			unsigned int ro_top_count = 0;

			memset(ro_top_rate, 0, sizeof(ro_top_rate));

			for (i = 0; i < nr_syscalls_to_scan; i++) {
				unsigned long lec = __atomic_load_n(
					&kcov_shm->local_pc_edge_calls[i],
					__ATOMIC_RELAXED);
				unsigned long rec = __atomic_load_n(
					&kcov_shm->remote_pc_edge_calls[i],
					__ATOMIC_RELAXED);
				unsigned long ren, rate;

				if (lec != 0 || rec == 0)
					continue;
				ren = __atomic_load_n(
					&kcov_shm->remote_pc_edge_count[i],
					__ATOMIC_RELAXED);
				/* rec > 0 here; ren >= rec by
				 * construction so rate is >= 1.000. */
				rate = (ren * 1000UL) / rec;
				topn_push(ro_top_rate, ro_top_nr,
					  &ro_top_count, 10, rate, i);
			}

			if (ro_top_count > 0) {
				output(0, "Remote-only edge winners (by rem_eCount/rem_eCalls):\n");
				output(0, "  %-24s %10s %10s %10s %10s %8s\n",
				       "syscall", "loc_calls", "rem_calls",
				       "rem_eCalls", "rem_eCount", "rate");
				for (j = 0; j < ro_top_count; j++) {
					struct syscallentry *entry =
						table[ro_top_nr[j]].entry;
					const char *name = entry ? entry->name : "???";
					unsigned int nr = ro_top_nr[j];
					unsigned long milli = ro_top_rate[j];
					unsigned long lc = __atomic_load_n(
						&kcov_shm->local_pc_calls[nr],
						__ATOMIC_RELAXED);
					unsigned long rc = __atomic_load_n(
						&kcov_shm->remote_pc_calls[nr],
						__ATOMIC_RELAXED);
					unsigned long rec = __atomic_load_n(
						&kcov_shm->remote_pc_edge_calls[nr],
						__ATOMIC_RELAXED);
					unsigned long ren = __atomic_load_n(
						&kcov_shm->remote_pc_edge_count[nr],
						__ATOMIC_RELAXED);

					output(0, "  %-24s %10lu %10lu %10lu %10lu %4lu.%03lu\n",
					       name, lc, rc, rec, ren,
					       milli / 1000, milli % 1000);
				}
			}
		}

		/* Per-syscall remote-enable health, sorted by the
		 * req - succ gap.  The four counters partition the
		 * kcov_enable_remote() path itself: requested is
		 * bumped once control is past the early-out and the
		 * KCOV_REMOTE_ENABLE ioctl is about to be attempted;
		 * succeeded once that ioctl returns 0; failed once
		 * it exhausts its EINTR retries or returns a
		 * non-EINTR error and flips remote_capable=false;
		 * remote_fallback_to_local once the PC-mode fallback
		 * ioctl that follows such a failure itself
		 * succeeds.  The yield-side local|remote split
		 * blocks above can only fold a refused remote enable
		 * into the local-mode column (the same child still
		 * produced PC-mode coverage via fallback), so a
		 * HEAVY-flagged slot whose KCOV_REMOTE_ENABLE
		 * consistently fails reads there as "zero remote
		 * yield" indistinguishable from "remote was sampled
		 * and the kernel ran the work on the calling task".
		 * Looking at req - succ directly per syscall surfaces
		 * the refusal surface the yield columns hide.
		 * Render-only over the existing per-syscall counters
		 * declared in include/kcov.h; no new shm, no
		 * behaviour change. */
		{
			unsigned int re_top_nr[10];
			unsigned long re_top_gap[10];
			unsigned int re_top_count = 0;

			memset(re_top_gap, 0, sizeof(re_top_gap));

			for (i = 0; i < nr_syscalls_to_scan; i++) {
				unsigned long req = __atomic_load_n(
					&kcov_shm->remote_enable_requested[i],
					__ATOMIC_RELAXED);
				unsigned long succ;
				unsigned long gap;

				if (req == 0)
					continue;
				succ = __atomic_load_n(
					&kcov_shm->remote_enable_succeeded[i],
					__ATOMIC_RELAXED);
				/* req and succ are bumped on separate
				 * RELAXED stores in kcov_enable_remote();
				 * under pressure a reader can sample
				 * succ ahead of its matching req bump.
				 * Clamp the unsigned subtraction so a
				 * torn sample never wraps to ~ULONG_MAX. */
				gap = succ >= req ? 0 : req - succ;
				topn_push(re_top_gap, re_top_nr,
					  &re_top_count, 10, gap, i);
			}

			if (re_top_count > 0) {
				output(0, "Per-syscall remote-enable health (by req-succ gap):\n");
				output(0, "  %-24s %10s %10s %10s %10s %10s %8s\n",
				       "syscall", "req", "succ", "fail",
				       "fb_loc", "gap", "gRate");
				for (j = 0; j < re_top_count; j++) {
					struct syscallentry *entry =
						table[re_top_nr[j]].entry;
					const char *name = entry ? entry->name : "???";
					unsigned int nr = re_top_nr[j];
					unsigned long req = __atomic_load_n(
						&kcov_shm->remote_enable_requested[nr],
						__ATOMIC_RELAXED);
					unsigned long succ = __atomic_load_n(
						&kcov_shm->remote_enable_succeeded[nr],
						__ATOMIC_RELAXED);
					unsigned long fail = __atomic_load_n(
						&kcov_shm->remote_enable_failed[nr],
						__ATOMIC_RELAXED);
					unsigned long fbl = __atomic_load_n(
						&kcov_shm->remote_fallback_to_local[nr],
						__ATOMIC_RELAXED);
					unsigned long gap = succ >= req ? 0 : req - succ;
					unsigned long milli = (gap * 1000UL) / req;

					output(0, "  %-24s %10lu %10lu %10lu %10lu %10lu %4lu.%03lu\n",
					       name, req, succ, fail, fbl, gap,
					       milli / 1000, milli % 1000);
				}
			}
		}

		/* Per-syscall view of slots whose remote-mode enable was
		 * attempted at least REMOTE_WASTE_FLOOR times yet produced
		 * zero remote edges, sorted by remote-enable requested.
		 * The rem_eCount-ranked and remote-only views above pull
		 * in slots that DO yield on the remote arm; this block is
		 * the inverse cut, lifting out the slots where remote
		 * sampling has paid its KCOV_REMOTE_ENABLE / disable
		 * round-trip cost enough times to be statistically
		 * meaningful and earned nothing back, so the operator can
		 * read the demote-candidate list directly.  HEAVY is
		 * surfaced in its own column because the same condition
		 * on a HEAVY-flagged syscall is the loudest signal: the
		 * syscall is paying the heavier sampling rate and still
		 * carrying zero remote yield.  The waste verdict gates on
		 * remote_enable_requested (bumped on entry to the
		 * KCOV_REMOTE_ENABLE attempt) rather than remote_pc_calls
		 * (bumped only on a successful collect) so a syscall whose
		 * enable consistently falls back to local-mode PC coverage
		 * is not hidden by its own refusal surface; succ and fail
		 * are printed alongside so a "wasted" reading can be split
		 * into "sampled enough and produced no edge" vs "rarely
		 * even successfully sampled".  Render-only over the
		 * existing per-syscall counters declared in include/kcov.h;
		 * no new shm, no behaviour change to the collection or
		 * fuzzing path.  No childop variant: the per-childop
		 * remote-enable counters the verdict needs do not exist
		 * (childop enable accounting was intentionally deferred). */
		{
			unsigned int w_top_nr[10];
			unsigned long w_top_req[10];
			unsigned int w_top_count = 0;

			memset(w_top_req, 0, sizeof(w_top_req));

			for (i = 0; i < nr_syscalls_to_scan; i++) {
				unsigned long req = __atomic_load_n(
					&kcov_shm->remote_enable_requested[i],
					__ATOMIC_RELAXED);
				unsigned long rec;

				if (req < REMOTE_WASTE_FLOOR)
					continue;
				rec = __atomic_load_n(
					&kcov_shm->remote_pc_edge_calls[i],
					__ATOMIC_RELAXED);
				if (rec != 0)
					continue;
				topn_push(w_top_req, w_top_nr,
					  &w_top_count, 10, req, i);
			}

			if (w_top_count > 0) {
				output(0, "Wasted-remote syscalls (req >= %lu, rem_eCalls == 0):\n",
				       REMOTE_WASTE_FLOOR);
				output(0, "  %-2s %-24s %10s %10s %10s %10s %10s %10s\n",
				       "fl", "syscall",
				       "req", "succ", "fail", "fb_loc",
				       "rem_calls", "rem_eCount");
				for (j = 0; j < w_top_count; j++) {
					struct syscallentry *entry =
						table[w_top_nr[j]].entry;
					const char *name = entry ? entry->name : "???";
					unsigned int nr = w_top_nr[j];
					unsigned long req = w_top_req[j];
					unsigned long succ = __atomic_load_n(
						&kcov_shm->remote_enable_succeeded[nr],
						__ATOMIC_RELAXED);
					unsigned long fail = __atomic_load_n(
						&kcov_shm->remote_enable_failed[nr],
						__ATOMIC_RELAXED);
					unsigned long fbl = __atomic_load_n(
						&kcov_shm->remote_fallback_to_local[nr],
						__ATOMIC_RELAXED);
					unsigned long rc = __atomic_load_n(
						&kcov_shm->remote_pc_calls[nr],
						__ATOMIC_RELAXED);
					unsigned long ren = __atomic_load_n(
						&kcov_shm->remote_pc_edge_count[nr],
						__ATOMIC_RELAXED);
					bool heavy = entry &&
						(entry->flags & KCOV_REMOTE_HEAVY);

					output(0, "  %-2s %-24s %10lu %10lu %10lu %10lu %10lu %10lu\n",
					       heavy ? "H" : "-", name,
					       req, succ, fail, fbl, rc, ren);
				}
			}
		}

		/* combined top-N
		 * trace_truncated + cmp_trace_truncated + max_trace_size
		 * table plus a dedup-probe-overflow summary line.  Lets
		 * buffer-policy decisions read off the cross-counter signal
		 * (saturate-without-trunc vs trunc-with-modest-max) that
		 * the per-counter blocks below flatten.  Diagnostic only. */
		kcov_diag_emit_truncation_topn();

		/* Per-syscall KCOV diagnostic blocks.  See kcov_diag_emit_block:
		 * one top-20-non-zero block per counter, alphabetical by
		 * counter name, silent when no syscall has a non-zero
		 * value. */
		kcov_diag_emit_block("bucket_bits_real",
				     KCOV_DIAG_BUCKET_BITS_REAL);
		kcov_diag_emit_block("cmp_trace_truncated",
				     KCOV_DIAG_CMP_TRACE_TRUNCATED);
		kcov_diag_emit_block("dedup_probe_overflow",
				     KCOV_DIAG_DEDUP_PROBE_OVERFLOW);
		kcov_diag_emit_block("distinct_pcs",
				     KCOV_DIAG_DISTINCT_PCS);
		kcov_diag_emit_block("max_trace_size",
				     KCOV_DIAG_MAX_TRACE_SIZE);
		kcov_diag_emit_block("trace_truncated",
				     KCOV_DIAG_TRACE_TRUNCATED);
	}
}

static void dump_stats_corpus_and_taint_tail(void)
{
	unsigned int i;

	if (minicorpus_shm != NULL) {
		unsigned long tot_trials = 0;
		unsigned long r_count, r_wins, s_hits, s_wins, pct10;
		unsigned long histo_total;
		char hbuf[80];
		int hpos;

		for (i = 0; i < MUT_NUM_OPS; i++)
			tot_trials += __atomic_load_n(&minicorpus_shm->mut_trials[i],
						      __ATOMIC_RELAXED);

		if (tot_trials > 0) {
			output(0, "\nMutator productivity (wins/trials  [structured wins/trials]):\n");
			for (i = 0; i < MUT_NUM_OPS; i++) {
				unsigned long t  = __atomic_load_n(&minicorpus_shm->mut_trials[i],
								   __ATOMIC_RELAXED);
				unsigned long w  = __atomic_load_n(&minicorpus_shm->mut_wins[i],
								   __ATOMIC_RELAXED);
				unsigned long st = __atomic_load_n(
					&minicorpus_shm->mut_structured_trials[i],
					__ATOMIC_RELAXED);
				unsigned long sw = __atomic_load_n(
					&minicorpus_shm->mut_structured_wins[i],
					__ATOMIC_RELAXED);
				unsigned long spct10 = st ? (sw * 1000UL / st) : 0UL;

				pct10 = t ? (w * 1000UL / t) : 0UL;
				output(0, "  %-10s %lu/%lu (%lu.%lu%%)  [%lu/%lu (%lu.%lu%%)]\n",
				       op_names[i], w, t, pct10 / 10, pct10 % 10,
				       sw, st, spct10 / 10, spct10 % 10);
			}
		}

		s_hits = __atomic_load_n(&minicorpus_shm->splice_hits, __ATOMIC_RELAXED);
		s_wins = __atomic_load_n(&minicorpus_shm->splice_wins, __ATOMIC_RELAXED);
		if (s_hits > 0) {
			pct10 = s_wins * 1000UL / s_hits;
			output(0, "Splice: %lu hits  %lu wins (%lu.%lu%%)\n",
			       s_hits, s_wins, pct10 / 10, pct10 % 10);
		}

		{
			unsigned long xp_hits = __atomic_load_n(
				&minicorpus_shm->xprop_hits, __ATOMIC_RELAXED);
			unsigned long xp_wins = __atomic_load_n(
				&minicorpus_shm->xprop_wins, __ATOMIC_RELAXED);

			if (xp_hits > 0) {
				pct10 = xp_wins * 1000UL / xp_hits;
				output(0, "Xprop: %lu hits  %lu wins (%lu.%lu%%)\n",
				       xp_hits, xp_wins, pct10 / 10, pct10 % 10);
			}
		}

		/* Lockless-reader torn-read validator firings (aggregate over
		 * xprop pick, replay common, replay burst).  Gated on non-zero
		 * because the expected steady-state value is 0 -- the writer's
		 * release-store publish pattern makes mid-publish reads rare.
		 * A non-zero rate here means the validator is doing real work
		 * and torn reads ARE happening at the printed rate. */
		{
			unsigned long torn = __atomic_load_n(
				&minicorpus_shm->replay_torn_rejects,
				__ATOMIC_RELAXED);

			if (torn > 0)
				output(0, "Corpus torn-read rejects: %lu\n", torn);
		}

		histo_total = 0;
		for (i = 1; i <= STACK_MAX; i++)
			histo_total += __atomic_load_n(&minicorpus_shm->stack_depth_histogram[i],
						       __ATOMIC_RELAXED);
		if (histo_total > 0) {
			int written;

			hpos = 0;
			for (i = 1; i <= STACK_MAX; i++) {
				unsigned long d = __atomic_load_n(
					&minicorpus_shm->stack_depth_histogram[i],
					__ATOMIC_RELAXED);
				/* Bound BEFORE snprintf — sizeof(hbuf)-hpos goes to
				 * zero when full, but snprintf still returns the
				 * would-have-written length and the next iteration's
				 * hbuf+hpos lands past the buffer.  Stop here. */
				if (hpos >= (int)sizeof(hbuf) - 1)
					break;
				written = snprintf(hbuf + hpos, sizeof(hbuf) - hpos,
						   " [%u]:%lu", i, d);
				if (written < 0)
					break;
				hpos += written;
			}
			output(0, "Stack depth:%s\n", hbuf);
		}

		r_count = __atomic_load_n(&minicorpus_shm->replay_count, __ATOMIC_RELAXED);
		r_wins  = __atomic_load_n(&minicorpus_shm->replay_wins,  __ATOMIC_RELAXED);
		if (r_count > 0) {
			pct10 = r_wins * 1000UL / r_count;
			output(0, "Corpus replay: %lu replays  %lu wins (%lu.%lu%%)\n",
			       r_count, r_wins, pct10 / 10, pct10 % 10);
		}

		/* CMP-source save / win telemetry.  Always emit when the
		 * minicorpus block is being dumped -- a zero on saves_cmp is
		 * itself a signal worth seeing ("the gate widening is in but
		 * the path isn't firing"), per the falsification criteria in
		 * the investigations/ analysis. */
		{
			unsigned long saves_pc = __atomic_load_n(
				&minicorpus_shm->saves_by_reason[CORPUS_SAVE_REASON_PC],
				__ATOMIC_RELAXED);
			unsigned long saves_cmp = __atomic_load_n(
				&minicorpus_shm->saves_by_reason[CORPUS_SAVE_REASON_CMP],
				__ATOMIC_RELAXED);
			unsigned long saves_errno = __atomic_load_n(
				&minicorpus_shm->saves_by_reason[CORPUS_SAVE_REASON_ERRNO],
				__ATOMIC_RELAXED);
			unsigned long cmp_wins = __atomic_load_n(
				&minicorpus_shm->mut_attrib_cmp_wins,
				__ATOMIC_RELAXED);
			unsigned long errno_would = __atomic_load_n(
				&shm->stats.errno_grad_save_would_save,
				__ATOMIC_RELAXED);
			unsigned long errno_did = __atomic_load_n(
				&shm->stats.errno_grad_save_did_save,
				__ATOMIC_RELAXED);

			output(0, "Corpus saves: pc=%lu cmp=%lu errno=%lu  mut wins (cmp-source): %lu\n",
			       saves_pc, saves_cmp, saves_errno, cmp_wins);
			output(0, "Errno-gradient save: would=%lu did=%lu (gate=%s)\n",
			       errno_would, errno_did,
			       corpus_save_errno_grad_live ? "live" : "shadow");
		}

		/*
		 * Per-tag productivity for the C.2b post-fill struct-field
		 * mutator.  Independent from the per-op MUT_NUM_OPS counters
		 * dumped above -- different injection point, different
		 * histogram axis.  Suppressed when the aggregate trial count
		 * is zero so a build / fleet that never invoked the path
		 * stays clean; a single non-zero slot brings the whole
		 * histogram into view so per-tag relative productivity
		 * (FT_FLAGS bit-flips vs FT_RAW noise) is greppable.
		 * Skip-listed tags (FT_PTR_*, FT_LEN_*, FT_FD, FT_ADDRESS,
		 * FT_BPF_PROGRAM, FT_TAGGED_UNION) stay zero by design and
		 * are silently skipped to keep the output compact.
		 */
		{
			static const char *const tag_names[FT_NUM_TAGS] = {
				[FT_RAW]		= "raw",
				[FT_ENUM]		= "enum",
				[FT_RANGE]		= "range",
				[FT_FLAGS]		= "flags",
				[FT_PTR_BYTES]		= "ptr_bytes",
				[FT_PTR_ARRAY]		= "ptr_array",
				[FT_PTR_STRUCT]		= "ptr_struct",
				[FT_LEN_BYTES]		= "len_bytes",
				[FT_LEN_COUNT]		= "len_count",
				[FT_FD]			= "fd",
				[FT_MAGIC]		= "magic",
				[FT_VERSION_MAGIC]	= "vermagic",
				[FT_ADDRESS]		= "address",
				[FT_TAGGED_UNION]	= "tagged_union",
				[FT_BPF_PROGRAM]	= "bpf_program",
				[FT_VOCAB]		= "vocab",
				[FT_PICKER]		= "picker",
			};
			unsigned long sf_total = 0;
			unsigned int t;

			for (t = 0; t < FT_NUM_TAGS; t++)
				sf_total += __atomic_load_n(
					&minicorpus_shm->mut_struct_field_trials[t],
					__ATOMIC_RELAXED);

			if (sf_total > 0) {
				output(0, "\nStruct-field mutator wins/trials (per tag):\n");
				for (t = 0; t < FT_NUM_TAGS; t++) {
					unsigned long tr = __atomic_load_n(
						&minicorpus_shm->mut_struct_field_trials[t],
						__ATOMIC_RELAXED);
					unsigned long wn = __atomic_load_n(
						&minicorpus_shm->mut_struct_field_wins[t],
						__ATOMIC_RELAXED);
					unsigned long tag_pct10;

					if (tr == 0 || tag_names[t] == NULL)
						continue;
					tag_pct10 = wn * 1000UL / tr;
					output(0, "  %-12s %lu/%lu (%lu.%lu%%)\n",
					       tag_names[t], wn, tr,
					       tag_pct10 / 10, tag_pct10 % 10);
				}
			}
		}

		{
			unsigned long c_iter = __atomic_load_n(
				&minicorpus_shm->chain_iter_count,
				__ATOMIC_RELAXED);
			unsigned long c_subst = __atomic_load_n(
				&minicorpus_shm->chain_substitution_count,
				__ATOMIC_RELAXED);
			unsigned long c_save = chain_corpus_shm ? __atomic_load_n(
				&chain_corpus_shm->save_count,
				__ATOMIC_RELAXED) : 0UL;
			unsigned long c_replay = chain_corpus_shm ? __atomic_load_n(
				&chain_corpus_shm->replay_count,
				__ATOMIC_RELAXED) : 0UL;

			if (c_iter > 0)
				output(0, "Sequence chains: %lu iters  %lu substitutions  %lu corpus saves  %lu replays\n",
				       c_iter, c_subst, c_save, c_replay);
		}
	}

	if (cmp_hints_shm != NULL) {
		unsigned int total_hints = 0, syscalls_with_hints = 0;
		unsigned int a;

		/* Per-arch slots count individually -- same rationale as the
		 * JSON emitter above. */
		for (i = 0; i < MAX_NR_SYSCALL; i++) {
			for (a = 0; a < 2; a++) {
				unsigned int n = cmp_hints_pool_safe_count(&cmp_hints_shm->pools[i][a]);

				if (n > 0) {
					total_hints += n;
					syscalls_with_hints++;
				}
			}
		}
		stat_row("cmp_hints", "values_total",        total_hints);
		stat_row("cmp_hints", "syscalls_with_hints", syscalls_with_hints);
	}

	/*
	 * Periodic snapshot of /proc/sys/kernel/tainted so successive
	 * stats dumps record when the kernel became tainted and which
	 * flags were set, without waiting for is_tainted()'s mask-gated
	 * "became tainted" trip.  Skipped on a clean kernel to match
	 * the "suppress when zero" convention of the surrounding blocks.
	 * mask row carries the raw bitmask; one row per recognised flag
	 * makes the decoded set greppable.
	 */
	{
		static const struct {
			const char *name;
			int bit;
		} taint_flags[] = {
			{ "PROPRIETARY_MODULE",    TAINT_PROPRIETARY_MODULE },
			{ "FORCED_MODULE",         TAINT_FORCED_MODULE },
			{ "UNSAFE_SMP",            TAINT_UNSAFE_SMP },
			{ "FORCED_RMMOD",          TAINT_FORCED_RMMOD },
			{ "MACHINE_CHECK",         TAINT_MACHINE_CHECK },
			{ "BAD_PAGE",              TAINT_BAD_PAGE },
			{ "USER",                  TAINT_USER },
			{ "DIE",                   TAINT_DIE },
			{ "OVERRIDDEN_ACPI_TABLE", TAINT_OVERRIDDEN_ACPI_TABLE },
			{ "WARN",                  TAINT_WARN },
			{ "CRAP",                  TAINT_CRAP },
			{ "FIRMWARE_WORKAROUND",   TAINT_FIRMWARE_WORKAROUND },
			{ "OOT_MODULE",            TAINT_OOT_MODULE },
		};
		int current_taint = get_taint();
		unsigned int t;

		if (current_taint != 0) {
			stat_row("taint", "mask", (unsigned long)current_taint);
			for (t = 0; t < ARRAY_SIZE(taint_flags); t++)
				if (current_taint & (1U << taint_flags[t].bit))
					stat_row("taint", taint_flags[t].name, 1);
		}
	}
}

/*
 * SHADOW reader for the per-childop decaying edge+wall recency ring.
 * Emits one "childop_decay:" line per op that has been invoked at least
 * once this run, carrying the cached recent-edge and recent-wall totals
 * across the last CHILDOP_DECAY_WINDOWS rotations alongside the
 * cumulative childop_edges_clean[] / childop_wall_ns[] denominators so
 * the operator can read recent vs lifetime yield in the same row.  No
 * scheduler / picker / canary path reads either ring -- the dump is the
 * only consumer today; the C2 spec's future util-table extension is the
 * next consumer.  Skips CHILD_OP_SYSCALL (the syscall path attributes
 * its work through the per-strategy counters, matching the surrounding
 * per-childop dumps) and skips never-invoked ops (skip-zero convention).
 */
void __cold dump_stats_childop_decay_recency(void)
{
	enum child_op_type op;
	unsigned int slot;
	bool any = false;

	slot = __atomic_load_n(&shm->stats.childop_decay_slot,
			       __ATOMIC_RELAXED);

	for (op = CHILD_OP_SYSCALL + 1; op < NR_CHILD_OP_TYPES; op++) {
		unsigned long invocations, recent_edges, recent_wall;
		unsigned long cum_edges, cum_wall;

		invocations = __atomic_load_n(
				&shm->stats.childop_invocations[op],
				__ATOMIC_RELAXED);
		if (invocations == 0)
			continue;

		recent_edges = __atomic_load_n(
				&shm->stats.childop_edge_recent_cached[op],
				__ATOMIC_RELAXED);
		recent_wall = __atomic_load_n(
				&shm->stats.childop_wall_recent_cached[op],
				__ATOMIC_RELAXED);
		cum_edges = __atomic_load_n(
				&shm->stats.childop_edges_clean[op],
				__ATOMIC_RELAXED);
		cum_wall = __atomic_load_n(
				&shm->stats.childop_wall_ns[op],
				__ATOMIC_RELAXED);

		if (!any) {
			output(1,
			       "childop_decay: per-op recent edges+wall over "
			       "last %u windows (slot=%u)\n",
			       (unsigned int)CHILDOP_DECAY_WINDOWS,
			       slot & (CHILDOP_DECAY_WINDOWS - 1));
			any = true;
		}

		output(1,
		       "childop_decay %s: invocations=%lu recent_edges=%lu recent_wall_ns=%lu cum_edges=%lu cum_wall_ns=%lu\n",
		       alt_op_name(op), invocations,
		       recent_edges, recent_wall, cum_edges, cum_wall);
	}
}

void __cold dump_stats(void)
{
	if (stats_json) {
		dump_stats_json();
		return;
	}

	/* Lead the shutdown report with the run-identity block so the
	 * provenance triple + cold/warm carrier state + own-start deltas
	 * are the first thing an operator sees -- the post-mortem hook a
	 * "did this run actually advance coverage" check needs before
	 * any of the downstream tables can be interpreted. */
	stats_runid_render();

	dump_stats_runtime_header();

	dump_stats_per_syscall_tables();

	dump_stats_top_wedging_syscalls();

	dump_stats_top_wedging_childops();

	dump_stats_fd_tracking();

	dump_stats_oracle_anomalies();

	dump_stats_fuzzer_subsystems();

	dump_stats_corruption_and_pool();

	dump_stats_childop_ranked_tables();

	childop_score_dump();

	childop_outcome_window_dump();

	dump_stats_childop_decay_recency();

	dump_stats_shared_buffer_misc();

	dump_stats_strategy_summary();

	dump_stats_childop_runs_local();

	dump_stats_childop_runs_network();

	dump_stats_kcov_block();

	dump_stats_corpus_and_taint_tail();

	/* Cumulative childop vs random-syscall effort split.  Also emitted
	 * mid-run from defense_counters_periodic_dump on the 600 s cadence
	 * for long-fuzz visibility, but a short --dry-run (or any run that
	 * exits before the first periodic dump fires) still needs to see
	 * the block, so emit it unconditionally from the shutdown dump too.
	 * Self-skips silently if no dispatch has happened yet. */
	childop_split_dump();
}
