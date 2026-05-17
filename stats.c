#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "arch.h"
#include "cmp_hints.h"
#include "edgepair.h"
#include "edgepair_ring.h"
#include "healer.h"
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
#include "trinity.h"
#include "utils.h"

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

	for (j = 0; j < NR_ERRNOS; j++) {
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
	for (j = 0; j < NR_ERRNOS; j++) {
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

static void json_emit_kcov_section(void)
{
	unsigned int i, j;
	const struct syscalltable *table;
	unsigned int nr_syscalls_to_scan;
	unsigned long kc_edges, kc_pcs, kc_calls, kc_remote;
	unsigned long kc_cmp_records, kc_cmp_trunc;
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
	kc_pcs    = __atomic_load_n(&kcov_shm->total_pcs,    __ATOMIC_RELAXED);
	kc_calls  = __atomic_load_n(&kcov_shm->total_calls,  __ATOMIC_RELAXED);
	kc_remote = __atomic_load_n(&kcov_shm->remote_calls, __ATOMIC_RELAXED);
	kc_cmp_records = __atomic_load_n(&kcov_shm->cmp_records_collected,
		__ATOMIC_RELAXED);
	kc_cmp_trunc = __atomic_load_n(&kcov_shm->cmp_trace_truncated,
		__ATOMIC_RELAXED);

	nr_syscalls_to_scan = biarch ? max_nr_64bit_syscalls : max_nr_syscalls;
	table = biarch ? syscalls_64bit : syscalls;

	memset(top_edges, 0, sizeof(top_edges));
	memset(delta_edges, 0, sizeof(delta_edges));

	for (i = 0; i < nr_syscalls_to_scan; i++) {
		unsigned long edges = __atomic_load_n(&kcov_shm->per_syscall_edges[i], __ATOMIC_RELAXED);
		unsigned long prev  = kcov_shm->per_syscall_edges_previous[i];
		unsigned long delta = (edges > prev) ? edges - prev : 0;

		if (edges > 0) {
			for (j = top_count; j > 0 && edges > top_edges[j - 1]; j--) {
				if (j < 10) {
					top_edges[j] = top_edges[j - 1];
					top_nr[j] = top_nr[j - 1];
				}
			}
			if (j < 10) {
				top_edges[j] = edges;
				top_nr[j] = i;
				if (top_count < 10)
					top_count++;
			}
		}

		if (delta > 0) {
			for (j = delta_count; j > 0 && delta > delta_edges[j - 1]; j--) {
				if (j < 10) {
					delta_edges[j] = delta_edges[j - 1];
					delta_nr[j] = delta_nr[j - 1];
				}
			}
			if (j < 10) {
				delta_edges[j] = delta;
				delta_nr[j] = i;
				if (delta_count < 10)
					delta_count++;
			}
		}
	}

	printf(",\"kcov\":{\"unique_edges\":%lu,\"total_pcs\":%lu,"
		"\"total_calls\":%lu,\"remote_calls\":%lu,"
		"\"cmp_records_collected\":%lu,\"cmp_trace_truncated\":%lu",
		kc_edges, kc_pcs, kc_calls, kc_remote,
		kc_cmp_records, kc_cmp_trunc);

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
	static const char * const op_names[MUT_NUM_OPS] = {
		"bit-flip", "add", "sub", "boundary", "byte-shuf", "keep",
		"bswap-add", "bswap-sub", "fd-swap"
	};
	unsigned int i;
	unsigned long s_hits, s_wins, r_count, r_wins;
	unsigned long c_iter, c_subst, c_save, c_replay;

	if (minicorpus_shm == NULL) {
		fputs(",\"minicorpus\":null", stdout);
		return;
	}

	fputs(",\"minicorpus\":{\"mutators\":[", stdout);
	for (i = 0; i < MUT_NUM_OPS; i++) {
		unsigned long t = __atomic_load_n(&minicorpus_shm->mut_trials[i], __ATOMIC_RELAXED);
		unsigned long w = __atomic_load_n(&minicorpus_shm->mut_wins[i],   __ATOMIC_RELAXED);

		if (i > 0)
			putchar(',');
		fputs("{\"name\":", stdout);
		json_emit_string(op_names[i]);
		printf(",\"trials\":%lu,\"wins\":%lu}", t, w);
	}
	putchar(']');

	s_hits = __atomic_load_n(&minicorpus_shm->splice_hits, __ATOMIC_RELAXED);
	s_wins = __atomic_load_n(&minicorpus_shm->splice_wins, __ATOMIC_RELAXED);
	printf(",\"splice\":{\"hits\":%lu,\"wins\":%lu}", s_hits, s_wins);

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
	unsigned int i, total_hints = 0, syscalls_with_hints = 0;

	if (cmp_hints_shm == NULL) {
		fputs(",\"cmp_hints\":null", stdout);
		return;
	}

	for (i = 0; i < MAX_NR_SYSCALL; i++) {
		if (cmp_hints_shm->pools[i].count > 0) {
			total_hints += cmp_hints_shm->pools[i].count;
			syscalls_with_hints++;
		}
	}
	printf(",\"cmp_hints\":{\"values_total\":%u,\"syscalls_with_hints\":%u}",
		total_hints, syscalls_with_hints);
}

static void json_emit_edgepair_section(void)
{
	unsigned int i, j;
	unsigned int top_count = 0;
	unsigned int cold_pairs = 0;
	struct {
		unsigned int prev_nr;
		unsigned int curr_nr;
		unsigned long new_edges;
	} top[10];
	const struct syscalltable *table;
	unsigned int nr_max;

	if (!edgepair_is_enabled()) {
		fputs(",\"edgepair\":null", stdout);
		return;
	}

	memset(top, 0, sizeof(top));
	for (i = 0; i < EDGEPAIR_TABLE_SIZE; i++) {
		struct edgepair_entry *e = &parent_edgepair.table[i];
		unsigned long edges;

		if (e->prev_nr == EDGEPAIR_EMPTY)
			continue;
		edges = e->new_edge_count;
		if (edges == 0)
			continue;
		if (edgepair_is_cold(e->prev_nr, e->curr_nr))
			cold_pairs++;

		for (j = top_count; j > 0 && edges > top[j - 1].new_edges; j--) {
			if (j < 10)
				top[j] = top[j - 1];
		}
		if (j < 10) {
			top[j].prev_nr = e->prev_nr;
			top[j].curr_nr = e->curr_nr;
			top[j].new_edges = edges;
			if (top_count < 10)
				top_count++;
		}
	}

	printf(",\"edgepair\":{\"unique_pairs\":%lu,\"total_pair_calls\":%lu,"
		"\"inserts_dropped\":%lu,\"cold_pairs\":%u,\"top_pairs\":[",
		parent_edgepair.pairs_tracked, parent_edgepair.total_pair_calls,
		parent_edgepair.pairs_dropped, cold_pairs);

	table = biarch ? syscalls_64bit : syscalls;
	nr_max = biarch ? max_nr_64bit_syscalls : max_nr_syscalls;
	for (j = 0; j < top_count; j++) {
		const char *prev_name = "???";
		const char *curr_name = "???";

		if (top[j].prev_nr < nr_max && table[top[j].prev_nr].entry)
			prev_name = table[top[j].prev_nr].entry->name;
		if (top[j].curr_nr < nr_max && table[top[j].curr_nr].entry)
			curr_name = table[top[j].curr_nr].entry->name;

		if (j > 0)
			putchar(',');
		fputs("{\"prev\":", stdout);
		json_emit_string(prev_name);
		fputs(",\"curr\":", stdout);
		json_emit_string(curr_name);
		printf(",\"new_edges\":%lu}", top[j].new_edges);
	}
	fputs("]}", stdout);

	/* Match text path: still dump the full table to its on-disk file. */
	edgepair_dump_to_file("edgepair.dump");
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
	size_t      offset;	/* offsetof(struct stats_s, <field>) */
};

struct stat_category {
	const char              *name;		/* JSON object key / text category column */
	size_t                   gate_offset;	/* offsetof of the "is this category active" counter */
	const struct stat_field *fields;
	size_t                   n_fields;
};

#define STAT_FIELD(cat, suffix) \
	{ #suffix, offsetof(struct stats_s, cat##_##suffix) }

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
		printf("%s\"%s\":%lu",
		       i ? "," : "",
		       cat->fields[i].name,
		       stat_field_load(&cat->fields[i]));
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

/*
 * Emit every counter from struct stats_s as a single JSON object.
 * All scalar counters are emitted unconditionally so consumers see a stable
 * schema regardless of which subsystems happened to fire on this run.
 */
static void dump_stats_json(void)
{
	putchar('{');

	json_emit_syscalls_array();

	printf(",\"stats\":{"
		"\"fault_injection\":{\"armed_fail_nth\":%lu,\"returned_enomem\":%lu},"
		"\"fd_lifecycle\":{\"stale_detected\":%lu,\"stale_by_generation\":%lu,"
			"\"closed_tracked\":%lu,\"regenerated\":%lu,\"duped\":%lu,"
			"\"events_processed\":%lu,\"events_dropped\":%lu,"
			"\"hash_reinsert_dropped\":%lu,"
			"\"local_hash_insert_dropped\":%lu,"
			"\"runtime_registered\":%lu,\"epoll_lazy_armed\":%lu,"
			"\"epoll_blocking_poll_skipped\":%lu,"
			"\"random_exhausted\":%lu},"
		"\"oracle\":{\"fd_anomalies\":%lu,\"mmap_anomalies\":%lu,"
			"\"cred_anomalies\":%lu,\"sched_anomalies\":%lu,"
			"\"uid_anomalies\":%lu,\"gid_anomalies\":%lu,"
			"\"setgroups_anomalies\":%lu,\"getegid_anomalies\":%lu,"
			"\"getuid_anomalies\":%lu,\"getgid_anomalies\":%lu,"
				"\"getppid_anomalies\":%lu,\"getcwd_anomalies\":%lu,"
				"\"getpid_anomalies\":%lu,"
				"\"getpgid_anomalies\":%lu,"
				"\"getpgrp_anomalies\":%lu,"
				"\"geteuid_anomalies\":%lu,"
				"\"getsid_anomalies\":%lu,"
				"\"gettid_anomalies\":%lu,"
				"\"setsid_anomalies\":%lu,"
				"\"setpgid_anomalies\":%lu,"
				"\"sched_getscheduler_anomalies\":%lu,"
				"\"getgroups_anomalies\":%lu,"
				"\"getresuid_anomalies\":%lu,"
				"\"getresgid_anomalies\":%lu,"
				"\"umask_anomalies\":%lu,"
				"\"sched_get_priority_max_anomalies\":%lu,"
				"\"sched_get_priority_min_anomalies\":%lu,"
				"\"sched_yield_anomalies\":%lu,"
				"\"getpagesize_anomalies\":%lu,"
				"\"time_anomalies\":%lu,"
				"\"gettimeofday_anomalies\":%lu,"
				"\"newuname_anomalies\":%lu,"
				"\"rt_sigpending_anomalies\":%lu,"
				"\"sched_getaffinity_anomalies\":%lu,"
				"\"rt_sigprocmask_anomalies\":%lu,"
				"\"sched_getparam_anomalies\":%lu,"
				"\"sched_rr_get_interval_anomalies\":%lu,"
				"\"get_robust_list_anomalies\":%lu,"
				"\"getrlimit_anomalies\":%lu,"
				"\"sysinfo_anomalies\":%lu,"
				"\"times_anomalies\":%lu,"
				"\"clock_getres_anomalies\":%lu,"
				"\"capget_anomalies\":%lu,"
				"\"newlstat_anomalies\":%lu,"
				"\"newstat_anomalies\":%lu,"
				"\"newfstat_anomalies\":%lu,"
				"\"newfstatat_anomalies\":%lu,"
				"\"statx_anomalies\":%lu,"
				"\"fstatfs_anomalies\":%lu,"
				"\"fstatfs64_anomalies\":%lu,"
				"\"statfs_anomalies\":%lu,"
				"\"statfs64_anomalies\":%lu,"
				"\"uname_anomalies\":%lu,"
				"\"lsm_list_modules_anomalies\":%lu,"
				"\"listmount_anomalies\":%lu,"
				"\"statmount_anomalies\":%lu,"
				"\"getsockname_anomalies\":%lu,"
				"\"getpeername_anomalies\":%lu,"
				"\"file_getattr_anomalies\":%lu,"
				"\"sched_getattr_anomalies\":%lu,"
				"\"getrusage_anomalies\":%lu,"
				"\"sigpending_anomalies\":%lu,"
				"\"getcpu_anomalies\":%lu,"
				"\"clock_gettime_anomalies\":%lu,"
				"\"get_mempolicy_anomalies\":%lu,"
				"\"lsm_get_self_attr_anomalies\":%lu,"
				"\"prlimit64_anomalies\":%lu,"
				"\"sigaltstack_anomalies\":%lu,"
				"\"olduname_anomalies\":%lu,"
				"\"lookup_dcookie_anomalies\":%lu,"
				"\"getxattr_anomalies\":%lu,"
				"\"lgetxattr_anomalies\":%lu,"
				"\"fgetxattr_anomalies\":%lu,"
				"\"listxattrat_anomalies\":%lu,"
				"\"flistxattr_anomalies\":%lu,"
				"\"listxattr_anomalies\":%lu,"
				"\"llistxattr_anomalies\":%lu,"
				"\"readlink_anomalies\":%lu,"
				"\"readlinkat_anomalies\":%lu,"
				"\"sysfs_anomalies\":%lu},"
		"\"vfs_writes\":{\"procfs\":%lu,\"sysfs\":%lu,\"debugfs\":%lu},"
		"\"memory_pressure\":{\"runs_madv_pageout\":%lu},"
		"\"sched_cycler\":{\"runs\":%lu,\"eperm\":%lu},"
		"\"userns_fuzzer\":{\"runs\":%lu,\"inner_crashed\":%lu,\"unsupported\":%lu},"
		"\"barrier_racer\":{\"runs\":%lu,\"inner_crashed\":%lu},"
		"\"genetlink_fuzzer\":{\"families_discovered\":%lu,\"msgs_sent\":%lu,\"eperm\":%lu},"
		"\"genl_family_calls\":{\"devlink\":%lu,\"nl80211\":%lu,\"taskstats\":%lu,"
			"\"ethtool\":%lu,\"mptcp_pm\":%lu,\"l2tp\":%lu,\"gtp\":%lu,\"macsec\":%lu,"
				"\"netlabel\":%lu,\"team\":%lu,\"hsr\":%lu,\"fou\":%lu,"
				"\"psample\":%lu,\"ila\":%lu,\"ioam6\":%lu,\"seg6\":%lu,"
				"\"thermal\":%lu,\"ipvs\":%lu},"
		"\"nfnl_subsys_calls\":{\"ctnetlink\":%lu,\"ctnetlink_exp\":%lu,"
			"\"nftables\":%lu,\"ipset\":%lu},"
		"\"netlink_generator\":{\"nested_attrs_emitted\":%lu},"
		"\"perf_event_chains\":{\"runs\":%lu,\"groups_created\":%lu,\"ioctl_ops\":%lu},"
		"\"tracefs_fuzzer\":{\"kprobe_writes\":%lu,\"uprobe_writes\":%lu,"
			"\"filter_writes\":%lu,\"event_enable_writes\":%lu,\"misc_writes\":%lu},"
		"\"bpf_lifecycle\":{\"runs\":%lu,\"progs_loaded\":%lu,\"attached\":%lu,"
			"\"triggered\":%lu,\"verifier_rejects\":%lu,\"attach_failed\":%lu,\"eperm\":%lu},"
		"\"bpf_fd_provider\":{\"maps_provided\":%lu,\"progs_provided\":%lu},"
		"\"recipe_runner\":{\"runs\":%lu,\"completed\":%lu,\"partial\":%lu,\"unsupported\":%lu},"
		"\"iouring_recipes\":{\"runs\":%lu,\"completed\":%lu,\"partial\":%lu,\"enosys\":%lu},"
		"\"iouring_eventfd\":{\"register_ok\":%lu,\"register_fail\":%lu,"
			"\"recursive_runs\":%lu,\"recursive_cqes\":%lu},"
		"\"zombie_slots\":{\"pending\":%lu,\"reaped\":%lu,\"timed_out\":%lu},"
		"\"corruption\":{\"fd_event_ring_noncanon\":%lu,"
			"\"fd_event_ring_canary\":%lu,\"fd_event_payload\":%lu,"
			"\"deferred_free_corrupt_ptr\":%lu,"
			"\"post_handler_corrupt_ptr\":%lu,\"deferred_free_reject\":%lu,"
			"\"snapshot_non_heap_reject\":%lu,"
			"\"rec_canary_stomped\":%lu,\"rzs_blanket_reject\":%lu,"
			"\"retfd_blanket_reject\":%lu,"
			"\"sibling_mprotect_failed\":%lu,"
			"\"destroy_object_idx\":%lu,"
			"\"global_obj_uaf_caught\":%lu,"
			"\"maps_uaf_caught\":%lu,"
			"\"pagecache_canary_corrupt_caught\":%lu},"
		"\"shared_buffer\":{\"args_redirected\":%lu,\"range_overlaps_shared_rejects\":%lu,"
			"\"libc_heap_redirected\":%lu,\"libc_heap_embedded_redirected\":%lu,"
			"\"get_writable_address_scribbled_slots_caught\":%lu},"
		"\"refcount_audit\":{\"runs\":%lu,\"fd_anomalies\":%lu,"
			"\"mmap_anomalies\":%lu,\"sock_anomalies\":%lu},"
		"\"fs_lifecycle\":{\"tmpfs\":%lu,\"ramfs\":%lu,\"rdonly\":%lu,"
			"\"overlay\":%lu,\"unsupported\":%lu},"
		"\"signal_storm\":{\"runs\":%lu,\"kill\":%lu,\"sigqueue\":%lu,\"no_targets\":%lu},"
		"\"futex_storm\":{\"runs\":%lu,\"inner_crashed\":%lu,\"iters\":%lu},"
		"\"pipe_thrash\":{\"runs\":%lu,\"pipes\":%lu,\"socketpairs\":%lu,\"alloc_failed\":%lu},"
		"\"fork_storm\":{\"runs\":%lu,\"forks\":%lu,\"failed\":%lu,"
			"\"nested\":%lu,\"reaped_signal\":%lu},"
		"\"pidfd_storm\":{\"runs\":%lu,\"signals\":%lu,\"getfds\":%lu,\"failed\":%lu},"
		"\"madvise_cycler\":{\"runs\":%lu,\"calls\":%lu,\"failed\":%lu},"
		"\"keyring_spam\":{\"runs\":%lu,\"calls\":%lu,\"failed\":%lu},"
		"\"vdso_mremap_race\":{\"runs\":%lu,\"mutations\":%lu,\"helper_segvs\":%lu},"
		"\"flock_thrash\":{\"runs\":%lu,\"locks\":%lu,\"failed\":%lu},"
		"\"xattr_thrash\":{\"runs\":%lu,\"set\":%lu,\"get\":%lu,"
			"\"remove\":%lu,\"list\":%lu,\"failed\":%lu},"
		"\"epoll_volatility\":{\"runs\":%lu,\"ctl_calls\":%lu,\"failed\":%lu},"
		"\"cgroup_churn\":{\"runs\":%lu,\"mkdirs\":%lu,\"rmdirs\":%lu,\"failed\":%lu,"
			"\"psi_race_runs\":%lu,\"psi_race_writes\":%lu,\"psi_race_failed\":%lu},"
		"\"mount_churn\":{\"runs\":%lu,\"mounts\":%lu,\"umounts\":%lu,\"failed\":%lu},"
		"\"uffd_churn\":{\"runs\":%lu,\"registers\":%lu,\"unregisters\":%lu,\"failed\":%lu},"
		"\"iouring_flood\":{\"runs\":%lu,\"submits\":%lu,\"reaped\":%lu,\"failed\":%lu},"
		"\"close_racer\":{\"runs\":%lu,\"pairs\":%lu,\"failed\":%lu,\"thread_spawn_fail\":%lu},"
		"\"socket_family_chain\":{\"runs\":%lu,\"completed\":%lu,\"failed\":%lu,\"authencesn_attempts\":%lu,\"splice_attempts\":%lu},"
		"\"socket_family_grammar\":{\"runs\":%lu,\"completed\":%lu},"
		"\"tls_rotate\":{\"runs\":%lu,\"setup_failed\":%lu,\"ulp_failed\":%lu,\"installs\":%lu,\"rekeys_ok\":%lu,\"rekeys_rejected\":%lu},"
		"\"packet_fanout_thrash\":{\"runs\":%lu,\"setup_failed\":%lu,\"ring_failed\":%lu,\"rings_installed\":%lu,\"mmap_failed\":%lu,\"joins\":%lu,\"rejoins_ok\":%lu,\"rejoins_rejected\":%lu},"
		"\"iouring_net_multishot\":{\"runs\":%lu,\"setup_failed\":%lu,\"pbuf_ring_ok\":%lu,\"pbuf_legacy_ok\":%lu,\"armed\":%lu,\"packets_sent\":%lu,\"completions\":%lu,\"cancel_submitted\":%lu,\"napi_register_ok\":%lu,\"napi_register_fail\":%lu,\"napi_unregister_ok\":%lu,\"napi_unregister_fail\":%lu},"
		"\"tcp_ao_rotate\":{\"runs\":%lu,\"setup_failed\":%lu,\"addkey_rejected\":%lu,\"keys_added\":%lu,\"connect_failed\":%lu,\"connected\":%lu,\"packets_sent\":%lu,\"key_rotations\":%lu,\"info_rejected\":%lu,\"key_dels\":%lu,\"delkey_rejected\":%lu,\"cycles\":%lu},"
		"\"tcp_md5_listener_race\":{\"runs\":%lu,\"setup_failed\":%lu,\"md5_set_ok\":%lu,\"md5_set_failed\":%lu,\"connect_ok\":%lu,\"rst_sent_ok\":%lu,\"completed_ok\":%lu},"
		"\"ipv6_pmtu_race\":{\"runs\":%lu,\"setup_failed\":%lu,\"ptb_sent_ok\":%lu,\"dellink_ok\":%lu,\"completed_ok\":%lu},"
		"\"vrf_fib_churn\":{\"runs\":%lu,\"setup_failed\":%lu,\"link_ok\":%lu,\"addr_ok\":%lu,\"up_ok\":%lu,\"rule_added\":%lu,\"bound\":%lu,\"sendto_ok\":%lu,\"rule2_added\":%lu,\"rule_removed\":%lu,\"link_removed\":%lu},"
		"\"mpls_route_churn\":{\"runs\":%lu,\"label_install_ok\":%lu,\"iptunnel_install_ok\":%lu,\"delete_ok\":%lu,\"ns_unsupported\":%lu},"
		"\"netlink_monitor_race\":{\"runs\":%lu,\"setup_failed\":%lu,\"mon_open\":%lu,\"mut_open\":%lu,\"mut_op_ok\":%lu,\"recv_drained\":%lu,\"group_drop\":%lu,\"group_add\":%lu},"
		"\"tipc_link_churn\":{\"runs\":%lu,\"setup_failed\":%lu,\"bearer_enable_ok\":%lu,\"sock_rdm_ok\":%lu,\"topsrv_connect_ok\":%lu,\"sub_ports_sent\":%lu,\"publish_ok\":%lu,\"bearer_disable_ok\":%lu},"
		"\"tls_ulp_churn\":{\"runs\":%lu,\"setup_failed\":%lu,\"ulp_install_ok\":%lu,\"tx_install_ok\":%lu,\"send_ok\":%lu,\"splice_ok\":%lu,\"rekey_ok\":%lu,\"recv_ok\":%lu},"
		"\"vxlan_encap_churn\":{\"runs\":%lu,\"setup_failed\":%lu,\"link_create_ok\":%lu,\"fdb_add_ok\":%lu,\"link_up_ok\":%lu,\"packet_sent_ok\":%lu,\"link_del_ok\":%lu},"
		"\"ovs_tunnel_vport_churn\":{\"runs\":%lu,\"setup_failed\":%lu,\"create_ok\":%lu,\"delete_ok\":%lu,\"race_dellink_attempted\":%lu},"
		"\"bridge_fdb_stp\":{\"runs\":%lu,\"setup_failed\":%lu,\"bridge_create_ok\":%lu,\"veth_create_ok\":%lu,\"raw_send_ok\":%lu,\"stp_toggle_ok\":%lu,\"fdb_del_ok\":%lu,\"link_del_ok\":%lu,\"vlan_mass_runs\":%lu,\"vlan_mass_max_n\":%lu,\"vlan_mass_enotbufs\":%lu},"
		"\"bridge_conntrack_churn\":{\"runs\":%lu,\"flushes\":%lu,\"pkts_sent\":%lu},"
		"\"nftables_churn\":{\"runs\":%lu,\"setup_failed\":%lu,\"table_create_ok\":%lu,\"set_create_ok\":%lu,\"chain_create_ok\":%lu,\"rule_create_ok\":%lu,\"packet_sent_ok\":%lu,\"rule_insert_ok\":%lu,\"rule_del_ok\":%lu,\"table_del_ok\":%lu,\"payload_expr_emit\":%lu,\"objref_expr_emit\":%lu,\"compat_validate_install_ok\":%lu,\"compat_validate_install_fail\":%lu,\"compat_validate_unsupported\":%lu,\"compat_validate_per_hook_pairs\":%lu,\"dormant_abort_iters\":%lu,\"dormant_abort_eperm\":%lu,\"dormant_abort_emsg\":%lu,\"dormant_abort_ok\":%lu,\"xt_ct_iters\":%lu,\"xt_ct_eperm\":%lu,\"xt_ct_unsupported\":%lu,\"xt_ct_set_ok\":%lu,\"xt_ct_get_ok\":%lu,\"xt_ct_v2_seen\":%lu,\"fwd_loop_runs\":%lu,\"fwd_loop_ns_setup_failed\":%lu,\"fwd_loop_probe_sent_ok\":%lu,\"fwd_loop_completed_ok\":%lu,\"l4frag_iters\":%lu,\"l4frag_install_ok\":%lu,\"l4frag_rule_ok\":%lu,\"l4frag_send_ok\":%lu,\"l4frag_send_failed\":%lu},"
		"\"tc_qdisc_churn\":{\"runs\":%lu,\"setup_failed\":%lu,\"link_create_ok\":%lu,\"qdisc_create_ok\":%lu,\"tclass_create_ok\":%lu,\"tfilter_create_ok\":%lu,\"packet_sent_ok\":%lu,\"qdisc_replace_ok\":%lu,\"tfilter_del_ok\":%lu,\"qdisc_del_ok\":%lu,\"link_del_ok\":%lu,\"peek_stack_runs\":%lu,\"peek_stack_install_ok\":%lu,\"peek_stack_install_fail\":%lu,\"peek_stack_burst_ok\":%lu,\"bridge_parent_runs\":%lu,\"bridge_dellink_race_ok\":%lu},"
		"\"xfrm_churn\":{\"runs\":%lu,\"setup_failed\":%lu,\"sa_added\":%lu,\"sa_updated\":%lu,\"sa_deleted\":%lu,\"pol_added\":%lu,\"pol_deleted\":%lu,\"esp_sent\":%lu,\"pfkey_send_ok\":%lu,\"ah_esn_setup_ok\":%lu,\"ah_esn_setup_fail\":%lu,\"ah_esn_async_runs\":%lu,\"ah_esn_delsa_races\":%lu},"
		"\"bpf_cgroup_attach\":{\"runs\":%lu,\"setup_failed\":%lu,\"prog_loaded\":%lu,\"attached\":%lu,\"attach_rejected\":%lu,\"packets_sent\":%lu,\"detached\":%lu,\"post_detach_sent\":%lu},"
		"\"sctp_assoc_churn\":{\"runs\":%lu,\"setup_failed\":%lu,\"bindx_added\":%lu,\"bindx_removed\":%lu,\"bindx_rejected\":%lu,\"connect_failed\":%lu,\"connected\":%lu,\"accepted\":%lu,\"packets_sent\":%lu,\"peeled_off\":%lu,\"peeloff_rejected\":%lu,\"cycles\":%lu},"
		"\"mptcp_pm_churn\":{\"runs\":%lu,\"setup_failed\":%lu,\"sock_mptcp_ok\":%lu,\"addr_added_ok\":%lu,\"addr_removed_ok\":%lu,\"send_ok\":%lu,\"setsockopt_unsupported\":%lu,\"setsockopt_master_set\":%lu,\"setsockopt_master_fail\":%lu,\"getsockopt_verify_ok\":%lu,\"getsockopt_verify_drift\":%lu,\"sockopt_sweep_runs\":%lu,\"sockopt_set_ok\":%lu,\"sockopt_set_failed\":%lu,\"sockopt_subflow_added\":%lu,\"sockopt_readback_ok\":%lu,\"sockopt_inherit_mismatch\":%lu,\"sockopt_unsupported_latched\":%lu},"
		"\"devlink_port_churn\":{\"iterations\":%lu,\"split_ok\":%lu,\"split_fail\":%lu,\"reload_ok\":%lu,\"reload_fail\":%lu,\"create_skipped\":%lu},"
		"\"handshake_req_abort\":{\"runs\":%lu,\"setup_failed\":%lu,\"accept_ok\":%lu,\"done_ok\":%lu,\"abort_ok\":%lu,\"orphan_close\":%lu},"
		"\"nf_conntrack_helper_churn\":{\"runs\":%lu,\"setup_failed\":%lu,\"no_helper\":%lu,\"attach_ok\":%lu,\"attach_fail\":%lu,\"exp_ok\":%lu,\"packet_sent\":%lu,\"delete_ok\":%lu,\"zone_swap\":%lu,\"detach_ok\":%lu},"
		"\"af_unix_scm_rights_gc\":{\"runs\":%lu,\"setup_failed\":%lu,\"cycle_built_ok\":%lu,\"close_ok\":%lu,\"trigger_ok\":%lu,\"recv_ok\":%lu,\"peek_ok\":%lu,\"iouring_variant_ok\":%lu},"
		"\"netns_teardown\":{\"runs\":%lu,\"setup_failed\":%lu,\"unshare_ok\":%lu,\"socket_pair_ok\":%lu,\"fork_ok\":%lu,\"setns_ok\":%lu,\"kill_ok\":%lu,\"completed_ok\":%lu},"
		"\"tcp_ulp_swap_churn\":{\"runs\":%lu,\"setup_failed\":%lu,\"install_tls_ok\":%lu,\"tx_install_ok\":%lu,\"send_ok\":%lu,\"swap_rejected_ok\":%lu,\"ifname_probe_ok\":%lu,\"uninstall_ok\":%lu,\"reinstall_ok\":%lu,\"install_failed\":%lu},",
		parent_stats.fault_injected, parent_stats.fault_consumed,
		shm->stats.fd_stale_detected, shm->stats.fd_stale_by_generation,
		shm->stats.fd_closed_tracked, shm->stats.fd_regenerated,
		shm->stats.fd_duped, shm->stats.fd_events_processed,
		shm->stats.fd_events_dropped, shm->stats.fd_hash_reinsert_dropped,
		shm->stats.local_fd_hash_insert_dropped,
		shm->stats.fd_runtime_registered,
		shm->stats.epoll_lazy_armed,
		shm->stats.epoll_blocking_poll_skipped,
		shm->stats.fd_random_exhausted,
		shm->stats.fd_oracle_anomalies, shm->stats.mmap_oracle_anomalies,
		shm->stats.cred_oracle_anomalies, shm->stats.sched_oracle_anomalies,
		shm->stats.uid_oracle_anomalies, shm->stats.gid_oracle_anomalies,
		shm->stats.setgroups_oracle_anomalies,
		shm->stats.getegid_oracle_anomalies,
		shm->stats.getuid_oracle_anomalies,
		shm->stats.getgid_oracle_anomalies,
		shm->stats.getppid_oracle_anomalies,
		shm->stats.getcwd_oracle_anomalies,
		shm->stats.getpid_oracle_anomalies,
		shm->stats.getpgid_oracle_anomalies,
		shm->stats.getpgrp_oracle_anomalies,
		shm->stats.geteuid_oracle_anomalies,
		shm->stats.getsid_oracle_anomalies,
		shm->stats.gettid_oracle_anomalies,
		shm->stats.setsid_oracle_anomalies,
		shm->stats.setpgid_oracle_anomalies,
		shm->stats.sched_getscheduler_oracle_anomalies,
		shm->stats.getgroups_oracle_anomalies,
		shm->stats.getresuid_oracle_anomalies,
		shm->stats.getresgid_oracle_anomalies,
		shm->stats.umask_oracle_anomalies,
		shm->stats.sched_get_priority_max_oracle_anomalies,
		shm->stats.sched_get_priority_min_oracle_anomalies,
		shm->stats.sched_yield_oracle_anomalies,
		shm->stats.getpagesize_oracle_anomalies,
		shm->stats.time_oracle_anomalies,
		shm->stats.gettimeofday_oracle_anomalies,
		shm->stats.newuname_oracle_anomalies,
		shm->stats.rt_sigpending_oracle_anomalies,
		shm->stats.sched_getaffinity_oracle_anomalies,
		shm->stats.rt_sigprocmask_oracle_anomalies,
		shm->stats.sched_getparam_oracle_anomalies,
		shm->stats.sched_rr_get_interval_oracle_anomalies,
		shm->stats.get_robust_list_oracle_anomalies,
		shm->stats.getrlimit_oracle_anomalies,
		shm->stats.sysinfo_oracle_anomalies,
		shm->stats.times_oracle_anomalies,
		shm->stats.clock_getres_oracle_anomalies,
		shm->stats.capget_oracle_anomalies,
		shm->stats.newlstat_oracle_anomalies,
		shm->stats.newstat_oracle_anomalies,
		shm->stats.newfstat_oracle_anomalies,
		shm->stats.newfstatat_oracle_anomalies,
		shm->stats.statx_oracle_anomalies,
		shm->stats.fstatfs_oracle_anomalies,
		shm->stats.fstatfs64_oracle_anomalies,
		shm->stats.statfs_oracle_anomalies,
		shm->stats.statfs64_oracle_anomalies,
		shm->stats.uname_oracle_anomalies,
		shm->stats.lsm_list_modules_oracle_anomalies,
		shm->stats.listmount_oracle_anomalies,
		shm->stats.statmount_oracle_anomalies,
		shm->stats.getsockname_oracle_anomalies,
		shm->stats.getpeername_oracle_anomalies,
		shm->stats.file_getattr_oracle_anomalies,
		shm->stats.sched_getattr_oracle_anomalies,
		shm->stats.getrusage_oracle_anomalies,
		shm->stats.sigpending_oracle_anomalies,
		shm->stats.getcpu_oracle_anomalies,
		shm->stats.clock_gettime_oracle_anomalies,
		shm->stats.get_mempolicy_oracle_anomalies,
		shm->stats.lsm_get_self_attr_oracle_anomalies,
		shm->stats.prlimit64_oracle_anomalies,
		shm->stats.sigaltstack_oracle_anomalies,
		shm->stats.olduname_oracle_anomalies,
		shm->stats.lookup_dcookie_oracle_anomalies,
		shm->stats.getxattr_oracle_anomalies,
		shm->stats.lgetxattr_oracle_anomalies,
		shm->stats.fgetxattr_oracle_anomalies,
		shm->stats.listxattrat_oracle_anomalies,
		shm->stats.flistxattr_oracle_anomalies,
		shm->stats.listxattr_oracle_anomalies,
		shm->stats.llistxattr_oracle_anomalies,
		shm->stats.readlink_oracle_anomalies,
		shm->stats.readlinkat_oracle_anomalies,
		shm->stats.sysfs_oracle_anomalies,
		shm->stats.procfs_writes, shm->stats.sysfs_writes, shm->stats.debugfs_writes,
		shm->stats.memory_pressure_runs,
		shm->stats.sched_cycler_runs, shm->stats.sched_cycler_eperm,
		shm->stats.userns_runs, shm->stats.userns_inner_crashed, shm->stats.userns_unsupported,
		shm->stats.barrier_racer_runs, shm->stats.barrier_racer_inner_crashed,
		shm->stats.genetlink_families_discovered, shm->stats.genetlink_msgs_sent,
		shm->stats.genetlink_eperm,
		shm->stats.genl_family_calls_devlink,
		shm->stats.genl_family_calls_nl80211,
		shm->stats.genl_family_calls_taskstats,
		shm->stats.genl_family_calls_ethtool,
		shm->stats.genl_family_calls_mptcp_pm,
		shm->stats.genl_family_calls_l2tp,
		shm->stats.genl_family_calls_gtp,
		shm->stats.genl_family_calls_macsec,
		shm->stats.genl_family_calls_netlabel,
		shm->stats.genl_family_calls_team,
		shm->stats.genl_family_calls_hsr,
		shm->stats.genl_family_calls_fou,
		shm->stats.genl_family_calls_psample,
		shm->stats.genl_family_calls_ila,
		shm->stats.genl_family_calls_ioam6,
		shm->stats.genl_family_calls_seg6,
		shm->stats.genl_family_calls_thermal,
		shm->stats.genl_family_calls_ipvs,
		shm->stats.nfnl_subsys_calls_ctnetlink,
		shm->stats.nfnl_subsys_calls_ctnetlink_exp,
		shm->stats.nfnl_subsys_calls_nftables,
		shm->stats.nfnl_subsys_calls_ipset,
		shm->stats.netlink_nested_attrs_emitted,
		shm->stats.perf_chains_runs, shm->stats.perf_chains_groups_created,
		shm->stats.perf_chains_ioctl_ops,
		shm->stats.tracefs_kprobe_writes, shm->stats.tracefs_uprobe_writes,
		shm->stats.tracefs_filter_writes, shm->stats.tracefs_event_enable_writes,
		shm->stats.tracefs_misc_writes,
		shm->stats.bpf_lifecycle_runs, shm->stats.bpf_lifecycle_progs_loaded,
		shm->stats.bpf_lifecycle_attached, shm->stats.bpf_lifecycle_triggered,
		shm->stats.bpf_lifecycle_verifier_rejects, shm->stats.bpf_lifecycle_attach_failed,
		shm->stats.bpf_lifecycle_eperm,
		shm->stats.bpf_maps_provided, shm->stats.bpf_progs_provided,
		shm->stats.recipe_runs, shm->stats.recipe_completed,
		shm->stats.recipe_partial, shm->stats.recipe_unsupported,
		shm->stats.iouring_recipes_runs, shm->stats.iouring_recipes_completed,
		shm->stats.iouring_recipes_partial, shm->stats.iouring_recipes_enosys,
		shm->stats.iouring_eventfd_register_ok,
		shm->stats.iouring_eventfd_register_fail,
		shm->stats.iouring_eventfd_recursive_runs,
		shm->stats.iouring_eventfd_recursive_cqes,
		shm->stats.zombie_slots_pending, shm->stats.zombies_reaped,
		shm->stats.zombies_timed_out,
		shm->stats.fd_event_ring_corrupted,
		shm->stats.fd_event_ring_overwritten,
		shm->stats.fd_event_payload_corrupt,
		shm->stats.deferred_free_corrupt_ptr,
		shm->stats.post_handler_corrupt_ptr,
		shm->stats.deferred_free_reject,
		shm->stats.snapshot_non_heap_reject,
		shm->stats.rec_canary_stomped,
		shm->stats.rzs_blanket_reject,
		shm->stats.retfd_blanket_reject,
		shm->stats.sibling_mprotect_failed,
		shm->stats.destroy_object_idx_corrupt,
		shm->stats.global_obj_uaf_caught,
		shm->stats.maps_uaf_caught,
		shm->stats.pagecache_canary_corrupt_caught,
		parent_stats.shared_buffer_redirected, parent_stats.range_overlaps_shared_rejects,
		parent_stats.libc_heap_redirected, parent_stats.libc_heap_embedded_redirected,
		parent_stats.get_writable_address_scribbled_slots_caught,
		shm->stats.refcount_audit_runs, shm->stats.refcount_audit_fd_anomalies,
		shm->stats.refcount_audit_mmap_anomalies, shm->stats.refcount_audit_sock_anomalies,
		shm->stats.fs_lifecycle_tmpfs, shm->stats.fs_lifecycle_ramfs,
		shm->stats.fs_lifecycle_rdonly, shm->stats.fs_lifecycle_overlay,
		shm->stats.fs_lifecycle_unsupported,
		shm->stats.signal_storm_runs, shm->stats.signal_storm_kill,
		shm->stats.signal_storm_sigqueue, shm->stats.signal_storm_no_targets,
		shm->stats.futex_storm_runs, shm->stats.futex_storm_inner_crashed,
		shm->stats.futex_storm_iters,
		shm->stats.pipe_thrash_runs, shm->stats.pipe_thrash_pipes,
		shm->stats.pipe_thrash_socketpairs, shm->stats.pipe_thrash_alloc_failed,
		shm->stats.fork_storm_runs, shm->stats.fork_storm_forks,
		shm->stats.fork_storm_failed, shm->stats.fork_storm_nested,
		shm->stats.fork_storm_reaped_signal,
		shm->stats.pidfd_storm_runs, shm->stats.pidfd_storm_signals,
		shm->stats.pidfd_storm_getfds, shm->stats.pidfd_storm_failed,
		shm->stats.madvise_cycler_runs, shm->stats.madvise_cycler_calls,
		shm->stats.madvise_cycler_failed,
		shm->stats.keyring_spam_runs, shm->stats.keyring_spam_calls,
		shm->stats.keyring_spam_failed,
		shm->stats.vdso_race_runs, shm->stats.vdso_race_mutations,
		shm->stats.vdso_race_helper_segvs,
		shm->stats.flock_thrash_runs, shm->stats.flock_thrash_locks,
		shm->stats.flock_thrash_failed,
		shm->stats.xattr_thrash_runs, shm->stats.xattr_thrash_set,
		shm->stats.xattr_thrash_get, shm->stats.xattr_thrash_remove,
		shm->stats.xattr_thrash_list, shm->stats.xattr_thrash_failed,
		shm->stats.epoll_volatility_runs,
		shm->stats.epoll_volatility_ctl_calls,
		shm->stats.epoll_volatility_failed,
		shm->stats.cgroup_churn_runs, shm->stats.cgroup_mkdirs,
		shm->stats.cgroup_rmdirs, shm->stats.cgroup_failed,
		shm->stats.cgroup_psi_race_runs,
		shm->stats.cgroup_psi_race_writes,
		shm->stats.cgroup_psi_race_failed,
		shm->stats.mount_churn_runs, shm->stats.mount_churn_mounts,
		shm->stats.mount_churn_umounts, shm->stats.mount_churn_failed,
		shm->stats.uffd_runs, shm->stats.uffd_registers,
		shm->stats.uffd_unregisters, shm->stats.uffd_failed,
		shm->stats.iouring_runs, shm->stats.iouring_submits,
		shm->stats.iouring_reaped, shm->stats.iouring_failed,
		shm->stats.close_racer_runs, shm->stats.close_racer_pairs,
		shm->stats.close_racer_failed, shm->stats.close_racer_thread_spawn_fail,
		shm->stats.socket_family_chain_runs,
		shm->stats.socket_family_chain_completed,
		shm->stats.socket_family_chain_failed,
		shm->stats.socket_family_chain_authencesn_attempts,
		shm->stats.socket_family_chain_splice_attempts,
		shm->stats.socket_family_grammar_runs,
		shm->stats.socket_family_grammar_completed,
		shm->stats.tls_rotate_runs,
		shm->stats.tls_rotate_setup_failed,
		shm->stats.tls_rotate_ulp_failed,
		shm->stats.tls_rotate_installs,
		shm->stats.tls_rotate_rekeys_ok,
		shm->stats.tls_rotate_rekeys_rejected,
		shm->stats.packet_fanout_runs,
		shm->stats.packet_fanout_setup_failed,
		shm->stats.packet_fanout_ring_failed,
		shm->stats.packet_fanout_rings_installed,
		shm->stats.packet_fanout_mmap_failed,
		shm->stats.packet_fanout_joins,
		shm->stats.packet_fanout_rejoins_ok,
		shm->stats.packet_fanout_rejoins_rejected,
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
		shm->stats.tcp_ao_rotate_runs,
		shm->stats.tcp_ao_rotate_setup_failed,
		shm->stats.tcp_ao_rotate_addkey_rejected,
		shm->stats.tcp_ao_rotate_keys_added,
		shm->stats.tcp_ao_rotate_connect_failed,
		shm->stats.tcp_ao_rotate_connected,
		shm->stats.tcp_ao_rotate_packets_sent,
		shm->stats.tcp_ao_rotate_key_rotations,
		shm->stats.tcp_ao_rotate_info_rejected,
		shm->stats.tcp_ao_rotate_key_dels,
		shm->stats.tcp_ao_rotate_delkey_rejected,
		shm->stats.tcp_ao_rotate_cycles,
		shm->stats.tcp_md5_listener_race_runs,
		shm->stats.tcp_md5_listener_race_setup_failed,
		shm->stats.tcp_md5_listener_race_md5_set_ok,
		shm->stats.tcp_md5_listener_race_md5_set_failed,
		shm->stats.tcp_md5_listener_race_connect_ok,
		shm->stats.tcp_md5_listener_race_rst_sent_ok,
		shm->stats.tcp_md5_listener_race_completed_ok,
		shm->stats.ipv6_pmtu_race_runs,
		shm->stats.ipv6_pmtu_race_setup_failed,
		shm->stats.ipv6_pmtu_race_ptb_sent_ok,
		shm->stats.ipv6_pmtu_race_dellink_ok,
		shm->stats.ipv6_pmtu_race_completed_ok,
		shm->stats.vrf_fib_churn_runs,
		shm->stats.vrf_fib_churn_setup_failed,
		shm->stats.vrf_fib_churn_link_ok,
		shm->stats.vrf_fib_churn_addr_ok,
		shm->stats.vrf_fib_churn_up_ok,
		shm->stats.vrf_fib_churn_rule_added,
		shm->stats.vrf_fib_churn_bound,
		shm->stats.vrf_fib_churn_sendto_ok,
		shm->stats.vrf_fib_churn_rule2_added,
		shm->stats.vrf_fib_churn_rule_removed,
		shm->stats.vrf_fib_churn_link_removed,
		shm->stats.mpls_route_churn_runs,
		shm->stats.mpls_route_churn_label_install_ok,
		shm->stats.mpls_route_churn_iptunnel_install_ok,
		shm->stats.mpls_route_churn_delete_ok,
		shm->stats.mpls_route_churn_ns_unsupported,
		shm->stats.netlink_monitor_race_runs,
		shm->stats.netlink_monitor_race_setup_failed,
		shm->stats.netlink_monitor_race_mon_open,
		shm->stats.netlink_monitor_race_mut_open,
		shm->stats.netlink_monitor_race_mut_op_ok,
		shm->stats.netlink_monitor_race_recv_drained,
		shm->stats.netlink_monitor_race_group_drop,
		shm->stats.netlink_monitor_race_group_add,
		shm->stats.tipc_link_churn_runs,
		shm->stats.tipc_link_churn_setup_failed,
		shm->stats.tipc_link_churn_bearer_enable_ok,
		shm->stats.tipc_link_churn_sock_rdm_ok,
		shm->stats.tipc_link_churn_topsrv_connect_ok,
		shm->stats.tipc_link_churn_sub_ports_sent,
		shm->stats.tipc_link_churn_publish_ok,
		shm->stats.tipc_link_churn_bearer_disable_ok,
		shm->stats.tls_ulp_churn_runs,
		shm->stats.tls_ulp_churn_setup_failed,
		shm->stats.tls_ulp_churn_ulp_install_ok,
		shm->stats.tls_ulp_churn_tx_install_ok,
		shm->stats.tls_ulp_churn_send_ok,
		shm->stats.tls_ulp_churn_splice_ok,
		shm->stats.tls_ulp_churn_rekey_ok,
		shm->stats.tls_ulp_churn_recv_ok,
		shm->stats.vxlan_encap_churn_runs,
		shm->stats.vxlan_encap_churn_setup_failed,
		shm->stats.vxlan_encap_churn_link_create_ok,
		shm->stats.vxlan_encap_churn_fdb_add_ok,
		shm->stats.vxlan_encap_churn_link_up_ok,
		shm->stats.vxlan_encap_churn_packet_sent_ok,
		shm->stats.vxlan_encap_churn_link_del_ok,
		shm->stats.ovs_tunnel_vport_churn_runs,
		shm->stats.ovs_tunnel_vport_churn_setup_failed,
		shm->stats.ovs_tunnel_vport_churn_create_ok,
		shm->stats.ovs_tunnel_vport_churn_delete_ok,
		shm->stats.ovs_tunnel_vport_churn_race_dellink_attempted,
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
		shm->stats.bridge_vlan_mass_enotbufs,
		shm->stats.bridge_ct_runs,
		shm->stats.bridge_ct_flushes,
		shm->stats.bridge_ct_pkts_sent,
		shm->stats.nftables_churn_runs,
		shm->stats.nftables_churn_setup_failed,
		shm->stats.nftables_churn_table_create_ok,
		shm->stats.nftables_churn_set_create_ok,
		shm->stats.nftables_churn_chain_create_ok,
		shm->stats.nftables_churn_rule_create_ok,
		shm->stats.nftables_churn_packet_sent_ok,
		shm->stats.nftables_churn_rule_insert_ok,
		shm->stats.nftables_churn_rule_del_ok,
		shm->stats.nftables_churn_table_del_ok,
		shm->stats.nftables_churn_payload_expr_emit,
		shm->stats.nftables_churn_objref_expr_emit,
		shm->stats.nft_compat_validate_install_ok,
		shm->stats.nft_compat_validate_install_fail,
		shm->stats.nft_compat_validate_unsupported,
		shm->stats.nft_compat_validate_per_hook_pairs,
		shm->stats.nft_dormant_abort_iters,
		shm->stats.nft_dormant_abort_eperm,
		shm->stats.nft_dormant_abort_emsg,
		shm->stats.nft_dormant_abort_ok,
		shm->stats.xt_ct_iters,
		shm->stats.xt_ct_eperm,
		shm->stats.xt_ct_unsupported,
		shm->stats.xt_ct_set_ok,
		shm->stats.xt_ct_get_ok,
		shm->stats.xt_ct_v2_seen,
		shm->stats.nft_fwd_loop_runs,
		shm->stats.nft_fwd_loop_ns_setup_failed,
		shm->stats.nft_fwd_loop_probe_sent_ok,
		shm->stats.nft_fwd_loop_completed_ok,
		shm->stats.nft_l4frag_iters,
		shm->stats.nft_l4frag_install_ok,
		shm->stats.nft_l4frag_rule_ok,
		shm->stats.nft_l4frag_send_ok,
		shm->stats.nft_l4frag_send_failed,
		shm->stats.tc_qdisc_churn_runs,
		shm->stats.tc_qdisc_churn_setup_failed,
		shm->stats.tc_qdisc_churn_link_create_ok,
		shm->stats.tc_qdisc_churn_qdisc_create_ok,
		shm->stats.tc_qdisc_churn_tclass_create_ok,
		shm->stats.tc_qdisc_churn_tfilter_create_ok,
		shm->stats.tc_qdisc_churn_packet_sent_ok,
		shm->stats.tc_qdisc_churn_qdisc_replace_ok,
		shm->stats.tc_qdisc_churn_tfilter_del_ok,
		shm->stats.tc_qdisc_churn_qdisc_del_ok,
		shm->stats.tc_qdisc_churn_link_del_ok,
		shm->stats.tc_qdisc_peek_stack_runs,
		shm->stats.tc_qdisc_peek_stack_install_ok,
		shm->stats.tc_qdisc_peek_stack_install_fail,
		shm->stats.tc_qdisc_peek_stack_burst_ok,
		shm->stats.tc_qdisc_churn_bridge_parent_runs,
		shm->stats.tc_qdisc_churn_bridge_dellink_race_ok,
		shm->stats.xfrm_churn_runs,
		shm->stats.xfrm_churn_setup_failed,
		shm->stats.xfrm_churn_sa_added,
		shm->stats.xfrm_churn_sa_updated,
		shm->stats.xfrm_churn_sa_deleted,
		shm->stats.xfrm_churn_pol_added,
		shm->stats.xfrm_churn_pol_deleted,
		shm->stats.xfrm_churn_esp_sent,
		shm->stats.xfrm_churn_pfkey_send_ok,
		shm->stats.xfrm_ah_esn_setup_ok,
		shm->stats.xfrm_ah_esn_setup_fail,
		shm->stats.xfrm_ah_esn_async_runs,
		shm->stats.xfrm_ah_esn_delsa_races,
		shm->stats.bpf_cgroup_attach_runs,
		shm->stats.bpf_cgroup_attach_setup_failed,
		shm->stats.bpf_cgroup_attach_prog_loaded,
		shm->stats.bpf_cgroup_attach_attached,
		shm->stats.bpf_cgroup_attach_attach_rejected,
		shm->stats.bpf_cgroup_attach_packets_sent,
		shm->stats.bpf_cgroup_attach_detached,
		shm->stats.bpf_cgroup_attach_post_detach_sent,
		shm->stats.sctp_assoc_churn_runs,
		shm->stats.sctp_assoc_churn_setup_failed,
		shm->stats.sctp_assoc_churn_bindx_added,
		shm->stats.sctp_assoc_churn_bindx_removed,
		shm->stats.sctp_assoc_churn_bindx_rejected,
		shm->stats.sctp_assoc_churn_connect_failed,
		shm->stats.sctp_assoc_churn_connected,
		shm->stats.sctp_assoc_churn_accepted,
		shm->stats.sctp_assoc_churn_packets_sent,
		shm->stats.sctp_assoc_churn_peeled_off,
		shm->stats.sctp_assoc_churn_peeloff_rejected,
		shm->stats.sctp_assoc_churn_cycles,
		shm->stats.mptcp_pm_churn_runs,
		shm->stats.mptcp_pm_churn_setup_failed,
		shm->stats.mptcp_pm_churn_sock_mptcp_ok,
		shm->stats.mptcp_pm_churn_addr_added_ok,
		shm->stats.mptcp_pm_churn_addr_removed_ok,
		shm->stats.mptcp_pm_churn_send_ok,
		shm->stats.mptcp_setsockopt_unsupported,
		shm->stats.mptcp_setsockopt_master_set,
		shm->stats.mptcp_setsockopt_master_fail,
		shm->stats.mptcp_getsockopt_verify_ok,
		shm->stats.mptcp_getsockopt_verify_drift,
		shm->stats.mptcp_sockopt_sweep_runs,
		shm->stats.mptcp_sockopt_set_ok,
		shm->stats.mptcp_sockopt_set_failed,
		shm->stats.mptcp_sockopt_subflow_added,
		shm->stats.mptcp_sockopt_readback_ok,
		shm->stats.mptcp_sockopt_inherit_mismatch,
		shm->stats.mptcp_sockopt_unsupported_latched,
		shm->stats.devlink_port_churn_iterations,
		shm->stats.devlink_port_churn_split_ok,
		shm->stats.devlink_port_churn_split_fail,
		shm->stats.devlink_port_churn_reload_ok,
		shm->stats.devlink_port_churn_reload_fail,
		shm->stats.devlink_port_churn_create_skipped,
		shm->stats.handshake_req_abort_runs,
		shm->stats.handshake_req_abort_setup_failed,
		shm->stats.handshake_req_abort_accept_ok,
		shm->stats.handshake_req_abort_done_ok,
		shm->stats.handshake_req_abort_abort_ok,
		shm->stats.handshake_req_abort_orphan_close,
		shm->stats.nf_conntrack_helper_churn_runs,
		shm->stats.nf_conntrack_helper_churn_setup_failed,
		shm->stats.nf_conntrack_helper_churn_no_helper,
		shm->stats.nf_conntrack_helper_churn_attach_ok,
		shm->stats.nf_conntrack_helper_churn_attach_fail,
		shm->stats.nf_conntrack_helper_churn_exp_ok,
		shm->stats.nf_conntrack_helper_churn_packet_sent,
		shm->stats.nf_conntrack_helper_churn_delete_ok,
		shm->stats.nf_conntrack_helper_churn_zone_swap,
		shm->stats.nf_conntrack_helper_churn_detach_ok,
		shm->stats.af_unix_scm_rights_gc_runs,
		shm->stats.af_unix_scm_rights_gc_setup_failed,
		shm->stats.af_unix_scm_rights_gc_cycle_built_ok,
		shm->stats.af_unix_scm_rights_gc_close_ok,
		shm->stats.af_unix_scm_rights_gc_trigger_ok,
		shm->stats.af_unix_scm_rights_gc_recv_ok,
		shm->stats.af_unix_scm_rights_gc_peek_ok,
		shm->stats.af_unix_scm_rights_gc_iouring_variant_ok,
		shm->stats.netns_teardown_runs,
		shm->stats.netns_teardown_setup_failed,
		shm->stats.netns_teardown_unshare_ok,
		shm->stats.netns_teardown_socket_pair_ok,
		shm->stats.netns_teardown_fork_ok,
		shm->stats.netns_teardown_setns_ok,
		shm->stats.netns_teardown_kill_ok,
		shm->stats.netns_teardown_completed_ok,
		shm->stats.tcp_ulp_swap_churn_runs,
		shm->stats.tcp_ulp_swap_churn_setup_failed,
		shm->stats.tcp_ulp_swap_churn_install_tls_ok,
		shm->stats.tcp_ulp_swap_churn_tx_install_ok,
		shm->stats.tcp_ulp_swap_churn_send_ok,
		shm->stats.tcp_ulp_swap_churn_swap_rejected_ok,
		shm->stats.tcp_ulp_swap_churn_ifname_probe_ok,
		shm->stats.tcp_ulp_swap_churn_uninstall_ok,
		shm->stats.tcp_ulp_swap_churn_reinstall_ok,
		shm->stats.tcp_ulp_swap_churn_install_failed);

	stat_category_emit_json(&msg_zerocopy_churn_category);

	printf(",\"iouring_send_zc_churn\":{\"runs\":%lu,\"setup_failed\":%lu,\"register_bufs_ok\":%lu,\"send_zc_ok\":%lu,\"sendmsg_zc_ok\":%lu,\"unregister_race_ok\":%lu,\"update_race_ok\":%lu,\"cqe_drained\":%lu},"
		"\"vsock_transport_churn\":{\"runs\":%lu,\"setup_failed\":%lu,\"bind_ok\":%lu,\"connect_ok\":%lu,\"send_ok\":%lu,\"buffer_size_ok\":%lu,\"timeout_ok\":%lu,\"get_cid_ok\":%lu,\"seq_eom_runs\":%lu,\"seq_eom_sends_ok\":%lu,\"seq_eom_sends_failed\":%lu,\"seq_eom_skipped\":%lu},"
		"\"bridge_vlan_churn\":{\"runs\":%lu,\"setup_failed\":%lu,\"bridge_create_ok\":%lu,\"veth_create_ok\":%lu,\"vlan_add_ok\":%lu,\"vlan_del_ok\":%lu,\"tunnel_add_ok\":%lu,\"mst_set_ok\":%lu,\"raw_send_ok\":%lu},"
		"\"igmp_mld_source_churn\":{\"runs\":%lu,\"setup_failed\":%lu,\"join_ok\":%lu,\"leave_ok\":%lu,\"block_ok\":%lu,\"msfilter_ok\":%lu,\"drop_ok\":%lu,\"send_ok\":%lu},"
		"\"psp_key_rotate\":{\"runs\":%lu,\"setup_failed\":%lu,\"netdev_create_ok\":%lu,\"family_resolve_ok\":%lu,\"dev_get_ok\":%lu,\"key_install_ok\":%lu,\"spi_set_ok\":%lu,\"send_ok\":%lu,\"rotate_ok\":%lu,\"spi_switch_ok\":%lu,\"shutdown_ok\":%lu,\"devlink_port_churn_runs\":%lu,\"devlink_port_churn_port_add_ok\":%lu,\"devlink_port_churn_port_del_ok\":%lu,\"devlink_port_churn_vf_spawn_ok\":%lu,\"devlink_port_churn_unsupported_latched\":%lu},"
		"\"afxdp_churn\":{\"runs\":%lu,\"setup_failed\":%lu,\"umem_reg_ok\":%lu,\"rings_setup_ok\":%lu,\"prog_load_ok\":%lu,\"map_create_ok\":%lu,\"map_update_ok\":%lu,\"bind_ok\":%lu,\"link_attach_ok\":%lu,\"netlink_attach_ok\":%lu,\"attach_failed\":%lu,\"send_ok\":%lu,\"recv_ok\":%lu,\"map_delete_ok\":%lu,\"munmap_race_ok\":%lu,\"xsg_iters\":%lu,\"tx_metadata_iters\":%lu,\"tun_bind_iters\":%lu,\"xsg_bind_failed\":%lu,\"tx_md_bind_failed\":%lu},"
		"\"kvm\":{\"vcpu_ioctls_dispatched\":%lu},"
		"\"kvm_run_churn\":{\"invocations\":%lu,\"exit_io\":%lu,\"exit_mmio\":%lu,\"exit_hlt\":%lu,\"exit_shutdown\":%lu,\"exit_fail_entry\":%lu,\"exit_internal_error\":%lu,\"exit_intr\":%lu,\"exit_other\":%lu,\"errors\":%lu,\"gpc_memslot_race_runs\":%lu,\"gpc_memslot_race_deletes\":%lu,\"gpc_memslot_race_unsupported\":%lu},"
		"\"nl80211\":{\"runs\":%lu,\"setup_failed\":%lu,\"scan_triggered\":%lu,\"connect_attempted\":%lu,\"connect_succeeded\":%lu,\"disconnect_attempted\":%lu,\"regdom_changed\":%lu,\"iface_created\":%lu,\"iface_destroyed\":%lu,\"bursts_sent\":%lu,\"pmsr_runs\":%lu,\"pmsr_ok\":%lu,\"admin_gate_runs\":%lu,\"admin_gate_eperm_ok\":%lu,\"admin_gate_unexpected\":%lu},"
		"\"nat_t_churn\":{\"runs\":%lu,\"setup_failed\":%lu,\"sa_added\":%lu,\"sa_deleted\":%lu,\"frames_sent\":%lu,\"xfrm6_setup_ok\":%lu,\"xfrm6_setup_fail\":%lu,\"xfrm6_sendto_runs\":%lu,\"xfrm6_delsa_races\":%lu},"
		"\"splice_protocols\":{\"runs\":%lu,\"setup_failed\":%lu,\"chain_ok\":%lu,\"in_bytes\":%lu,\"out_bytes\":%lu,\"udp_encap_attempted\":%lu,\"tcp_repair_attempted\":%lu,\"packet_ring_attempted\":%lu,\"alg_attempted\":%lu,\"rxrpc_attempted\":%lu,\"msg_splice_pages_attempted\":%lu,\"msg_splice_pages_path_taken_inferred\":%lu},"
		"\"rxrpc_key_install\":{\"runs\":%lu,\"calls\":%lu,\"revokes\":%lu,\"quota_hits\":%lu,\"unsupported\":%lu},"
		"\"af_alg_weak_cipher_probe\":{\"runs\":%lu,\"socket_failed\":%lu,\"total_bind_attempts\":%lu,\"total_bind_accepted\":%lu,\"weak_accepted_total\":%lu,\"setkey_accepted_total\":%lu,\"skcipher_weak_accepted\":%lu,\"aead_weak_accepted\":%lu,\"hash_weak_accepted\":%lu,\"strong_rejected\":%lu},"
		"\"af_alg_probe\":{\"runs\":%lu,\"unsupported\":%lu,\"accept_total\":%lu,\"reject_total\":%lu},"
		"\"af_alg_recvmsg\":{\"runs\":%lu,\"setkey_sent\":%lu,\"iv_sent\":%lu,\"oob_iov\":%lu,\"zerolen\":%lu,\"oversize\":%lu,\"empty_cmsg_no_more\":%lu,\"unsupported\":%lu},"
		"\"ublk_lifecycle\":{\"iters\":%lu,\"eperm\":%lu,\"add_ok\":%lu,\"fetch_ok\":%lu,\"del_ok\":%lu,\"race_observed\":%lu},"
		"\"veth_asymmetric_xdp\":{\"iters\":%lu,\"eperm\":%lu,\"unsupported\":%lu,\"pair_ok\":%lu,\"xdp_attach_ok\":%lu,\"send_ok\":%lu},"
		"\"ip6erspan_netns_migrate\":{\"iters\":%lu,\"eperm\":%lu,\"unsupported\":%lu,\"link_create_ok\":%lu,\"netns_migrate_ok\":%lu,\"changelink_ok\":%lu},"
		"\"ip6gre_bond_lapb_stack\":{\"runs\":%lu,\"setup_failed\":%lu,\"flag_toggles\":%lu},"
		"\"wireguard_decrypt_flood\":{\"runs\":%lu,\"setup_failed\":%lu,\"packets_sent\":%lu,\"unsupported_latched\":%lu},"
		"\"blkdev_lifecycle_race\":{\"runs\":%lu,\"setup_failed\":%lu,\"set_fd_ok\":%lu,\"clr_fd\":%lu,\"ebusy\":%lu,\"rescans\":%lu},"
		"\"ipvs_sysctl_writer\":{\"runs\":%lu,\"writes_ok\":%lu,\"writes_failed\":%lu,\"unsupported_latched\":%lu,\"burn_iters\":%lu},"
		"\"ipv6_ndisc_proxy\":{\"runs\":%lu,\"ns_sent_ok\":%lu,\"setup_failed\":%lu,\"proxy_enable_ok\":%lu},"
		"\"ipfrag_source_churn\":{\"runs\":%lu,\"packets_sent_ok\":%lu,\"send_failed\":%lu,\"unique_srcs\":%lu},"
		"\"rtnl_vf_broadcast_getlink\":{\"runs\":%lu,\"setup_ok\":%lu,\"setup_failed\":%lu,\"getlink_ok\":%lu},"
		"\"obscure_af_churn\":{\"runs\":%lu,\"no_viable_pf\":%lu,"
			"\"sendmsg_no_bind\":{\"runs\":%lu,\"rejected\":%lu,\"unexpected_success\":%lu},"
			"\"bind_then_sendmsg\":{\"runs\":%lu,\"rejected\":%lu,\"unexpected_success\":%lu},"
			"\"connect_no_listen\":{\"runs\":%lu,\"rejected\":%lu,\"unexpected_success\":%lu},"
			"\"ioctl_rotation\":{\"runs\":%lu,\"rejected\":%lu,\"unexpected_success\":%lu},"
			"\"setsockopt_zero_len\":{\"runs\":%lu,\"rejected\":%lu,\"unexpected_success\":%lu},"
			"\"close_via_dup\":{\"runs\":%lu,\"rejected\":%lu,\"unexpected_success\":%lu}},"
		"\"flowtable_encap_vlan\":{\"runs\":%lu,\"setup_ok\":%lu,\"setup_failed\":%lu,\"offloaded_pkts\":%lu,\"gso_sends\":%lu,\"vlan_teardown_races\":%lu,\"unsupported_latched\":%lu},"
		"\"rxrpc_sendmsg_cmsg_churn\":{\"runs\":%lu,\"socket_failed\":%lu,\"sendmsg_ok\":%lu,\"sendmsg_fail\":%lu,"
			"\"user_call_id\":%lu,\"abort\":%lu,\"accept\":%lu,\"exclusive_call\":%lu,"
			"\"upgrade_service\":%lu,\"tx_length\":%lu,\"set_call_timeout\":%lu,\"charge_accept\":%lu},"
		"\"tty_ldisc_churn\":{\"runs\":%lu,\"setup_failed\":%lu,\"ldisc_set_ok\":%lu,\"ldisc_set_failed\":%lu,"
			"\"write_ok\":%lu,\"read_ok\":%lu,"
			"\"per_disc\":[%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu]}"
		"}",
		shm->stats.iouring_send_zc_churn_runs,
		shm->stats.iouring_send_zc_churn_setup_failed,
		shm->stats.iouring_send_zc_churn_register_bufs_ok,
		shm->stats.iouring_send_zc_churn_send_zc_ok,
		shm->stats.iouring_send_zc_churn_sendmsg_zc_ok,
		shm->stats.iouring_send_zc_churn_unregister_race_ok,
		shm->stats.iouring_send_zc_churn_update_race_ok,
		shm->stats.iouring_send_zc_churn_cqe_drained,
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
		shm->stats.bridge_vlan_churn_runs,
		shm->stats.bridge_vlan_churn_setup_failed,
		shm->stats.bridge_vlan_churn_bridge_create_ok,
		shm->stats.bridge_vlan_churn_veth_create_ok,
		shm->stats.bridge_vlan_churn_vlan_add_ok,
		shm->stats.bridge_vlan_churn_vlan_del_ok,
		shm->stats.bridge_vlan_churn_tunnel_add_ok,
		shm->stats.bridge_vlan_churn_mst_set_ok,
		shm->stats.bridge_vlan_churn_raw_send_ok,
		shm->stats.igmp_mld_source_churn_runs,
		shm->stats.igmp_mld_source_churn_setup_failed,
		shm->stats.igmp_mld_source_churn_join_ok,
		shm->stats.igmp_mld_source_churn_leave_ok,
		shm->stats.igmp_mld_source_churn_block_ok,
		shm->stats.igmp_mld_source_churn_msfilter_ok,
		shm->stats.igmp_mld_source_churn_drop_ok,
		shm->stats.igmp_mld_source_churn_send_ok,
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
		shm->stats.nat_t_xfrm6_delsa_races,
		shm->stats.splice_protocols_runs,
		shm->stats.splice_protocols_setup_failed,
		shm->stats.splice_protocols_chain_ok,
		shm->stats.splice_protocols_in_bytes,
		shm->stats.splice_protocols_out_bytes,
		shm->stats.splice_protocols_udp_encap_attempted,
		shm->stats.splice_protocols_tcp_repair_attempted,
		shm->stats.splice_protocols_packet_ring_attempted,
		shm->stats.splice_protocols_alg_attempted,
		shm->stats.splice_protocols_rxrpc_attempted,
		shm->stats.splice_protocols_msg_splice_pages_attempted,
		shm->stats.splice_protocols_msg_splice_pages_path_taken_inferred,
		shm->stats.rxrpc_key_install_runs,
		shm->stats.rxrpc_key_install_calls,
		shm->stats.rxrpc_key_install_revokes,
		shm->stats.rxrpc_key_install_quota_hits,
		shm->stats.rxrpc_key_install_unsupported,
		shm->stats.af_alg_weak_cipher_probe_runs,
		shm->stats.af_alg_weak_cipher_probe_socket_failed,
		shm->stats.af_alg_weak_cipher_probe_total_bind_attempts,
		shm->stats.af_alg_weak_cipher_probe_total_bind_accepted,
		shm->stats.af_alg_weak_cipher_probe_weak_accepted_total,
		shm->stats.af_alg_weak_cipher_probe_setkey_accepted_total,
		shm->stats.af_alg_weak_cipher_probe_skcipher_weak_accepted,
		shm->stats.af_alg_weak_cipher_probe_aead_weak_accepted,
		shm->stats.af_alg_weak_cipher_probe_hash_weak_accepted,
		shm->stats.af_alg_weak_cipher_probe_strong_rejected,
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
		shm->stats.af_alg_recvmsg_unsupported,
		shm->stats.ublk_lifecycle_iters,
		shm->stats.ublk_lifecycle_eperm,
		shm->stats.ublk_lifecycle_add_ok,
		shm->stats.ublk_lifecycle_fetch_ok,
		shm->stats.ublk_lifecycle_del_ok,
		shm->stats.ublk_lifecycle_race_observed,
		shm->stats.veth_asym_iters,
		shm->stats.veth_asym_eperm,
		shm->stats.veth_asym_unsupported,
		shm->stats.veth_asym_pair_ok,
		shm->stats.veth_asym_xdp_attach_ok,
		shm->stats.veth_asym_send_ok,
		shm->stats.inm_iters,
		shm->stats.inm_eperm,
		shm->stats.inm_unsupported,
		shm->stats.inm_link_create_ok,
		shm->stats.inm_netns_migrate_ok,
		shm->stats.inm_changelink_ok,
		shm->stats.ip6gre_lapb_runs,
		shm->stats.ip6gre_lapb_setup_failed,
		shm->stats.ip6gre_lapb_flag_toggles,
		shm->stats.wgdf_runs,
		shm->stats.wgdf_setup_failed,
		shm->stats.wgdf_packets_sent,
		shm->stats.wgdf_unsupported_latched,
		shm->stats.blkdev_lifecycle_runs,
		shm->stats.blkdev_lifecycle_setup_failed,
		shm->stats.blkdev_lifecycle_set_fd_ok,
		shm->stats.blkdev_lifecycle_clr_fd,
		shm->stats.blkdev_lifecycle_ebusy,
		shm->stats.blkdev_lifecycle_rescans,
		shm->stats.ipvs_sysctl_writer_runs,
		shm->stats.ipvs_sysctl_writer_writes_ok,
		shm->stats.ipvs_sysctl_writer_writes_failed,
		shm->stats.ipvs_sysctl_writer_unsupported_latched,
		shm->stats.ipvs_sysctl_writer_burn_iters,
		shm->stats.ipv6_ndisc_proxy_runs,
		shm->stats.ipv6_ndisc_proxy_ns_sent_ok,
		shm->stats.ipv6_ndisc_proxy_setup_failed,
		shm->stats.ipv6_ndisc_proxy_proxy_enable_ok,
		shm->stats.ipfrag_source_runs,
		shm->stats.ipfrag_packets_sent_ok,
		shm->stats.ipfrag_send_failed,
		shm->stats.ipfrag_unique_srcs,
		shm->stats.rtnl_vf_broadcast_runs,
		shm->stats.rtnl_vf_broadcast_setup_ok,
		shm->stats.rtnl_vf_broadcast_setup_failed,
		shm->stats.rtnl_vf_broadcast_getlink_ok,
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
		shm->stats.flowtable_vlan_runs,
		shm->stats.flowtable_vlan_setup_ok,
		shm->stats.flowtable_vlan_setup_failed,
		shm->stats.flowtable_vlan_offloaded_pkts,
		shm->stats.flowtable_vlan_gso_sends,
		shm->stats.flowtable_vlan_vlan_teardown_races,
		shm->stats.flowtable_vlan_unsupported_latched,
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

	/*
	 * Per-childop arrays in struct stats_s indexed by NR_CHILD_OP_TYPES
	 * (taint_transitions[], pool_race_aborted[],
	 * childop_edges_discovered[]) are intentionally not emitted here.
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
	json_emit_edgepair_section();

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
 * Spike detector for shm->stats.post_handler_corrupt_ptr.  Called once
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
	 * not mis-attributed to this window. */
	if (window_start.tv_sec == 0) {
		window_start = now;
		window_baseline = __atomic_load_n(&shm->stats.post_handler_corrupt_ptr,
						  __ATOMIC_RELAXED);
		return;
	}

	if ((now.tv_sec - window_start.tv_sec) < CORRUPT_PTR_SPIKE_WINDOW_SEC)
		return;

	current = __atomic_load_n(&shm->stats.post_handler_corrupt_ptr,
				  __ATOMIC_RELAXED);
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
	{ "get_writable_address_scribbled_slots_caught",
	  offsetof(struct stats_aggregate, get_writable_address_scribbled_slots_caught), true },
	{ "post_handler_corrupt_ptr",
	  offsetof(struct stats_s, post_handler_corrupt_ptr) },
	{ "deferred_free_reject",
	  offsetof(struct stats_s, deferred_free_reject) },
	{ "snapshot_non_heap_reject",
	  offsetof(struct stats_s, snapshot_non_heap_reject) },
	{ "deferred_free_corrupt_ptr",
	  offsetof(struct stats_s, deferred_free_corrupt_ptr) },
	{ "rec_canary_stomped",
	  offsetof(struct stats_s, rec_canary_stomped) },
	{ "rzs_blanket_reject",
	  offsetof(struct stats_s, rzs_blanket_reject) },
	{ "retfd_blanket_reject",
	  offsetof(struct stats_s, retfd_blanket_reject) },
	{ "execve_self_exec_blocked",
	  offsetof(struct stats_s, execve_self_exec_blocked) },
	{ "sibling_mprotect_failed",
	  offsetof(struct stats_s, sibling_mprotect_failed) },
	{ "sibling_refreeze_count",
	  offsetof(struct stats_s, sibling_refreeze_count) },
	{ "divergence_sentinel_anomalies",
	  offsetof(struct stats_s, divergence_sentinel_anomalies) },
	{ "iouring_enter_mask_corrupt",
	  offsetof(struct stats_s, iouring_enter_mask_corrupt) },
	{ "fd_event_ring_corrupted",
	  offsetof(struct stats_s, fd_event_ring_corrupted) },
	{ "fd_event_ring_overwritten",
	  offsetof(struct stats_s, fd_event_ring_overwritten) },
	{ "fd_event_payload_corrupt",
	  offsetof(struct stats_s, fd_event_payload_corrupt) },
	{ "destroy_object_idx_corrupt",
	  offsetof(struct stats_s, destroy_object_idx_corrupt) },
	{ "global_obj_uaf_caught",
	  offsetof(struct stats_s, global_obj_uaf_caught) },
	{ "maps_uaf_caught",
	  offsetof(struct stats_s, maps_uaf_caught) },
	{ "pagecache_canary_corrupt_caught",
	  offsetof(struct stats_s, pagecache_canary_corrupt_caught) },
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
	/* STRATEGY_HEALER picker counters: cold-start (no predecessor, biarch
	 * skip), pair-path success, triple-path success (subset that also
	 * mixed in the triple table), and zero-weight fallback.  Surface the
	 * arm's effective behaviour at the same dump granularity as the other
	 * per-strategy counters above. */
	{ "healer_picker_cold_start",
	  offsetof(struct stats_s, healer_picker_cold_start) },
	{ "healer_picker_pair_path",
	  offsetof(struct stats_s, healer_picker_pair_path) },
	{ "healer_picker_triple_path",
	  offsetof(struct stats_s, healer_picker_triple_path) },
	{ "healer_picker_zero_weight_fallback",
	  offsetof(struct stats_s, healer_picker_zero_weight_fallback) },
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
	 * fd_regenerated keeps climbing means children aren't picking up
	 * the regenerated epfds — i.e. the consumer wireup regressed. */
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
 * share one snap+sort across the dump pass.  Silent when no entry
 * matches -- pre-sub-attribution runs and quiet handlers stay terse.
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
				    unsigned int nr, bool do32bit)
{
	unsigned int i;

	for (i = 0; i < CORRUPT_PTR_PC_SLOTS; i++) {
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
		/* When the caller of post_handler_corrupt_ptr_bump_site
		 * supplied a site tag (e.g. add_object: defence-in-depth
		 * walls that all share dispatch_step+0x336 after LTO inlining
		 * collapses __builtin_return_address(0)), render it inline so
		 * the dump disambiguates rejection sites that the bare PC
		 * cannot.  Falls back to PC-only when no tag was passed. */
		if (snap[i].site != NULL && src != NULL)
			stats_log_write("    %-32s [%s] (%s) %lu\n",
					pc_to_string(snap[i].pc, pcbuf, sizeof(pcbuf)),
					snap[i].site, src, snap[i].count);
		else if (snap[i].site != NULL)
			stats_log_write("    %-32s [%s] %lu\n",
					pc_to_string(snap[i].pc, pcbuf, sizeof(pcbuf)),
					snap[i].site, snap[i].count);
		else if (src != NULL)
			stats_log_write("    %-32s (%s) %lu\n",
					pc_to_string(snap[i].pc, pcbuf, sizeof(pcbuf)),
					src, snap[i].count);
		else
			stats_log_write("    %-32s %lu\n",
					pc_to_string(snap[i].pc, pcbuf, sizeof(pcbuf)),
					snap[i].count);
	}
}

static void corrupt_ptr_attr_dump(void)
{
	struct corrupt_ptr_attr_entry snap[CORRUPT_PTR_ATTR_SLOTS];
	struct corrupt_ptr_pc_entry pc_snap[CORRUPT_PTR_PC_SLOTS];
	unsigned int i, n = 0;

	lock(&shm->stats.corrupt_ptr_attr_lock);
	memcpy(snap, shm->stats.corrupt_ptr_attr, sizeof(snap));
	unlock(&shm->stats.corrupt_ptr_attr_lock);

	lock(&shm->stats.corrupt_ptr_pc_lock);
	memcpy(pc_snap, shm->stats.corrupt_ptr_pc, sizeof(pc_snap));
	unlock(&shm->stats.corrupt_ptr_pc_lock);

	for (i = 0; i < CORRUPT_PTR_ATTR_SLOTS; i++)
		if (snap[i].count != 0)
			n++;

	if (n == 0)
		return;

	qsort(snap, CORRUPT_PTR_ATTR_SLOTS, sizeof(snap[0]),
	      corrupt_ptr_attr_cmp);
	qsort(pc_snap, CORRUPT_PTR_PC_SLOTS, sizeof(pc_snap[0]),
	      corrupt_ptr_pc_cmp);

	stats_log_write("post_handler_corrupt_ptr attribution (top %u handlers):\n", n);
	for (i = 0; i < CORRUPT_PTR_ATTR_SLOTS; i++) {
		const char *name;
		const char *width;

		if (snap[i].count == 0)
			break;
		if (snap[i].nr == CORRUPT_PTR_ATTR_NR_NONE) {
			name = "<deferred-free / non-syscall>";
			width = "(all)";
		} else {
			name = print_syscall_name(snap[i].nr, snap[i].do32bit);
			width = snap[i].do32bit ? "(32)" : "(64)";
		}
		stats_log_write("  %-32s %s %lu\n", name, width, snap[i].count);
		corrupt_ptr_pc_dump_for(pc_snap, snap[i].nr, snap[i].do32bit);
	}
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

static void deferred_free_reject_pc_dump(void)
{
	struct deferred_free_reject_pc_entry snap[CORRUPT_PTR_PC_SLOTS];
	unsigned int i, n = 0;

	lock(&shm->stats.deferred_free_reject_pc_lock);
	memcpy(snap, shm->stats.deferred_free_reject_pc, sizeof(snap));
	unlock(&shm->stats.deferred_free_reject_pc_lock);

	for (i = 0; i < CORRUPT_PTR_PC_SLOTS; i++)
		if (snap[i].count != 0)
			n++;

	if (n == 0)
		return;

	qsort(snap, CORRUPT_PTR_PC_SLOTS, sizeof(snap[0]),
	      deferred_free_reject_pc_cmp);

	stats_log_write("deferred_free_reject attribution (top %u callers):\n", n);
	for (i = 0; i < CORRUPT_PTR_PC_SLOTS; i++) {
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
		ts, (int)getpid());
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

void defense_counters_periodic_dump(void)
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

	healer_table_dump();

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

void top_syscalls_periodic_dump(void)
{
	static unsigned long prev_bandit[MAX_NR_SYSCALL];
	static unsigned long prev_explorer[MAX_NR_SYSCALL];
	static struct timespec last_dump;
	unsigned long cur_bandit[MAX_NR_SYSCALL];
	unsigned long cur_explorer[MAX_NR_SYSCALL];
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

	memcpy(prev_bandit,   cur_bandit,   sizeof(prev_bandit));
	memcpy(prev_explorer, cur_explorer, sizeof(prev_explorer));

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
void vma_count_periodic_dump(void)
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

	stats_log_write("[main] VMAs: parent=%lu children_total=%lu children_max=%lu children_min=%lu\n",
			(parent_vmas < 0) ? 0UL : (unsigned long)parent_vmas,
			total, max_vmas, min_vmas);

	last_dump = now;
}

void dump_stats(void)
{
	unsigned int i;

	if (stats_json) {
		dump_stats_json();
		return;
	}

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

	if (parent_stats.fault_injected) {
		stat_row("fault_injection", "armed_fail_nth",  parent_stats.fault_injected);
		stat_row("fault_injection", "returned_enomem", parent_stats.fault_consumed);
	}

	if (shm->stats.fd_stale_detected || shm->stats.fd_closed_tracked ||
	    shm->stats.fd_regenerated || shm->stats.fd_stale_by_generation ||
	    shm->stats.fd_duped || shm->stats.fd_events_processed ||
	    shm->stats.fd_hash_reinsert_dropped ||
	    shm->stats.local_fd_hash_insert_dropped ||
	    shm->stats.epoll_lazy_armed ||
	    shm->stats.epoll_blocking_poll_skipped ||
	    shm->stats.fd_random_exhausted) {
		stat_row("fd_lifecycle", "stale_detected",      shm->stats.fd_stale_detected);
		stat_row("fd_lifecycle", "stale_by_generation", shm->stats.fd_stale_by_generation);
		stat_row("fd_lifecycle", "closed_tracked",      shm->stats.fd_closed_tracked);
		stat_row("fd_lifecycle", "regenerated",         shm->stats.fd_regenerated);
		stat_row("fd_lifecycle", "duped",               shm->stats.fd_duped);
		stat_row("fd_lifecycle", "events_processed",    shm->stats.fd_events_processed);
		stat_row("fd_lifecycle", "events_dropped",      shm->stats.fd_events_dropped);
		stat_row("fd_lifecycle", "hash_reinsert_dropped", shm->stats.fd_hash_reinsert_dropped);
		stat_row("fd_lifecycle", "local_hash_insert_dropped",
			 shm->stats.local_fd_hash_insert_dropped);
		stat_row("fd_lifecycle", "epoll_lazy_armed",    shm->stats.epoll_lazy_armed);
		stat_row("fd_lifecycle", "epoll_blocking_poll_skipped",
			 shm->stats.epoll_blocking_poll_skipped);
		stat_row("fd_lifecycle", "random_exhausted",    shm->stats.fd_random_exhausted);
	}

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
	if (shm->stats.newlstat_oracle_anomalies)
		stat_row("oracle", "newlstat_anomalies",
			 shm->stats.newlstat_oracle_anomalies);
	if (shm->stats.newstat_oracle_anomalies)
		stat_row("oracle", "newstat_anomalies",
			 shm->stats.newstat_oracle_anomalies);
	if (shm->stats.newfstat_oracle_anomalies)
		stat_row("oracle", "newfstat_anomalies",
			 shm->stats.newfstat_oracle_anomalies);
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

	if (shm->stats.procfs_writes || shm->stats.sysfs_writes ||
	    shm->stats.debugfs_writes) {
		stat_row("vfs_writes", "procfs",  shm->stats.procfs_writes);
		stat_row("vfs_writes", "sysfs",   shm->stats.sysfs_writes);
		stat_row("vfs_writes", "debugfs", shm->stats.debugfs_writes);
	}

	if (shm->stats.memory_pressure_runs)
		stat_row("memory_pressure", "runs_madv_pageout", shm->stats.memory_pressure_runs);

	if (shm->stats.sched_cycler_runs) {
		stat_row("sched_cycler", "runs",  shm->stats.sched_cycler_runs);
		stat_row("sched_cycler", "eperm", shm->stats.sched_cycler_eperm);
	}

	if (shm->stats.userns_runs) {
		stat_row("userns_fuzzer", "runs",          shm->stats.userns_runs);
		stat_row("userns_fuzzer", "inner_crashed", shm->stats.userns_inner_crashed);
		stat_row("userns_fuzzer", "unsupported",   shm->stats.userns_unsupported);
	}

	if (shm->stats.barrier_racer_runs) {
		stat_row("barrier_racer", "runs",          shm->stats.barrier_racer_runs);
		stat_row("barrier_racer", "inner_crashed", shm->stats.barrier_racer_inner_crashed);
	}

	if (shm->stats.genetlink_families_discovered ||
	    shm->stats.genetlink_msgs_sent) {
		stat_row("genetlink_fuzzer", "families_discovered", shm->stats.genetlink_families_discovered);
		stat_row("genetlink_fuzzer", "msgs_sent",           shm->stats.genetlink_msgs_sent);
		stat_row("genetlink_fuzzer", "eperm",               shm->stats.genetlink_eperm);
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

	if (shm->stats.perf_chains_runs) {
		stat_row("perf_event_chains", "runs",           shm->stats.perf_chains_runs);
		stat_row("perf_event_chains", "groups_created", shm->stats.perf_chains_groups_created);
		stat_row("perf_event_chains", "ioctl_ops",      shm->stats.perf_chains_ioctl_ops);
	}

	if (shm->stats.tracefs_kprobe_writes || shm->stats.tracefs_uprobe_writes ||
	    shm->stats.tracefs_filter_writes || shm->stats.tracefs_event_enable_writes ||
	    shm->stats.tracefs_misc_writes) {
		stat_row("tracefs_fuzzer", "kprobe_writes",       shm->stats.tracefs_kprobe_writes);
		stat_row("tracefs_fuzzer", "uprobe_writes",       shm->stats.tracefs_uprobe_writes);
		stat_row("tracefs_fuzzer", "filter_writes",       shm->stats.tracefs_filter_writes);
		stat_row("tracefs_fuzzer", "event_enable_writes", shm->stats.tracefs_event_enable_writes);
		stat_row("tracefs_fuzzer", "misc_writes",         shm->stats.tracefs_misc_writes);
	}

	if (shm->stats.bpf_lifecycle_runs) {
		stat_row("bpf_lifecycle", "runs",             shm->stats.bpf_lifecycle_runs);
		stat_row("bpf_lifecycle", "progs_loaded",     shm->stats.bpf_lifecycle_progs_loaded);
		stat_row("bpf_lifecycle", "attached",         shm->stats.bpf_lifecycle_attached);
		stat_row("bpf_lifecycle", "triggered",        shm->stats.bpf_lifecycle_triggered);
		stat_row("bpf_lifecycle", "verifier_rejects", shm->stats.bpf_lifecycle_verifier_rejects);
		stat_row("bpf_lifecycle", "attach_failed",    shm->stats.bpf_lifecycle_attach_failed);
		stat_row("bpf_lifecycle", "eperm",            shm->stats.bpf_lifecycle_eperm);
	}

	if (shm->stats.bpf_maps_provided || shm->stats.bpf_progs_provided) {
		stat_row("bpf_fd_provider", "maps_provided",  shm->stats.bpf_maps_provided);
		stat_row("bpf_fd_provider", "progs_provided", shm->stats.bpf_progs_provided);
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

	if (shm->stats.fd_event_ring_corrupted)
		stat_row("corruption", "fd_event_ring_noncanon", shm->stats.fd_event_ring_corrupted);
	if (shm->stats.fd_event_ring_overwritten)
		stat_row("corruption", "fd_event_ring_canary",   shm->stats.fd_event_ring_overwritten);
	if (shm->stats.fd_event_payload_corrupt)
		stat_row("corruption", "fd_event_payload",       shm->stats.fd_event_payload_corrupt);
	if (shm->stats.deferred_free_corrupt_ptr)
		stat_row("corruption", "deferred_free_corrupt_ptr", shm->stats.deferred_free_corrupt_ptr);
	if (shm->stats.post_handler_corrupt_ptr)
		stat_row("corruption", "post_handler_corrupt_ptr", shm->stats.post_handler_corrupt_ptr);
	if (shm->stats.deferred_free_reject)
		stat_row("corruption", "deferred_free_reject",   shm->stats.deferred_free_reject);
	if (shm->stats.snapshot_non_heap_reject)
		stat_row("corruption", "snapshot_non_heap_reject", shm->stats.snapshot_non_heap_reject);
	if (shm->stats.rec_canary_stomped)
		stat_row("corruption", "rec_canary_stomped",     shm->stats.rec_canary_stomped);
	if (shm->stats.rzs_blanket_reject)
		stat_row("corruption", "rzs_blanket_reject",     shm->stats.rzs_blanket_reject);
	if (shm->stats.retfd_blanket_reject)
		stat_row("corruption", "retfd_blanket_reject",   shm->stats.retfd_blanket_reject);
	if (shm->stats.sibling_mprotect_failed)
		stat_row("corruption", "sibling_mprotect_failed", shm->stats.sibling_mprotect_failed);
	if (shm->stats.divergence_sentinel_anomalies)
		stat_row("corruption", "divergence_sentinel_anomalies", shm->stats.divergence_sentinel_anomalies);
	if (shm->stats.destroy_object_idx_corrupt)
		stat_row("corruption", "destroy_object_idx",     shm->stats.destroy_object_idx_corrupt);
	if (shm->stats.global_obj_uaf_caught)
		stat_row("corruption", "global_obj_uaf_caught",  shm->stats.global_obj_uaf_caught);
	if (shm->stats.maps_uaf_caught)
		stat_row("corruption", "maps_uaf_caught",        shm->stats.maps_uaf_caught);
	if (shm->stats.pagecache_canary_corrupt_caught)
		stat_row("oracle", "pagecache_canary_corrupt_caught",
			 shm->stats.pagecache_canary_corrupt_caught);

	{
		unsigned int op;
		char metric[40];

		for (op = 0; op < NR_CHILD_OP_TYPES; op++) {
			if (shm->stats.taint_transitions[op] == 0)
				continue;
			snprintf(metric, sizeof(metric), "op_type_%u", op);
			stat_row("taint_transitions", metric,
				 shm->stats.taint_transitions[op]);
		}

		for (op = 0; op < NR_CHILD_OP_TYPES; op++) {
			if (shm->stats.pool_race_aborted[op] == 0)
				continue;
			snprintf(metric, sizeof(metric), "op_type_%u", op);
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
				snprintf(metric, sizeof(metric),
					 "op_type_%u", ranked[ri].op);
				stat_row("childop_edges_discovered",
					 metric, ranked[ri].count);
			}
		}
	}

	if (parent_stats.shared_buffer_redirected)
		stat_row("shared_buffer", "args_redirected",     parent_stats.shared_buffer_redirected);
	if (parent_stats.libc_heap_redirected)
		stat_row("shared_buffer", "libc_heap_redirected", parent_stats.libc_heap_redirected);
	if (parent_stats.libc_heap_embedded_redirected)
		stat_row("shared_buffer", "libc_heap_embedded_redirected",
			 parent_stats.libc_heap_embedded_redirected);
	if (parent_stats.range_overlaps_shared_rejects) {
		stat_row("shared_buffer", "range_overlaps_shared_rejects",
			 parent_stats.range_overlaps_shared_rejects);
		if (verbosity > 1)
			dump_range_overlaps_shared_top_offenders();
	}
	if (parent_stats.get_writable_address_scribbled_slots_caught)
		stat_row("shared_buffer", "get_writable_address_scribbled_slots_caught",
			 parent_stats.get_writable_address_scribbled_slots_caught);
	if (parent_stats.children_recycled_on_storm)
		stat_row("corruption", "children_recycled_on_storm",
			 parent_stats.children_recycled_on_storm);

	if (verbosity > 1)
		dump_syscall_category_histogram();

	if (shm->stats.bandit_cmp_reward_added)
		stat_row("strategy", "bandit_cmp_reward_added",
			 shm->stats.bandit_cmp_reward_added);
	if (shm->stats.frontier_strategy_picks)
		stat_row("strategy", "frontier_strategy_picks",
			 shm->stats.frontier_strategy_picks);
	if (shm->stats.healer_picker_cold_start)
		stat_row("strategy", "healer_picker_cold_start",
			 shm->stats.healer_picker_cold_start);
	if (shm->stats.healer_picker_pair_path)
		stat_row("strategy", "healer_picker_pair_path",
			 shm->stats.healer_picker_pair_path);
	if (shm->stats.healer_picker_triple_path)
		stat_row("strategy", "healer_picker_triple_path",
			 shm->stats.healer_picker_triple_path);
	if (shm->stats.healer_picker_zero_weight_fallback)
		stat_row("strategy", "healer_picker_zero_weight_fallback",
			 shm->stats.healer_picker_zero_weight_fallback);
	if (shm->stats.strategy_explorer_picks)
		stat_row("strategy", "strategy_explorer_picks",
			 shm->stats.strategy_explorer_picks);

	dump_strategy_stats();

	{
		size_t used = __atomic_load_n(&shm->shared_obj_heap_used,
					      __ATOMIC_RELAXED);
		size_t cap = obj_heap_get_capacity();
		unsigned long allocs = __atomic_load_n(&shm->stats.obj_heap_allocs,
						       __ATOMIC_RELAXED);
		unsigned long frees = __atomic_load_n(&shm->stats.obj_heap_frees,
						      __ATOMIC_RELAXED);
		unsigned long pct10 = cap ? (used * 1000UL / cap) : 0UL;

		output(1, "obj-heap: %lu.%lu%% used (%zu / %zu bytes), %lu allocs, %lu frees\n",
			pct10 / 10, pct10 % 10, used, cap, allocs, frees);
	}

	dump_obj_heap_stats();

	if (shm->stats.refcount_audit_runs) {
		stat_row("refcount_audit", "runs",           shm->stats.refcount_audit_runs);
		stat_row("refcount_audit", "fd_anomalies",   shm->stats.refcount_audit_fd_anomalies);
		stat_row("refcount_audit", "mmap_anomalies", shm->stats.refcount_audit_mmap_anomalies);
		stat_row("refcount_audit", "sock_anomalies", shm->stats.refcount_audit_sock_anomalies);
	}

	if (shm->stats.fs_lifecycle_tmpfs || shm->stats.fs_lifecycle_ramfs ||
	    shm->stats.fs_lifecycle_overlay || shm->stats.fs_lifecycle_unsupported) {
		stat_row("fs_lifecycle", "tmpfs",       shm->stats.fs_lifecycle_tmpfs);
		stat_row("fs_lifecycle", "ramfs",       shm->stats.fs_lifecycle_ramfs);
		stat_row("fs_lifecycle", "rdonly",      shm->stats.fs_lifecycle_rdonly);
		stat_row("fs_lifecycle", "overlay",     shm->stats.fs_lifecycle_overlay);
		stat_row("fs_lifecycle", "unsupported", shm->stats.fs_lifecycle_unsupported);
	}

	if (shm->stats.signal_storm_runs) {
		stat_row("signal_storm", "runs",       shm->stats.signal_storm_runs);
		stat_row("signal_storm", "kill",       shm->stats.signal_storm_kill);
		stat_row("signal_storm", "sigqueue",   shm->stats.signal_storm_sigqueue);
		stat_row("signal_storm", "no_targets", shm->stats.signal_storm_no_targets);
	}

	if (shm->stats.futex_storm_runs)
		output(0, "\nfutex storm: runs:%lu inner_crashed:%lu iters:%lu\n",
			shm->stats.futex_storm_runs,
			shm->stats.futex_storm_inner_crashed,
			shm->stats.futex_storm_iters);

	if (shm->stats.pipe_thrash_runs) {
		stat_row("pipe_thrash", "runs",         shm->stats.pipe_thrash_runs);
		stat_row("pipe_thrash", "pipes",        shm->stats.pipe_thrash_pipes);
		stat_row("pipe_thrash", "socketpairs",  shm->stats.pipe_thrash_socketpairs);
		stat_row("pipe_thrash", "alloc_failed", shm->stats.pipe_thrash_alloc_failed);
	}

	if (shm->stats.fork_storm_runs) {
		stat_row("fork_storm", "runs",          shm->stats.fork_storm_runs);
		stat_row("fork_storm", "forks",         shm->stats.fork_storm_forks);
		stat_row("fork_storm", "failed",        shm->stats.fork_storm_failed);
		stat_row("fork_storm", "nested",        shm->stats.fork_storm_nested);
		stat_row("fork_storm", "reaped_signal", shm->stats.fork_storm_reaped_signal);
	}

	if (shm->stats.pidfd_storm_runs) {
		stat_row("pidfd_storm", "runs",    shm->stats.pidfd_storm_runs);
		stat_row("pidfd_storm", "signals", shm->stats.pidfd_storm_signals);
		stat_row("pidfd_storm", "getfds",  shm->stats.pidfd_storm_getfds);
		stat_row("pidfd_storm", "failed",  shm->stats.pidfd_storm_failed);
	}

	if (shm->stats.madvise_cycler_runs) {
		stat_row("madvise_cycler", "runs",   shm->stats.madvise_cycler_runs);
		stat_row("madvise_cycler", "calls",  shm->stats.madvise_cycler_calls);
		stat_row("madvise_cycler", "failed", shm->stats.madvise_cycler_failed);
	}

	if (shm->stats.keyring_spam_runs) {
		stat_row("keyring_spam", "runs",   shm->stats.keyring_spam_runs);
		stat_row("keyring_spam", "calls",  shm->stats.keyring_spam_calls);
		stat_row("keyring_spam", "failed", shm->stats.keyring_spam_failed);
	}

	if (shm->stats.vdso_race_runs) {
		stat_row("vdso_mremap_race", "runs",         shm->stats.vdso_race_runs);
		stat_row("vdso_mremap_race", "mutations",    shm->stats.vdso_race_mutations);
		stat_row("vdso_mremap_race", "helper_segvs", shm->stats.vdso_race_helper_segvs);
	}

	if (shm->stats.flock_thrash_runs) {
		stat_row("flock_thrash", "runs",   shm->stats.flock_thrash_runs);
		stat_row("flock_thrash", "locks",  shm->stats.flock_thrash_locks);
		stat_row("flock_thrash", "failed", shm->stats.flock_thrash_failed);
	}

	if (shm->stats.xattr_thrash_runs) {
		stat_row("xattr_thrash", "runs",   shm->stats.xattr_thrash_runs);
		stat_row("xattr_thrash", "set",    shm->stats.xattr_thrash_set);
		stat_row("xattr_thrash", "get",    shm->stats.xattr_thrash_get);
		stat_row("xattr_thrash", "remove", shm->stats.xattr_thrash_remove);
		stat_row("xattr_thrash", "list",   shm->stats.xattr_thrash_list);
		stat_row("xattr_thrash", "failed", shm->stats.xattr_thrash_failed);
	}

	if (shm->stats.epoll_volatility_runs) {
		stat_row("epoll_volatility", "runs",      shm->stats.epoll_volatility_runs);
		stat_row("epoll_volatility", "ctl_calls", shm->stats.epoll_volatility_ctl_calls);
		stat_row("epoll_volatility", "failed",    shm->stats.epoll_volatility_failed);
	}

	if (shm->stats.cgroup_churn_runs) {
		stat_row("cgroup_churn", "runs",   shm->stats.cgroup_churn_runs);
		stat_row("cgroup_churn", "mkdirs", shm->stats.cgroup_mkdirs);
		stat_row("cgroup_churn", "rmdirs", shm->stats.cgroup_rmdirs);
		stat_row("cgroup_churn", "failed", shm->stats.cgroup_failed);
		stat_row("cgroup_churn", "psi_race_runs",
			 shm->stats.cgroup_psi_race_runs);
		stat_row("cgroup_churn", "psi_race_writes",
			 shm->stats.cgroup_psi_race_writes);
		stat_row("cgroup_churn", "psi_race_failed",
			 shm->stats.cgroup_psi_race_failed);
	}

	if (shm->stats.mount_churn_runs) {
		stat_row("mount_churn", "runs",    shm->stats.mount_churn_runs);
		stat_row("mount_churn", "mounts",  shm->stats.mount_churn_mounts);
		stat_row("mount_churn", "umounts", shm->stats.mount_churn_umounts);
		stat_row("mount_churn", "failed",  shm->stats.mount_churn_failed);
	}

	if (shm->stats.uffd_runs) {
		stat_row("uffd_churn", "runs",        shm->stats.uffd_runs);
		stat_row("uffd_churn", "registers",   shm->stats.uffd_registers);
		stat_row("uffd_churn", "unregisters", shm->stats.uffd_unregisters);
		stat_row("uffd_churn", "failed",      shm->stats.uffd_failed);
	}

	if (shm->stats.iouring_runs) {
		stat_row("iouring_flood", "runs",     shm->stats.iouring_runs);
		stat_row("iouring_flood", "submits",  shm->stats.iouring_submits);
		stat_row("iouring_flood", "reaped",   shm->stats.iouring_reaped);
		stat_row("iouring_flood", "failed",   shm->stats.iouring_failed);
	}

	if (shm->stats.close_racer_runs) {
		stat_row("close_racer", "runs",              shm->stats.close_racer_runs);
		stat_row("close_racer", "pairs",             shm->stats.close_racer_pairs);
		stat_row("close_racer", "failed",            shm->stats.close_racer_failed);
		stat_row("close_racer", "thread_spawn_fail", shm->stats.close_racer_thread_spawn_fail);
	}

	if (shm->stats.socket_family_chain_runs) {
		stat_row("socket_family_chain", "runs",                shm->stats.socket_family_chain_runs);
		stat_row("socket_family_chain", "completed",           shm->stats.socket_family_chain_completed);
		stat_row("socket_family_chain", "failed",              shm->stats.socket_family_chain_failed);
		stat_row("socket_family_chain", "authencesn_attempts", shm->stats.socket_family_chain_authencesn_attempts);
		stat_row("socket_family_chain", "splice_attempts",     shm->stats.socket_family_chain_splice_attempts);
	}

	if (shm->stats.socket_family_grammar_runs) {
		stat_row("socket_family_grammar", "runs",      shm->stats.socket_family_grammar_runs);
		stat_row("socket_family_grammar", "completed", shm->stats.socket_family_grammar_completed);
	}

	if (shm->stats.tls_rotate_runs) {
		stat_row("tls_rotate", "runs",            shm->stats.tls_rotate_runs);
		stat_row("tls_rotate", "setup_failed",    shm->stats.tls_rotate_setup_failed);
		stat_row("tls_rotate", "ulp_failed",      shm->stats.tls_rotate_ulp_failed);
		stat_row("tls_rotate", "installs",        shm->stats.tls_rotate_installs);
		stat_row("tls_rotate", "rekeys_ok",       shm->stats.tls_rotate_rekeys_ok);
		stat_row("tls_rotate", "rekeys_rejected", shm->stats.tls_rotate_rekeys_rejected);
	}

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

	if (shm->stats.tcp_ao_rotate_runs) {
		stat_row("tcp_ao_rotate", "runs",            shm->stats.tcp_ao_rotate_runs);
		stat_row("tcp_ao_rotate", "setup_failed",    shm->stats.tcp_ao_rotate_setup_failed);
		stat_row("tcp_ao_rotate", "addkey_rejected", shm->stats.tcp_ao_rotate_addkey_rejected);
		stat_row("tcp_ao_rotate", "keys_added",      shm->stats.tcp_ao_rotate_keys_added);
		stat_row("tcp_ao_rotate", "connect_failed",  shm->stats.tcp_ao_rotate_connect_failed);
		stat_row("tcp_ao_rotate", "connected",       shm->stats.tcp_ao_rotate_connected);
		stat_row("tcp_ao_rotate", "packets_sent",    shm->stats.tcp_ao_rotate_packets_sent);
		stat_row("tcp_ao_rotate", "key_rotations",   shm->stats.tcp_ao_rotate_key_rotations);
		stat_row("tcp_ao_rotate", "info_rejected",   shm->stats.tcp_ao_rotate_info_rejected);
		stat_row("tcp_ao_rotate", "key_dels",        shm->stats.tcp_ao_rotate_key_dels);
		stat_row("tcp_ao_rotate", "delkey_rejected", shm->stats.tcp_ao_rotate_delkey_rejected);
		stat_row("tcp_ao_rotate", "cycles",          shm->stats.tcp_ao_rotate_cycles);
	}

	if (shm->stats.tcp_md5_listener_race_runs) {
		stat_row("tcp_md5_listener_race", "runs",           shm->stats.tcp_md5_listener_race_runs);
		stat_row("tcp_md5_listener_race", "setup_failed",   shm->stats.tcp_md5_listener_race_setup_failed);
		stat_row("tcp_md5_listener_race", "md5_set_ok",     shm->stats.tcp_md5_listener_race_md5_set_ok);
		stat_row("tcp_md5_listener_race", "md5_set_failed", shm->stats.tcp_md5_listener_race_md5_set_failed);
		stat_row("tcp_md5_listener_race", "connect_ok",     shm->stats.tcp_md5_listener_race_connect_ok);
		stat_row("tcp_md5_listener_race", "rst_sent_ok",    shm->stats.tcp_md5_listener_race_rst_sent_ok);
		stat_row("tcp_md5_listener_race", "completed_ok",   shm->stats.tcp_md5_listener_race_completed_ok);
	}

	if (shm->stats.ipv6_pmtu_race_runs) {
		stat_row("ipv6_pmtu_race", "runs",          shm->stats.ipv6_pmtu_race_runs);
		stat_row("ipv6_pmtu_race", "setup_failed",  shm->stats.ipv6_pmtu_race_setup_failed);
		stat_row("ipv6_pmtu_race", "ptb_sent_ok",   shm->stats.ipv6_pmtu_race_ptb_sent_ok);
		stat_row("ipv6_pmtu_race", "dellink_ok",    shm->stats.ipv6_pmtu_race_dellink_ok);
		stat_row("ipv6_pmtu_race", "completed_ok",  shm->stats.ipv6_pmtu_race_completed_ok);
	}

	if (shm->stats.vrf_fib_churn_runs) {
		stat_row("vrf_fib_churn", "runs",         shm->stats.vrf_fib_churn_runs);
		stat_row("vrf_fib_churn", "setup_failed", shm->stats.vrf_fib_churn_setup_failed);
		stat_row("vrf_fib_churn", "link_ok",      shm->stats.vrf_fib_churn_link_ok);
		stat_row("vrf_fib_churn", "addr_ok",      shm->stats.vrf_fib_churn_addr_ok);
		stat_row("vrf_fib_churn", "up_ok",        shm->stats.vrf_fib_churn_up_ok);
		stat_row("vrf_fib_churn", "rule_added",   shm->stats.vrf_fib_churn_rule_added);
		stat_row("vrf_fib_churn", "bound",        shm->stats.vrf_fib_churn_bound);
		stat_row("vrf_fib_churn", "sendto_ok",    shm->stats.vrf_fib_churn_sendto_ok);
		stat_row("vrf_fib_churn", "rule2_added",  shm->stats.vrf_fib_churn_rule2_added);
		stat_row("vrf_fib_churn", "rule_removed", shm->stats.vrf_fib_churn_rule_removed);
		stat_row("vrf_fib_churn", "link_removed", shm->stats.vrf_fib_churn_link_removed);
	}

	if (shm->stats.mpls_route_churn_runs) {
		stat_row("mpls_route_churn", "runs",                shm->stats.mpls_route_churn_runs);
		stat_row("mpls_route_churn", "label_install_ok",    shm->stats.mpls_route_churn_label_install_ok);
		stat_row("mpls_route_churn", "iptunnel_install_ok", shm->stats.mpls_route_churn_iptunnel_install_ok);
		stat_row("mpls_route_churn", "delete_ok",           shm->stats.mpls_route_churn_delete_ok);
		stat_row("mpls_route_churn", "ns_unsupported",      shm->stats.mpls_route_churn_ns_unsupported);
	}

	if (shm->stats.netlink_monitor_race_runs) {
		stat_row("netlink_monitor_race", "runs",         shm->stats.netlink_monitor_race_runs);
		stat_row("netlink_monitor_race", "setup_failed", shm->stats.netlink_monitor_race_setup_failed);
		stat_row("netlink_monitor_race", "mon_open",     shm->stats.netlink_monitor_race_mon_open);
		stat_row("netlink_monitor_race", "mut_open",     shm->stats.netlink_monitor_race_mut_open);
		stat_row("netlink_monitor_race", "mut_op_ok",    shm->stats.netlink_monitor_race_mut_op_ok);
		stat_row("netlink_monitor_race", "recv_drained", shm->stats.netlink_monitor_race_recv_drained);
		stat_row("netlink_monitor_race", "group_drop",   shm->stats.netlink_monitor_race_group_drop);
		stat_row("netlink_monitor_race", "group_add",    shm->stats.netlink_monitor_race_group_add);
	}

	if (shm->stats.tipc_link_churn_runs) {
		stat_row("tipc_link_churn", "runs",              shm->stats.tipc_link_churn_runs);
		stat_row("tipc_link_churn", "setup_failed",      shm->stats.tipc_link_churn_setup_failed);
		stat_row("tipc_link_churn", "bearer_enable_ok",  shm->stats.tipc_link_churn_bearer_enable_ok);
		stat_row("tipc_link_churn", "sock_rdm_ok",       shm->stats.tipc_link_churn_sock_rdm_ok);
		stat_row("tipc_link_churn", "topsrv_connect_ok", shm->stats.tipc_link_churn_topsrv_connect_ok);
		stat_row("tipc_link_churn", "sub_ports_sent",    shm->stats.tipc_link_churn_sub_ports_sent);
		stat_row("tipc_link_churn", "publish_ok",        shm->stats.tipc_link_churn_publish_ok);
		stat_row("tipc_link_churn", "bearer_disable_ok", shm->stats.tipc_link_churn_bearer_disable_ok);
	}

	if (shm->stats.tls_ulp_churn_runs) {
		stat_row("tls_ulp_churn", "runs",            shm->stats.tls_ulp_churn_runs);
		stat_row("tls_ulp_churn", "setup_failed",    shm->stats.tls_ulp_churn_setup_failed);
		stat_row("tls_ulp_churn", "ulp_install_ok",  shm->stats.tls_ulp_churn_ulp_install_ok);
		stat_row("tls_ulp_churn", "tx_install_ok",   shm->stats.tls_ulp_churn_tx_install_ok);
		stat_row("tls_ulp_churn", "send_ok",         shm->stats.tls_ulp_churn_send_ok);
		stat_row("tls_ulp_churn", "splice_ok",       shm->stats.tls_ulp_churn_splice_ok);
		stat_row("tls_ulp_churn", "rekey_ok",        shm->stats.tls_ulp_churn_rekey_ok);
		stat_row("tls_ulp_churn", "recv_ok",         shm->stats.tls_ulp_churn_recv_ok);
	}

	if (shm->stats.vxlan_encap_churn_runs) {
		stat_row("vxlan_encap_churn", "runs",           shm->stats.vxlan_encap_churn_runs);
		stat_row("vxlan_encap_churn", "setup_failed",   shm->stats.vxlan_encap_churn_setup_failed);
		stat_row("vxlan_encap_churn", "link_create_ok", shm->stats.vxlan_encap_churn_link_create_ok);
		stat_row("vxlan_encap_churn", "fdb_add_ok",     shm->stats.vxlan_encap_churn_fdb_add_ok);
		stat_row("vxlan_encap_churn", "link_up_ok",     shm->stats.vxlan_encap_churn_link_up_ok);
		stat_row("vxlan_encap_churn", "packet_sent_ok", shm->stats.vxlan_encap_churn_packet_sent_ok);
		stat_row("vxlan_encap_churn", "link_del_ok",    shm->stats.vxlan_encap_churn_link_del_ok);
	}

	if (shm->stats.ovs_tunnel_vport_churn_runs) {
		stat_row("ovs_tunnel_vport_churn", "runs",                   shm->stats.ovs_tunnel_vport_churn_runs);
		stat_row("ovs_tunnel_vport_churn", "setup_failed",           shm->stats.ovs_tunnel_vport_churn_setup_failed);
		stat_row("ovs_tunnel_vport_churn", "create_ok",              shm->stats.ovs_tunnel_vport_churn_create_ok);
		stat_row("ovs_tunnel_vport_churn", "delete_ok",              shm->stats.ovs_tunnel_vport_churn_delete_ok);
		stat_row("ovs_tunnel_vport_churn", "race_dellink_attempted", shm->stats.ovs_tunnel_vport_churn_race_dellink_attempted);
	}

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

	if (shm->stats.bridge_ct_runs) {
		stat_row("bridge_conntrack_churn", "runs",      shm->stats.bridge_ct_runs);
		stat_row("bridge_conntrack_churn", "flushes",   shm->stats.bridge_ct_flushes);
		stat_row("bridge_conntrack_churn", "pkts_sent", shm->stats.bridge_ct_pkts_sent);
	}

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

	if (shm->stats.ublk_lifecycle_iters) {
		stat_row("ublk_lifecycle", "iters",         shm->stats.ublk_lifecycle_iters);
		stat_row("ublk_lifecycle", "eperm",         shm->stats.ublk_lifecycle_eperm);
		stat_row("ublk_lifecycle", "add_ok",        shm->stats.ublk_lifecycle_add_ok);
		stat_row("ublk_lifecycle", "fetch_ok",      shm->stats.ublk_lifecycle_fetch_ok);
		stat_row("ublk_lifecycle", "del_ok",        shm->stats.ublk_lifecycle_del_ok);
		stat_row("ublk_lifecycle", "race_observed", shm->stats.ublk_lifecycle_race_observed);
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

	if (shm->stats.bpf_cgroup_attach_runs) {
		stat_row("bpf_cgroup_attach", "runs",             shm->stats.bpf_cgroup_attach_runs);
		stat_row("bpf_cgroup_attach", "setup_failed",     shm->stats.bpf_cgroup_attach_setup_failed);
		stat_row("bpf_cgroup_attach", "prog_loaded",      shm->stats.bpf_cgroup_attach_prog_loaded);
		stat_row("bpf_cgroup_attach", "attached",         shm->stats.bpf_cgroup_attach_attached);
		stat_row("bpf_cgroup_attach", "attach_rejected",  shm->stats.bpf_cgroup_attach_attach_rejected);
		stat_row("bpf_cgroup_attach", "packets_sent",     shm->stats.bpf_cgroup_attach_packets_sent);
		stat_row("bpf_cgroup_attach", "detached",         shm->stats.bpf_cgroup_attach_detached);
		stat_row("bpf_cgroup_attach", "post_detach_sent", shm->stats.bpf_cgroup_attach_post_detach_sent);
	}

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

	if (shm->stats.handshake_req_abort_runs) {
		stat_row("handshake_req_abort", "runs",         shm->stats.handshake_req_abort_runs);
		stat_row("handshake_req_abort", "setup_failed", shm->stats.handshake_req_abort_setup_failed);
		stat_row("handshake_req_abort", "accept_ok",    shm->stats.handshake_req_abort_accept_ok);
		stat_row("handshake_req_abort", "done_ok",      shm->stats.handshake_req_abort_done_ok);
		stat_row("handshake_req_abort", "abort_ok",     shm->stats.handshake_req_abort_abort_ok);
		stat_row("handshake_req_abort", "orphan_close", shm->stats.handshake_req_abort_orphan_close);
	}

	if (shm->stats.nf_conntrack_helper_churn_runs) {
		stat_row("nf_conntrack_helper_churn", "runs",         shm->stats.nf_conntrack_helper_churn_runs);
		stat_row("nf_conntrack_helper_churn", "setup_failed", shm->stats.nf_conntrack_helper_churn_setup_failed);
		stat_row("nf_conntrack_helper_churn", "no_helper",    shm->stats.nf_conntrack_helper_churn_no_helper);
		stat_row("nf_conntrack_helper_churn", "attach_ok",    shm->stats.nf_conntrack_helper_churn_attach_ok);
		stat_row("nf_conntrack_helper_churn", "attach_fail",  shm->stats.nf_conntrack_helper_churn_attach_fail);
		stat_row("nf_conntrack_helper_churn", "exp_ok",       shm->stats.nf_conntrack_helper_churn_exp_ok);
		stat_row("nf_conntrack_helper_churn", "packet_sent",  shm->stats.nf_conntrack_helper_churn_packet_sent);
		stat_row("nf_conntrack_helper_churn", "delete_ok",    shm->stats.nf_conntrack_helper_churn_delete_ok);
		stat_row("nf_conntrack_helper_churn", "zone_swap",    shm->stats.nf_conntrack_helper_churn_zone_swap);
		stat_row("nf_conntrack_helper_churn", "detach_ok",    shm->stats.nf_conntrack_helper_churn_detach_ok);
	}

	if (shm->stats.af_unix_scm_rights_gc_runs) {
		stat_row("af_unix_scm_rights_gc", "runs",                shm->stats.af_unix_scm_rights_gc_runs);
		stat_row("af_unix_scm_rights_gc", "setup_failed",        shm->stats.af_unix_scm_rights_gc_setup_failed);
		stat_row("af_unix_scm_rights_gc", "cycle_built_ok",      shm->stats.af_unix_scm_rights_gc_cycle_built_ok);
		stat_row("af_unix_scm_rights_gc", "close_ok",            shm->stats.af_unix_scm_rights_gc_close_ok);
		stat_row("af_unix_scm_rights_gc", "trigger_ok",          shm->stats.af_unix_scm_rights_gc_trigger_ok);
		stat_row("af_unix_scm_rights_gc", "recv_ok",             shm->stats.af_unix_scm_rights_gc_recv_ok);
		stat_row("af_unix_scm_rights_gc", "peek_ok",             shm->stats.af_unix_scm_rights_gc_peek_ok);
		stat_row("af_unix_scm_rights_gc", "iouring_variant_ok",  shm->stats.af_unix_scm_rights_gc_iouring_variant_ok);
	}

	if (shm->stats.netns_teardown_runs) {
		stat_row("netns_teardown", "runs",            shm->stats.netns_teardown_runs);
		stat_row("netns_teardown", "setup_failed",    shm->stats.netns_teardown_setup_failed);
		stat_row("netns_teardown", "unshare_ok",      shm->stats.netns_teardown_unshare_ok);
		stat_row("netns_teardown", "socket_pair_ok",  shm->stats.netns_teardown_socket_pair_ok);
		stat_row("netns_teardown", "fork_ok",         shm->stats.netns_teardown_fork_ok);
		stat_row("netns_teardown", "setns_ok",        shm->stats.netns_teardown_setns_ok);
		stat_row("netns_teardown", "kill_ok",         shm->stats.netns_teardown_kill_ok);
		stat_row("netns_teardown", "completed_ok",    shm->stats.netns_teardown_completed_ok);
	}

	if (shm->stats.tcp_ulp_swap_churn_runs) {
		stat_row("tcp_ulp_swap_churn", "runs",              shm->stats.tcp_ulp_swap_churn_runs);
		stat_row("tcp_ulp_swap_churn", "setup_failed",      shm->stats.tcp_ulp_swap_churn_setup_failed);
		stat_row("tcp_ulp_swap_churn", "install_tls_ok",    shm->stats.tcp_ulp_swap_churn_install_tls_ok);
		stat_row("tcp_ulp_swap_churn", "tx_install_ok",     shm->stats.tcp_ulp_swap_churn_tx_install_ok);
		stat_row("tcp_ulp_swap_churn", "send_ok",           shm->stats.tcp_ulp_swap_churn_send_ok);
		stat_row("tcp_ulp_swap_churn", "swap_rejected_ok",  shm->stats.tcp_ulp_swap_churn_swap_rejected_ok);
		stat_row("tcp_ulp_swap_churn", "ifname_probe_ok",   shm->stats.tcp_ulp_swap_churn_ifname_probe_ok);
		stat_row("tcp_ulp_swap_churn", "uninstall_ok",      shm->stats.tcp_ulp_swap_churn_uninstall_ok);
		stat_row("tcp_ulp_swap_churn", "reinstall_ok",      shm->stats.tcp_ulp_swap_churn_reinstall_ok);
		stat_row("tcp_ulp_swap_churn", "install_failed",    shm->stats.tcp_ulp_swap_churn_install_failed);
	}

	stat_category_emit_text(&msg_zerocopy_churn_category);

	if (shm->stats.iouring_send_zc_churn_runs) {
		stat_row("iouring_send_zc_churn", "runs",               shm->stats.iouring_send_zc_churn_runs);
		stat_row("iouring_send_zc_churn", "setup_failed",       shm->stats.iouring_send_zc_churn_setup_failed);
		stat_row("iouring_send_zc_churn", "register_bufs_ok",   shm->stats.iouring_send_zc_churn_register_bufs_ok);
		stat_row("iouring_send_zc_churn", "send_zc_ok",         shm->stats.iouring_send_zc_churn_send_zc_ok);
		stat_row("iouring_send_zc_churn", "sendmsg_zc_ok",      shm->stats.iouring_send_zc_churn_sendmsg_zc_ok);
		stat_row("iouring_send_zc_churn", "unregister_race_ok", shm->stats.iouring_send_zc_churn_unregister_race_ok);
		stat_row("iouring_send_zc_churn", "update_race_ok",     shm->stats.iouring_send_zc_churn_update_race_ok);
		stat_row("iouring_send_zc_churn", "cqe_drained",        shm->stats.iouring_send_zc_churn_cqe_drained);
	}

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

	if (shm->stats.bridge_vlan_churn_runs) {
		stat_row("bridge_vlan_churn", "runs",             shm->stats.bridge_vlan_churn_runs);
		stat_row("bridge_vlan_churn", "setup_failed",     shm->stats.bridge_vlan_churn_setup_failed);
		stat_row("bridge_vlan_churn", "bridge_create_ok", shm->stats.bridge_vlan_churn_bridge_create_ok);
		stat_row("bridge_vlan_churn", "veth_create_ok",   shm->stats.bridge_vlan_churn_veth_create_ok);
		stat_row("bridge_vlan_churn", "vlan_add_ok",      shm->stats.bridge_vlan_churn_vlan_add_ok);
		stat_row("bridge_vlan_churn", "vlan_del_ok",      shm->stats.bridge_vlan_churn_vlan_del_ok);
		stat_row("bridge_vlan_churn", "tunnel_add_ok",    shm->stats.bridge_vlan_churn_tunnel_add_ok);
		stat_row("bridge_vlan_churn", "mst_set_ok",       shm->stats.bridge_vlan_churn_mst_set_ok);
		stat_row("bridge_vlan_churn", "raw_send_ok",      shm->stats.bridge_vlan_churn_raw_send_ok);
	}

	if (shm->stats.igmp_mld_source_churn_runs) {
		stat_row("igmp_mld_source_churn", "runs",         shm->stats.igmp_mld_source_churn_runs);
		stat_row("igmp_mld_source_churn", "setup_failed", shm->stats.igmp_mld_source_churn_setup_failed);
		stat_row("igmp_mld_source_churn", "join_ok",      shm->stats.igmp_mld_source_churn_join_ok);
		stat_row("igmp_mld_source_churn", "leave_ok",     shm->stats.igmp_mld_source_churn_leave_ok);
		stat_row("igmp_mld_source_churn", "block_ok",     shm->stats.igmp_mld_source_churn_block_ok);
		stat_row("igmp_mld_source_churn", "msfilter_ok",  shm->stats.igmp_mld_source_churn_msfilter_ok);
		stat_row("igmp_mld_source_churn", "drop_ok",      shm->stats.igmp_mld_source_churn_drop_ok);
		stat_row("igmp_mld_source_churn", "send_ok",      shm->stats.igmp_mld_source_churn_send_ok);
	}

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

	if (shm->stats.veth_asym_iters) {
		stat_row("veth_asymmetric_xdp", "iters",         shm->stats.veth_asym_iters);
		stat_row("veth_asymmetric_xdp", "eperm",         shm->stats.veth_asym_eperm);
		stat_row("veth_asymmetric_xdp", "unsupported",   shm->stats.veth_asym_unsupported);
		stat_row("veth_asymmetric_xdp", "pair_ok",       shm->stats.veth_asym_pair_ok);
		stat_row("veth_asymmetric_xdp", "xdp_attach_ok", shm->stats.veth_asym_xdp_attach_ok);
		stat_row("veth_asymmetric_xdp", "send_ok",       shm->stats.veth_asym_send_ok);
	}

	if (shm->stats.inm_iters) {
		stat_row("ip6erspan_netns_migrate", "iters",            shm->stats.inm_iters);
		stat_row("ip6erspan_netns_migrate", "eperm",            shm->stats.inm_eperm);
		stat_row("ip6erspan_netns_migrate", "unsupported",      shm->stats.inm_unsupported);
		stat_row("ip6erspan_netns_migrate", "link_create_ok",   shm->stats.inm_link_create_ok);
		stat_row("ip6erspan_netns_migrate", "netns_migrate_ok", shm->stats.inm_netns_migrate_ok);
		stat_row("ip6erspan_netns_migrate", "changelink_ok",    shm->stats.inm_changelink_ok);
	}

	if (shm->stats.ip6gre_lapb_runs) {
		stat_row("ip6gre_bond_lapb_stack", "runs",          shm->stats.ip6gre_lapb_runs);
		stat_row("ip6gre_bond_lapb_stack", "setup_failed",  shm->stats.ip6gre_lapb_setup_failed);
		stat_row("ip6gre_bond_lapb_stack", "flag_toggles",  shm->stats.ip6gre_lapb_flag_toggles);
	}

	if (shm->stats.wgdf_runs) {
		stat_row("wireguard_decrypt_flood", "runs",                shm->stats.wgdf_runs);
		stat_row("wireguard_decrypt_flood", "setup_failed",        shm->stats.wgdf_setup_failed);
		stat_row("wireguard_decrypt_flood", "packets_sent",        shm->stats.wgdf_packets_sent);
		stat_row("wireguard_decrypt_flood", "unsupported_latched", shm->stats.wgdf_unsupported_latched);
	}

	if (shm->stats.blkdev_lifecycle_runs) {
		stat_row("blkdev_lifecycle_race", "runs",          shm->stats.blkdev_lifecycle_runs);
		stat_row("blkdev_lifecycle_race", "setup_failed",  shm->stats.blkdev_lifecycle_setup_failed);
		stat_row("blkdev_lifecycle_race", "set_fd_ok",     shm->stats.blkdev_lifecycle_set_fd_ok);
		stat_row("blkdev_lifecycle_race", "clr_fd",        shm->stats.blkdev_lifecycle_clr_fd);
		stat_row("blkdev_lifecycle_race", "ebusy",         shm->stats.blkdev_lifecycle_ebusy);
		stat_row("blkdev_lifecycle_race", "rescans",       shm->stats.blkdev_lifecycle_rescans);
	}

	if (shm->stats.ipvs_sysctl_writer_runs) {
		stat_row("ipvs_sysctl_writer", "runs",                shm->stats.ipvs_sysctl_writer_runs);
		stat_row("ipvs_sysctl_writer", "writes_ok",           shm->stats.ipvs_sysctl_writer_writes_ok);
		stat_row("ipvs_sysctl_writer", "writes_failed",       shm->stats.ipvs_sysctl_writer_writes_failed);
		stat_row("ipvs_sysctl_writer", "unsupported_latched", shm->stats.ipvs_sysctl_writer_unsupported_latched);
	}

	if (shm->stats.ipv6_ndisc_proxy_runs) {
		stat_row("ipv6_ndisc_proxy", "runs",            shm->stats.ipv6_ndisc_proxy_runs);
		stat_row("ipv6_ndisc_proxy", "ns_sent_ok",      shm->stats.ipv6_ndisc_proxy_ns_sent_ok);
		stat_row("ipv6_ndisc_proxy", "setup_failed",    shm->stats.ipv6_ndisc_proxy_setup_failed);
		stat_row("ipv6_ndisc_proxy", "proxy_enable_ok", shm->stats.ipv6_ndisc_proxy_proxy_enable_ok);
	}

	if (shm->stats.ipfrag_source_runs) {
		stat_row("ipfrag_source_churn", "runs",            shm->stats.ipfrag_source_runs);
		stat_row("ipfrag_source_churn", "packets_sent_ok", shm->stats.ipfrag_packets_sent_ok);
		stat_row("ipfrag_source_churn", "send_failed",     shm->stats.ipfrag_send_failed);
		stat_row("ipfrag_source_churn", "unique_srcs",     shm->stats.ipfrag_unique_srcs);
	}

	if (shm->stats.rtnl_vf_broadcast_runs) {
		stat_row("rtnl_vf_broadcast_getlink", "runs",          shm->stats.rtnl_vf_broadcast_runs);
		stat_row("rtnl_vf_broadcast_getlink", "setup_ok",      shm->stats.rtnl_vf_broadcast_setup_ok);
		stat_row("rtnl_vf_broadcast_getlink", "setup_failed",  shm->stats.rtnl_vf_broadcast_setup_failed);
		stat_row("rtnl_vf_broadcast_getlink", "getlink_ok",    shm->stats.rtnl_vf_broadcast_getlink_ok);
	}

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

	if (shm->stats.flowtable_vlan_runs) {
		stat_row("flowtable_encap_vlan", "runs",                 shm->stats.flowtable_vlan_runs);
		stat_row("flowtable_encap_vlan", "setup_ok",             shm->stats.flowtable_vlan_setup_ok);
		stat_row("flowtable_encap_vlan", "setup_failed",         shm->stats.flowtable_vlan_setup_failed);
		stat_row("flowtable_encap_vlan", "offloaded_pkts",       shm->stats.flowtable_vlan_offloaded_pkts);
		stat_row("flowtable_encap_vlan", "gso_sends",            shm->stats.flowtable_vlan_gso_sends);
		stat_row("flowtable_encap_vlan", "vlan_teardown_races",  shm->stats.flowtable_vlan_vlan_teardown_races);
		stat_row("flowtable_encap_vlan", "unsupported_latched",  shm->stats.flowtable_vlan_unsupported_latched);
	}

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

	if (shm->stats.splice_protocols_runs) {
		stat_row("splice_protocols", "runs",                  shm->stats.splice_protocols_runs);
		stat_row("splice_protocols", "setup_failed",          shm->stats.splice_protocols_setup_failed);
		stat_row("splice_protocols", "chain_ok",              shm->stats.splice_protocols_chain_ok);
		stat_row("splice_protocols", "in_bytes",              shm->stats.splice_protocols_in_bytes);
		stat_row("splice_protocols", "out_bytes",             shm->stats.splice_protocols_out_bytes);
		stat_row("splice_protocols", "udp_encap_attempted",   shm->stats.splice_protocols_udp_encap_attempted);
		stat_row("splice_protocols", "tcp_repair_attempted",  shm->stats.splice_protocols_tcp_repair_attempted);
		stat_row("splice_protocols", "packet_ring_attempted", shm->stats.splice_protocols_packet_ring_attempted);
		stat_row("splice_protocols", "alg_attempted",         shm->stats.splice_protocols_alg_attempted);
		stat_row("splice_protocols", "rxrpc_attempted",       shm->stats.splice_protocols_rxrpc_attempted);
		stat_row("splice_protocols", "msg_splice_pages_attempted",           shm->stats.splice_protocols_msg_splice_pages_attempted);
		stat_row("splice_protocols", "msg_splice_pages_path_taken_inferred", shm->stats.splice_protocols_msg_splice_pages_path_taken_inferred);
	}

	if (shm->stats.rxrpc_key_install_runs) {
		stat_row("rxrpc_key_install", "runs",        shm->stats.rxrpc_key_install_runs);
		stat_row("rxrpc_key_install", "calls",       shm->stats.rxrpc_key_install_calls);
		stat_row("rxrpc_key_install", "revokes",     shm->stats.rxrpc_key_install_revokes);
		stat_row("rxrpc_key_install", "quota_hits",  shm->stats.rxrpc_key_install_quota_hits);
		stat_row("rxrpc_key_install", "unsupported", shm->stats.rxrpc_key_install_unsupported);
	}

	if (shm->stats.af_alg_weak_cipher_probe_runs) {
		stat_row("af_alg_weak_cipher_probe", "runs",                   shm->stats.af_alg_weak_cipher_probe_runs);
		stat_row("af_alg_weak_cipher_probe", "socket_failed",          shm->stats.af_alg_weak_cipher_probe_socket_failed);
		stat_row("af_alg_weak_cipher_probe", "total_bind_attempts",    shm->stats.af_alg_weak_cipher_probe_total_bind_attempts);
		stat_row("af_alg_weak_cipher_probe", "total_bind_accepted",    shm->stats.af_alg_weak_cipher_probe_total_bind_accepted);
		stat_row("af_alg_weak_cipher_probe", "weak_accepted_total",    shm->stats.af_alg_weak_cipher_probe_weak_accepted_total);
		stat_row("af_alg_weak_cipher_probe", "setkey_accepted_total",  shm->stats.af_alg_weak_cipher_probe_setkey_accepted_total);
		stat_row("af_alg_weak_cipher_probe", "skcipher_weak_accepted", shm->stats.af_alg_weak_cipher_probe_skcipher_weak_accepted);
		stat_row("af_alg_weak_cipher_probe", "aead_weak_accepted",     shm->stats.af_alg_weak_cipher_probe_aead_weak_accepted);
		stat_row("af_alg_weak_cipher_probe", "hash_weak_accepted",     shm->stats.af_alg_weak_cipher_probe_hash_weak_accepted);
		stat_row("af_alg_weak_cipher_probe", "strong_rejected",        shm->stats.af_alg_weak_cipher_probe_strong_rejected);
	}

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

	if (kcov_shm != NULL) {
		unsigned int top_nr[10];
		unsigned long top_edges[10];
		unsigned int top_count = 0;
		unsigned int cold_count = 0;
		unsigned int j;

		unsigned long kc_edges       = __atomic_load_n(&kcov_shm->edges_found,            __ATOMIC_RELAXED);
		unsigned long kc_pcs         = __atomic_load_n(&kcov_shm->total_pcs,              __ATOMIC_RELAXED);
		unsigned long kc_calls       = __atomic_load_n(&kcov_shm->total_calls,            __ATOMIC_RELAXED);
		unsigned long kc_remote      = __atomic_load_n(&kcov_shm->remote_calls,           __ATOMIC_RELAXED);
		unsigned long kc_cmp_records = __atomic_load_n(&kcov_shm->cmp_records_collected,  __ATOMIC_RELAXED);
		unsigned long kc_cmp_trunc   = __atomic_load_n(&kcov_shm->cmp_trace_truncated,    __ATOMIC_RELAXED);

		stat_row("kcov_coverage", "unique_edges",          kc_edges);
		stat_row("kcov_coverage", "total_pcs",             kc_pcs);
		stat_row("kcov_coverage", "total_calls",           kc_calls);
		stat_row("kcov_coverage", "remote_calls",          kc_remote);
		stat_row("kcov_coverage", "cmp_records_collected", kc_cmp_records);
		if (kc_cmp_trunc > 0)
			stat_row("kcov_coverage", "cmp_trace_truncated", kc_cmp_trunc);

		/* Find top 10 edge-producing syscalls via insertion sort. */
		unsigned int nr_syscalls_to_scan = biarch ? max_nr_64bit_syscalls : max_nr_syscalls;
		const struct syscalltable *table = biarch ? syscalls_64bit : syscalls;

		memset(top_edges, 0, sizeof(top_edges));
		for (i = 0; i < nr_syscalls_to_scan; i++) {
			unsigned long edges = __atomic_load_n(&kcov_shm->per_syscall_edges[i], __ATOMIC_RELAXED);

			if (edges == 0)
				continue;

			if (kcov_syscall_is_cold(i))
				cold_count++;

			/* Find insertion point. */
			for (j = top_count; j > 0 && edges > top_edges[j - 1]; j--) {
				if (j < 10) {
					top_edges[j] = top_edges[j - 1];
					top_nr[j] = top_nr[j - 1];
				}
			}
			if (j < 10) {
				top_edges[j] = edges;
				top_nr[j] = i;
				if (top_count < 10)
					top_count++;
			}
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

				for (j = delta_count; j > 0 && delta > delta_edges[j - 1]; j--) {
					if (j < 10) {
						delta_edges[j] = delta_edges[j - 1];
						delta_nr[j] = delta_nr[j - 1];
					}
				}
				if (j < 10) {
					delta_edges[j] = delta;
					delta_nr[j] = i;
					if (delta_count < 10)
						delta_count++;
				}
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
	}

	if (minicorpus_shm != NULL) {
		static const char * const op_names[MUT_NUM_OPS] = {
			"bit-flip", "add", "sub", "boundary", "byte-shuf", "keep",
			"bswap-add", "bswap-sub", "fd-swap"
		};
		unsigned long tot_trials = 0;
		unsigned long r_count, r_wins, s_hits, s_wins, pct10;
		unsigned long histo_total;
		char hbuf[80];
		int hpos;

		for (i = 0; i < MUT_NUM_OPS; i++)
			tot_trials += __atomic_load_n(&minicorpus_shm->mut_trials[i],
						      __ATOMIC_RELAXED);

		if (tot_trials > 0) {
			output(0, "\nMutator productivity (wins/trials):\n");
			for (i = 0; i < MUT_NUM_OPS; i++) {
				unsigned long t = __atomic_load_n(&minicorpus_shm->mut_trials[i],
								  __ATOMIC_RELAXED);
				unsigned long w = __atomic_load_n(&minicorpus_shm->mut_wins[i],
								  __ATOMIC_RELAXED);
				pct10 = t ? (w * 1000UL / t) : 0UL;
				output(0, "  %-10s %lu/%lu (%lu.%lu%%)\n",
				       op_names[i], w, t, pct10 / 10, pct10 % 10);
			}
		}

		s_hits = __atomic_load_n(&minicorpus_shm->splice_hits, __ATOMIC_RELAXED);
		s_wins = __atomic_load_n(&minicorpus_shm->splice_wins, __ATOMIC_RELAXED);
		if (s_hits > 0) {
			pct10 = s_wins * 1000UL / s_hits;
			output(0, "Splice: %lu hits  %lu wins (%lu.%lu%%)\n",
			       s_hits, s_wins, pct10 / 10, pct10 % 10);
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

		for (i = 0; i < MAX_NR_SYSCALL; i++) {
			if (cmp_hints_shm->pools[i].count > 0) {
				total_hints += cmp_hints_shm->pools[i].count;
				syscalls_with_hints++;
			}
		}
		stat_row("cmp_hints", "values_total",        total_hints);
		stat_row("cmp_hints", "syscalls_with_hints", syscalls_with_hints);
	}

	if (edgepair_is_enabled()) {
		unsigned int top_count = 0;
		unsigned int cold_pairs = 0;
		struct {
			unsigned int prev_nr;
			unsigned int curr_nr;
			unsigned long new_edges;
		} top[10];
		unsigned int j;

		memset(top, 0, sizeof(top));

		stat_row("edgepair_coverage", "unique_pairs",     parent_edgepair.pairs_tracked);
		stat_row("edgepair_coverage", "total_pair_calls", parent_edgepair.total_pair_calls);

		if (parent_edgepair.pairs_dropped > 0)
			stat_row("edgepair_coverage", "inserts_dropped", parent_edgepair.pairs_dropped);

		for (i = 0; i < EDGEPAIR_TABLE_SIZE; i++) {
			struct edgepair_entry *e = &parent_edgepair.table[i];
			unsigned long edges;

			if (e->prev_nr == EDGEPAIR_EMPTY)
				continue;

			edges = e->new_edge_count;
			if (edges == 0)
				continue;

			if (edgepair_is_cold(e->prev_nr, e->curr_nr))
				cold_pairs++;

			for (j = top_count; j > 0 && edges > top[j - 1].new_edges; j--) {
				if (j < 10)
					top[j] = top[j - 1];
			}
			if (j < 10) {
				top[j].prev_nr = e->prev_nr;
				top[j].curr_nr = e->curr_nr;
				top[j].new_edges = edges;
				if (top_count < 10)
					top_count++;
			}
		}

		if (top_count > 0) {
			const struct syscalltable *table = biarch ? syscalls_64bit : syscalls;
			unsigned int nr_max = biarch ? max_nr_64bit_syscalls : max_nr_syscalls;

			output(0, "Top edge-producing syscall pairs:\n");
			for (j = 0; j < top_count; j++) {
				const char *prev_name = "???";
				const char *curr_name = "???";

				if (top[j].prev_nr < nr_max && table[top[j].prev_nr].entry)
					prev_name = table[top[j].prev_nr].entry->name;
				if (top[j].curr_nr < nr_max && table[top[j].curr_nr].entry)
					curr_name = table[top[j].curr_nr].entry->name;

				output(0, "  %-20s -> %-20s %lu\n",
					prev_name, curr_name, top[j].new_edges);
			}
		}

		if (cold_pairs > 0)
			stat_row("edgepair_coverage", "cold_pairs", cold_pairs);

		edgepair_dump_to_file("edgepair.dump");
	}
}
