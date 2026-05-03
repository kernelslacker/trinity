#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "arch.h"
#include "cmp_hints.h"
#include "edgepair.h"
#include "kcov.h"
#include "minicorpus.h"
#include "params.h"
#include "sequence.h"
#include "shm.h"
#include "stats.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

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
		total += shm->stats.syscall_category_count[i];
	if (total == 0)
		return;

	output(0, "Syscall category histogram (total: %lu):\n", total);
	for (i = 0; i < NR_SYSCAT; i++) {
		unsigned long c = shm->stats.syscall_category_count[i];
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
		"\"total_calls\":%lu,\"remote_calls\":%lu",
		kc_edges, kc_pcs, kc_calls, kc_remote);

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

	if (edgepair_shm == NULL) {
		fputs(",\"edgepair\":null", stdout);
		return;
	}

	memset(top, 0, sizeof(top));
	for (i = 0; i < EDGEPAIR_TABLE_SIZE; i++) {
		struct edgepair_entry *e = &edgepair_shm->table[i];
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
		edgepair_shm->pairs_tracked, edgepair_shm->total_pair_calls,
		edgepair_shm->pairs_dropped, cold_pairs);

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
			"\"runtime_registered\":%lu},"
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
		"\"netlink_generator\":{\"nested_attrs_emitted\":%lu},"
		"\"perf_event_chains\":{\"runs\":%lu,\"groups_created\":%lu,\"ioctl_ops\":%lu},"
		"\"tracefs_fuzzer\":{\"kprobe_writes\":%lu,\"uprobe_writes\":%lu,"
			"\"filter_writes\":%lu,\"event_enable_writes\":%lu,\"misc_writes\":%lu},"
		"\"bpf_lifecycle\":{\"runs\":%lu,\"progs_loaded\":%lu,\"attached\":%lu,"
			"\"triggered\":%lu,\"verifier_rejects\":%lu,\"attach_failed\":%lu,\"eperm\":%lu},"
		"\"bpf_fd_provider\":{\"maps_provided\":%lu,\"progs_provided\":%lu},"
		"\"recipe_runner\":{\"runs\":%lu,\"completed\":%lu,\"partial\":%lu,\"unsupported\":%lu},"
		"\"iouring_recipes\":{\"runs\":%lu,\"completed\":%lu,\"partial\":%lu,\"enosys\":%lu},"
		"\"zombie_slots\":{\"pending\":%lu,\"reaped\":%lu,\"timed_out\":%lu},"
		"\"corruption\":{\"local_op_count\":%lu,\"fd_event_ring_noncanon\":%lu,"
			"\"fd_event_ring_canary\":%lu,\"deferred_free_corrupt_ptr\":%lu},"
		"\"shared_buffer\":{\"args_redirected\":%lu,\"range_overlaps_shared_rejects\":%lu},"
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
		"\"flock_thrash\":{\"runs\":%lu,\"locks\":%lu,\"failed\":%lu},"
		"\"xattr_thrash\":{\"runs\":%lu,\"set\":%lu,\"get\":%lu,"
			"\"remove\":%lu,\"list\":%lu,\"failed\":%lu},"
		"\"cgroup_churn\":{\"runs\":%lu,\"mkdirs\":%lu,\"rmdirs\":%lu,\"failed\":%lu},"
		"\"mount_churn\":{\"runs\":%lu,\"mounts\":%lu,\"umounts\":%lu,\"failed\":%lu},"
		"\"uffd_churn\":{\"runs\":%lu,\"registers\":%lu,\"unregisters\":%lu,\"failed\":%lu},"
		"\"iouring_flood\":{\"runs\":%lu,\"submits\":%lu,\"reaped\":%lu,\"failed\":%lu},"
		"\"close_racer\":{\"runs\":%lu,\"pairs\":%lu,\"failed\":%lu,\"thread_spawn_fail\":%lu},"
		"\"socket_family_chain\":{\"runs\":%lu,\"completed\":%lu,\"failed\":%lu,\"authencesn_attempts\":%lu,\"splice_attempts\":%lu}"
		"}",
		shm->stats.fault_injected, shm->stats.fault_consumed,
		shm->stats.fd_stale_detected, shm->stats.fd_stale_by_generation,
		shm->stats.fd_closed_tracked, shm->stats.fd_regenerated,
		shm->stats.fd_duped, shm->stats.fd_events_processed,
		shm->stats.fd_events_dropped, shm->stats.fd_runtime_registered,
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
		shm->stats.zombie_slots_pending, shm->stats.zombies_reaped,
		shm->stats.zombies_timed_out,
		shm->stats.local_op_count_corrupted, shm->stats.fd_event_ring_corrupted,
		shm->stats.fd_event_ring_overwritten,
		shm->stats.deferred_free_corrupt_ptr,
		shm->stats.shared_buffer_redirected, shm->stats.range_overlaps_shared_rejects,
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
		shm->stats.flock_thrash_runs, shm->stats.flock_thrash_locks,
		shm->stats.flock_thrash_failed,
		shm->stats.xattr_thrash_runs, shm->stats.xattr_thrash_set,
		shm->stats.xattr_thrash_get, shm->stats.xattr_thrash_remove,
		shm->stats.xattr_thrash_list, shm->stats.xattr_thrash_failed,
		shm->stats.cgroup_churn_runs, shm->stats.cgroup_mkdirs,
		shm->stats.cgroup_rmdirs, shm->stats.cgroup_failed,
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
		shm->stats.socket_family_chain_splice_attempts);

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
		unsigned long c64 = shm->stats.range_overlaps_shared_rejects_per_syscall_64[i];
		unsigned long c32 = shm->stats.range_overlaps_shared_rejects_per_syscall_32[i];
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

	if (shm->stats.fault_injected) {
		stat_row("fault_injection", "armed_fail_nth",  shm->stats.fault_injected);
		stat_row("fault_injection", "returned_enomem", shm->stats.fault_consumed);
	}

	if (shm->stats.fd_stale_detected || shm->stats.fd_closed_tracked ||
	    shm->stats.fd_regenerated || shm->stats.fd_stale_by_generation ||
	    shm->stats.fd_duped || shm->stats.fd_events_processed) {
		stat_row("fd_lifecycle", "stale_detected",      shm->stats.fd_stale_detected);
		stat_row("fd_lifecycle", "stale_by_generation", shm->stats.fd_stale_by_generation);
		stat_row("fd_lifecycle", "closed_tracked",      shm->stats.fd_closed_tracked);
		stat_row("fd_lifecycle", "regenerated",         shm->stats.fd_regenerated);
		stat_row("fd_lifecycle", "duped",               shm->stats.fd_duped);
		stat_row("fd_lifecycle", "events_processed",    shm->stats.fd_events_processed);
		stat_row("fd_lifecycle", "events_dropped",      shm->stats.fd_events_dropped);
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

	if (shm->stats.netlink_nested_attrs_emitted)
		stat_row("netlink_generator", "nested_attrs_emitted", shm->stats.netlink_nested_attrs_emitted);

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

	if (shm->stats.zombies_reaped || shm->stats.zombies_timed_out ||
	    shm->stats.zombie_slots_pending) {
		stat_row("zombie_slots", "pending",   shm->stats.zombie_slots_pending);
		stat_row("zombie_slots", "reaped",    shm->stats.zombies_reaped);
		stat_row("zombie_slots", "timed_out", shm->stats.zombies_timed_out);
	}

	if (shm->stats.local_op_count_corrupted)
		stat_row("corruption", "local_op_count",         shm->stats.local_op_count_corrupted);
	if (shm->stats.fd_event_ring_corrupted)
		stat_row("corruption", "fd_event_ring_noncanon", shm->stats.fd_event_ring_corrupted);
	if (shm->stats.fd_event_ring_overwritten)
		stat_row("corruption", "fd_event_ring_canary",   shm->stats.fd_event_ring_overwritten);
	if (shm->stats.deferred_free_corrupt_ptr)
		stat_row("corruption", "deferred_free_corrupt_ptr", shm->stats.deferred_free_corrupt_ptr);

	if (shm->stats.shared_buffer_redirected)
		stat_row("shared_buffer", "args_redirected",     shm->stats.shared_buffer_redirected);
	if (shm->stats.range_overlaps_shared_rejects) {
		stat_row("shared_buffer", "range_overlaps_shared_rejects",
			 shm->stats.range_overlaps_shared_rejects);
		if (verbosity > 1)
			dump_range_overlaps_shared_top_offenders();
	}

	if (verbosity > 1)
		dump_syscall_category_histogram();

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

	if (shm->stats.cgroup_churn_runs) {
		stat_row("cgroup_churn", "runs",   shm->stats.cgroup_churn_runs);
		stat_row("cgroup_churn", "mkdirs", shm->stats.cgroup_mkdirs);
		stat_row("cgroup_churn", "rmdirs", shm->stats.cgroup_rmdirs);
		stat_row("cgroup_churn", "failed", shm->stats.cgroup_failed);
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

	if (kcov_shm != NULL) {
		unsigned int top_nr[10];
		unsigned long top_edges[10];
		unsigned int top_count = 0;
		unsigned int cold_count = 0;
		unsigned int j;

		unsigned long kc_edges  = __atomic_load_n(&kcov_shm->edges_found,   __ATOMIC_RELAXED);
		unsigned long kc_pcs    = __atomic_load_n(&kcov_shm->total_pcs,     __ATOMIC_RELAXED);
		unsigned long kc_calls  = __atomic_load_n(&kcov_shm->total_calls,   __ATOMIC_RELAXED);
		unsigned long kc_remote = __atomic_load_n(&kcov_shm->remote_calls,  __ATOMIC_RELAXED);

		stat_row("kcov_coverage", "unique_edges", kc_edges);
		stat_row("kcov_coverage", "total_pcs",    kc_pcs);
		stat_row("kcov_coverage", "total_calls",  kc_calls);
		stat_row("kcov_coverage", "remote_calls", kc_remote);

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

	if (edgepair_shm != NULL) {
		unsigned int top_count = 0;
		unsigned int cold_pairs = 0;
		struct {
			unsigned int prev_nr;
			unsigned int curr_nr;
			unsigned long new_edges;
		} top[10];
		unsigned int j;

		memset(top, 0, sizeof(top));

		stat_row("edgepair_coverage", "unique_pairs",     edgepair_shm->pairs_tracked);
		stat_row("edgepair_coverage", "total_pair_calls", edgepair_shm->total_pair_calls);

		if (edgepair_shm->pairs_dropped > 0)
			stat_row("edgepair_coverage", "inserts_dropped", edgepair_shm->pairs_dropped);

		for (i = 0; i < EDGEPAIR_TABLE_SIZE; i++) {
			struct edgepair_entry *e = &edgepair_shm->table[i];
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
