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

/*
 * Aggregate-stats table column widths. Header + every row uses the same
 * format string so output is greppable (grep '^fd_lifecycle ') and
 * human-scannable (columns line up).
 */
static void stats_emit_header(void)
{
	output(0, "\n");
	output(0, STATS_HDR_FMT, "CATEGORY", "METRIC", "VALUE");
	output(0, STATS_HDR_FMT,
	       "----------------------",
	       "--------------------------------",
	       "-----");
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

void dump_syscall_category_histogram(void)
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

void dump_stats_runtime_header(void)
{
	time_t start = shm->start_time;
	uint64_t start_ns = shm->start_mono_ns;
	uint64_t now_ns = mono_ns();
	long elapsed = (start_ns != 0 && now_ns >= start_ns) ?
		(long)((now_ns - start_ns) / 1000000000ULL) : 0;
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

void dump_stats_per_syscall_tables(void)
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

void dump_stats_top_wedging_syscalls(void)
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
void dump_stats_top_wedging_childops(void)
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
			&shm->stats.childop.wedge_count[i],
			__ATOMIC_RELAXED);
		unsigned long long u = __atomic_load_n(
			&shm->stats.childop.wedge_total_us[i],
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
