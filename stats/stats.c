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

static void dump_stats_runtime_header(void)
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

static void dump_fd_lifecycle(void)
{
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
static void dump_fd_provider_outstanding(void)
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

static void dump_stats_fd_tracking(void)
{
	if (parent_stats.fault_injected) {
		stat_row("fault_injection", "armed_fail_nth",  parent_stats.fault_injected);
		stat_row("fault_injection", "returned_enomem", parent_stats.fault_consumed);
	}

	dump_fd_lifecycle();

	dump_fd_provider_outstanding();

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


static void dump_corpus_mutator_productivity(void)
{
	unsigned long tot_trials = 0;
	unsigned int i;

	for (i = 0; i < MUT_NUM_OPS; i++)
		tot_trials += __atomic_load_n(&minicorpus_shm->mut_trials[i],
					      __ATOMIC_RELAXED);

	if (tot_trials == 0)
		return;

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
		unsigned long pct10 = t ? (w * 1000UL / t) : 0UL;

		output(0, "  %-10s %lu/%lu (%lu.%lu%%)  [%lu/%lu (%lu.%lu%%)]\n",
		       op_names[i], w, t, pct10 / 10, pct10 % 10,
		       sw, st, spct10 / 10, spct10 % 10);
	}
}

static void dump_corpus_xprop(void)
{
	unsigned long xp_hits = __atomic_load_n(
		&minicorpus_shm->xprop_hits, __ATOMIC_RELAXED);
	unsigned long xp_wins = __atomic_load_n(
		&minicorpus_shm->xprop_wins, __ATOMIC_RELAXED);
	unsigned long pct10;

	if (xp_hits == 0)
		return;

	pct10 = xp_wins * 1000UL / xp_hits;
	output(0, "Xprop: %lu hits  %lu wins (%lu.%lu%%)\n",
	       xp_hits, xp_wins, pct10 / 10, pct10 % 10);
}

static void dump_corpus_stack_depth(void)
{
	unsigned long histo_total = 0;
	char hbuf[80];
	int hpos = 0;
	int written;
	unsigned int i;

	for (i = 1; i <= STACK_MAX; i++)
		histo_total += __atomic_load_n(&minicorpus_shm->stack_depth_histogram[i],
					       __ATOMIC_RELAXED);
	if (histo_total == 0)
		return;

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

/* CMP-source save / win telemetry.  Always emit when the
 * minicorpus block is being dumped -- a zero on saves_cmp is
 * itself a signal worth seeing ("the gate widening is in but
 * the path isn't firing"), per the falsification criteria in
 * the investigations/ analysis. */
static void dump_corpus_saves(void)
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
static void dump_corpus_struct_field_mutator(void)
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
		[FT_EMBEDDED_STRUCT]	= "embedded_struct",
	};
	unsigned long sf_total = 0;
	unsigned int t;

	for (t = 0; t < FT_NUM_TAGS; t++)
		sf_total += __atomic_load_n(
			&minicorpus_shm->mut_struct_field_trials[t],
			__ATOMIC_RELAXED);

	if (sf_total == 0)
		return;

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

static void dump_corpus_sequence_chains(void)
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

static void dump_stats_corpus_tail(void)
{
	unsigned long s_hits, s_wins, r_count, r_wins, torn, pct10;

	dump_corpus_mutator_productivity();

	s_hits = __atomic_load_n(&minicorpus_shm->splice_hits, __ATOMIC_RELAXED);
	s_wins = __atomic_load_n(&minicorpus_shm->splice_wins, __ATOMIC_RELAXED);
	if (s_hits > 0) {
		pct10 = s_wins * 1000UL / s_hits;
		output(0, "Splice: %lu hits  %lu wins (%lu.%lu%%)\n",
		       s_hits, s_wins, pct10 / 10, pct10 % 10);
	}

	dump_corpus_xprop();

	/* Lockless-reader torn-read validator firings (aggregate over
	 * xprop pick, replay common, replay burst).  Gated on non-zero
	 * because the expected steady-state value is 0 -- the writer's
	 * release-store publish pattern makes mid-publish reads rare.
	 * A non-zero rate here means the validator is doing real work
	 * and torn reads ARE happening at the printed rate. */
	torn = __atomic_load_n(&minicorpus_shm->replay_torn_rejects,
			       __ATOMIC_RELAXED);
	if (torn > 0)
		output(0, "Corpus torn-read rejects: %lu\n", torn);

	dump_corpus_stack_depth();

	r_count = __atomic_load_n(&minicorpus_shm->replay_count, __ATOMIC_RELAXED);
	r_wins  = __atomic_load_n(&minicorpus_shm->replay_wins,  __ATOMIC_RELAXED);
	if (r_count > 0) {
		pct10 = r_wins * 1000UL / r_count;
		output(0, "Corpus replay: %lu replays  %lu wins (%lu.%lu%%)\n",
		       r_count, r_wins, pct10 / 10, pct10 % 10);
	}

	dump_corpus_saves();
	dump_corpus_struct_field_mutator();
	dump_corpus_sequence_chains();
}

static void dump_stats_cmp_hints_tail(void)
{
	unsigned int total_hints = 0, syscalls_with_hints = 0;
	unsigned int i, a;

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
static void dump_stats_taint_snapshot(void)
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

static void dump_stats_corpus_and_taint_tail(void)
{
	if (minicorpus_shm != NULL)
		dump_stats_corpus_tail();

	if (cmp_hints_shm != NULL)
		dump_stats_cmp_hints_tail();

	dump_stats_taint_snapshot();
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

/*
 * Per-op fd-delta triage dump.  Skips ops that never landed a positive
 * delta (skip-zero convention, matches the rest of the per-childop
 * dumps).  When any op is emitted, the sort of the surviving rows by
 * total leak count is left to the operator; a leaker manifests as a
 * high fd_delta_positive_ops (many invocations that grew the fd table)
 * and a fd_delta_positive_sum trending unbounded across the run, while
 * ops with occasional short-lived probe collisions (open()/close() from
 * a sibling on the same low-numbered slot) sit at fd_delta_positive_ops
 * <= a few and _sum comparable to that count.  Fully self-suppressed
 * when instrumentation never fired -- the summary line only appears
 * once at least one op has a non-zero _sum.
 */
static void __cold dump_stats_childop_fd_delta(void)
{
	enum child_op_type op;
	bool any = false;

	for (op = CHILD_OP_SYSCALL + 1; op < NR_CHILD_OP_TYPES; op++) {
		unsigned long sum, ops;

		sum = __atomic_load_n(
				&shm->stats.childop_fd_delta_positive_sum[op],
				__ATOMIC_RELAXED);
		if (sum == 0)
			continue;
		ops = __atomic_load_n(
				&shm->stats.childop_fd_delta_positive_ops[op],
				__ATOMIC_RELAXED);

		if (!any) {
			output(1,
			       "childop_fd_delta: per-op net fd-table growth "
			       "observed across dispatched alt-op invocations\n");
			any = true;
		}
		output(1,
		       "childop_fd_delta %s: positive_sum=%lu positive_ops=%lu\n",
		       alt_op_name(op), sum, ops);
	}
}

static void __cold dump_stats_topo_pair_shadow(void)
{
	/* Per-setup_op aggregates from the surviving ring entries.  Sized
	 * by NR_CHILD_OP_TYPES so a corrupted setup_op byte that masks to
	 * the sentinel value is still in-bounds; the loop skips
	 * NR_CHILD_OP_TYPES at render time so the sentinel slot stays
	 * inert.  Local-stack to avoid touching shm for the aggregate. */
	unsigned long per_op_pc[NR_CHILD_OP_TYPES] = { 0 };
	unsigned long per_op_trans[NR_CHILD_OP_TYPES] = { 0 };
	unsigned long per_op_age_sum[NR_CHILD_OP_TYPES] = { 0 };
	unsigned long total_records, no_setup, head, total_valid = 0;
	unsigned int i;

	total_records = __atomic_load_n(&shm->stats.topo_pair_records,
					__ATOMIC_RELAXED);
	no_setup = __atomic_load_n(&shm->stats.topo_pair_no_setup_observed,
				   __ATOMIC_RELAXED);

	/* Self-skip when no productive event has fired through the ring
	 * AND no event has been dropped to the no-setup denominator -- in
	 * that state the row would carry no signal at all, and emitting a
	 * blank "shadow active, ring empty" line just adds noise to the
	 * shutdown dump.  Matches the dump_stats_top_wedging_childops()
	 * self-skip pattern. */
	if (total_records == 0 && no_setup == 0)
		return;

	head = __atomic_load_n(&shm->stats.topo_pair_ring_head,
			       __ATOMIC_RELAXED);

	for (i = 0; i < TOPO_PAIR_RING_SIZE; i++) {
		uint64_t packed;
		unsigned int setup_op, reason, syscall_nr, age;

		packed = __atomic_load_n(&shm->stats.topo_pair_ring[i],
					 __ATOMIC_RELAXED);
		if (!topo_pair_unpack(packed, &setup_op, &reason,
				      &syscall_nr, &age))
			continue;
		/* Defensive bounds check: the producer's topo_pair_pack()
		 * AND-masks setup_op to 8 bits, so a sentinel-or-corrupt
		 * value cast from NR_CHILD_OP_TYPES would not be filtered
		 * by the producer's branch alone.  Skip rather than scribble
		 * past the per_op_* arrays. */
		if (setup_op >= NR_CHILD_OP_TYPES)
			continue;
		if (reason == TOPO_PAIR_REASON_PC)
			per_op_pc[setup_op]++;
		else if (reason == TOPO_PAIR_REASON_TRANSITION)
			per_op_trans[setup_op]++;
		else
			continue;
		per_op_age_sum[setup_op] += age;
		total_valid++;
	}

	output(0,
	       "topo_pair_shadow: events_total=%lu sample_window=%u "
	       "valid_in_ring=%lu no_setup_observed=%lu head=%lu wrapped=%s\n",
	       total_records, (unsigned int)TOPO_PAIR_RING_SIZE,
	       total_valid, no_setup, head,
	       total_records >= (unsigned long)TOPO_PAIR_RING_SIZE
	       ? "yes" : "no");

	if (total_valid == 0)
		return;

	for (i = 0; i < NR_CHILD_OP_TYPES; i++) {
		unsigned long n;
		unsigned long mean_age;
		const char *name;

		n = per_op_pc[i] + per_op_trans[i];
		if (n == 0)
			continue;

		mean_age = per_op_age_sum[i] / n;
		name = alt_op_name((enum child_op_type)i);
		output(0,
		       "topo_pair_shadow %s: samples=%lu pc=%lu transition=%lu mean_age=%lu\n",
		       name ? name : "?", n,
		       per_op_pc[i], per_op_trans[i], mean_age);
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

	dump_stats_childop_fd_delta();

	dump_stats_topo_pair_shadow();

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
