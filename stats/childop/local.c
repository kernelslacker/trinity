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

void dump_stats_childop_runs_local(void)
{
	stat_category_emit_text(&refcount_audit_category);

	if (shm->stats.fs_lifecycle.tmpfs   || shm->stats.fs_lifecycle.ramfs   ||
	    shm->stats.fs_lifecycle.rdonly  || shm->stats.fs_lifecycle.overlay ||
	    shm->stats.fs_lifecycle.quota   || shm->stats.fs_lifecycle.bind    ||
	    shm->stats.fs_lifecycle.unsupported) {
		stat_row("fs_lifecycle", "tmpfs",       shm->stats.fs_lifecycle.tmpfs);
		stat_row("fs_lifecycle", "ramfs",       shm->stats.fs_lifecycle.ramfs);
		stat_row("fs_lifecycle", "rdonly",      shm->stats.fs_lifecycle.rdonly);
		stat_row("fs_lifecycle", "overlay",     shm->stats.fs_lifecycle.overlay);
		stat_row("fs_lifecycle", "quota",       shm->stats.fs_lifecycle.quota);
		stat_row("fs_lifecycle", "bind",        shm->stats.fs_lifecycle.bind);
		stat_row("fs_lifecycle", "unsupported", shm->stats.fs_lifecycle.unsupported);
	}

	stat_category_emit_text(&signal_storm_category);

	if (shm->stats.futex_storm.runs)
		output(0, "\nfutex storm: runs:%lu inner_crashed:%lu iters:%lu\n",
			shm->stats.futex_storm.runs,
			shm->stats.futex_storm.inner_crashed,
			shm->stats.futex_storm.iters);

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

	slot = __atomic_load_n(&shm->stats.childop.decay_slot,
			       __ATOMIC_RELAXED);

	for (op = CHILD_OP_SYSCALL + 1; op < NR_CHILD_OP_TYPES; op++) {
		unsigned long invocations, recent_edges, recent_wall;
		unsigned long cum_edges, cum_wall;

		invocations = __atomic_load_n(
				&shm->stats.childop.invocations[op],
				__ATOMIC_RELAXED);
		if (invocations == 0)
			continue;

		recent_edges = __atomic_load_n(
				&shm->stats.childop.edge_recent_cached[op],
				__ATOMIC_RELAXED);
		recent_wall = __atomic_load_n(
				&shm->stats.childop.wall_recent_cached[op],
				__ATOMIC_RELAXED);
		cum_edges = __atomic_load_n(
				&shm->stats.childop.edges_clean[op],
				__ATOMIC_RELAXED);
		cum_wall = __atomic_load_n(
				&shm->stats.childop.wall_ns[op],
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
void __cold dump_stats_childop_fd_delta(void)
{
	enum child_op_type op;
	bool any = false;

	for (op = CHILD_OP_SYSCALL + 1; op < NR_CHILD_OP_TYPES; op++) {
		unsigned long sum, ops;

		sum = __atomic_load_n(
				&shm->stats.childop.fd_delta_positive_sum[op],
				__ATOMIC_RELAXED);
		if (sum == 0)
			continue;
		ops = __atomic_load_n(
				&shm->stats.childop.fd_delta_positive_ops[op],
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

void __cold dump_stats_topo_pair_shadow(void)
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

	total_records = __atomic_load_n(&shm->stats.topo_pair.records,
					__ATOMIC_RELAXED);
	no_setup = __atomic_load_n(&shm->stats.topo_pair.no_setup_observed,
				   __ATOMIC_RELAXED);

	/* Self-skip when no productive event has fired through the ring
	 * AND no event has been dropped to the no-setup denominator -- in
	 * that state the row would carry no signal at all, and emitting a
	 * blank "shadow active, ring empty" line just adds noise to the
	 * shutdown dump.  Matches the dump_stats_top_wedging_childops()
	 * self-skip pattern. */
	if (total_records == 0 && no_setup == 0)
		return;

	head = __atomic_load_n(&shm->stats.topo_pair.ring_head,
			       __ATOMIC_RELAXED);

	for (i = 0; i < TOPO_PAIR_RING_SIZE; i++) {
		uint64_t packed;
		unsigned int setup_op, reason, syscall_nr, age;

		packed = __atomic_load_n(&shm->stats.topo_pair.ring[i],
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
