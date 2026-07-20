#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/utsname.h>
#include <stdio.h>
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
#include "shadow_promote.h"
#include "shm.h"
#include "stats.h"
#include "stats-internal.h"
#include "stats_ring.h"
#include "strategy.h"		/* frontier_spare_lane_decide, enum frontier_spare_reason */
#include "syscall.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"
#include "utils.h"
#include "utils-proc.h"
#include "version.h"

/* Per-childop edge-discovery attribution: rendered sorted by
 * count descending so the operator sees the dominant alt-op
 * coverage contributors first.  CHILD_OP_SYSCALL is skipped
 * because the syscall path attributes its edges via the
 * explorer/bandit strategy counters; including it here would
 * double-count against KCOV total. */
static void dump_stats_render_childop_edges_discovered(void)
{
	struct { unsigned int op; unsigned long count; }
		ranked[NR_CHILD_OP_TYPES];
	unsigned int op, nranked = 0, ri, rj;
	char metric[40];

	for (op = CHILD_OP_SYSCALL + 1;
	     op < NR_CHILD_OP_TYPES; op++) {
		unsigned long v =
			shm->stats.childop.edges_discovered[op];
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
static void dump_stats_render_childop_calls_with_edges(void)
{
	struct { unsigned int op; unsigned long count; }
		ranked[NR_CHILD_OP_TYPES];
	unsigned int op, nranked = 0, ri, rj;
	char metric[40];

	for (op = CHILD_OP_SYSCALL + 1;
	     op < NR_CHILD_OP_TYPES; op++) {
		unsigned long v =
			shm->stats.childop.calls_with_edges[op];
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
static void dump_stats_render_childop_last_success_ts(void)
{
	struct { unsigned int op; unsigned long count; }
		ranked[NR_CHILD_OP_TYPES];
	unsigned int op, nranked = 0, ri, rj;
	char metric[40];

	for (op = CHILD_OP_SYSCALL + 1;
	     op < NR_CHILD_OP_TYPES; op++) {
		unsigned long v =
			shm->stats.childop.last_success_ts[op];
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
static void dump_stats_render_childop_setup_accepted(void)
{
	struct { unsigned int op; unsigned long count; }
		ranked[NR_CHILD_OP_TYPES];
	unsigned int op, nranked = 0, ri, rj;
	char metric[40];

	for (op = CHILD_OP_SYSCALL + 1;
	     op < NR_CHILD_OP_TYPES; op++) {
		unsigned long v =
			shm->stats.childop.setup_accepted[op];
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
static void dump_stats_render_childop_data_path(void)
{
	struct { unsigned int op; unsigned long count; }
		ranked[NR_CHILD_OP_TYPES];
	unsigned int op, nranked = 0, ri, rj;
	char metric[40];

	for (op = CHILD_OP_SYSCALL + 1;
	     op < NR_CHILD_OP_TYPES; op++) {
		unsigned long v =
			shm->stats.childop.data_path[op];
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
static void dump_stats_render_childop_setup_bound_permille(void)
{
	struct { unsigned int op; unsigned long ratio; }
		ranked[NR_CHILD_OP_TYPES];
	unsigned int op, nranked = 0, ri, rj;
	char metric[40];

	for (op = CHILD_OP_SYSCALL + 1;
	     op < NR_CHILD_OP_TYPES; op++) {
		unsigned long inv =
			shm->stats.childop.invocations[op];
		unsigned long acc;

		if (inv == 0)
			continue;
		acc = shm->stats.childop.setup_accepted[op];
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
static void dump_stats_render_childop_data_path_cold_permille(void)
{
	struct { unsigned int op; unsigned long ratio; }
		ranked[NR_CHILD_OP_TYPES];
	unsigned int op, nranked = 0, ri, rj;
	char metric[40];

	for (op = CHILD_OP_SYSCALL + 1;
	     op < NR_CHILD_OP_TYPES; op++) {
		unsigned long dp =
			shm->stats.childop.data_path[op];
		unsigned long ce;

		if (dp == 0)
			continue;
		ce = shm->stats.childop.calls_with_edges[op];
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

static void dump_stats_render_childop_taint_transitions(void)
{
	unsigned int op;
	char metric[40];

	for (op = 0; op < NR_CHILD_OP_TYPES; op++) {
		if (shm->stats.childop.taint_transitions[op] == 0)
			continue;
		snprintf(metric, sizeof(metric), "%s",
			 alt_op_name((enum child_op_type)op));
		stat_row("taint_transitions", metric,
			 shm->stats.childop.taint_transitions[op]);
	}
}

static void dump_stats_render_slab_cache_thrash_runs(void)
{
	unsigned int t;

	for (t = 0; t < NR_SLAB_TARGETS; t++) {
		if (shm->stats.slab_cache_thrash_runs[t] == 0)
			continue;
		stat_row("slab_cache_thrash", slab_target_name(t),
			 shm->stats.slab_cache_thrash_runs[t]);
	}
}

static void dump_stats_render_childop_pool_race_aborted(void)
{
	unsigned int op;
	char metric[40];

	for (op = 0; op < NR_CHILD_OP_TYPES; op++) {
		if (shm->stats.childop.pool_race_aborted[op] == 0)
			continue;
		snprintf(metric, sizeof(metric), "%s",
			 alt_op_name((enum child_op_type)op));
		stat_row("pool_race_aborted", metric,
			 shm->stats.childop.pool_race_aborted[op]);
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
static void dump_stats_render_childop_missing_producer(void)
{
	unsigned int op;
	char metric[40];

	for (op = CHILD_OP_SYSCALL + 1;
	     op < NR_CHILD_OP_TYPES; op++) {
		unsigned long inv =
			shm->stats.childop.invocations[op];
		if (inv == 0)
			continue;
		if (shm->stats.childop.setup_accepted[op] != 0)
			continue;
		snprintf(metric, sizeof(metric), "%s",
			 alt_op_name((enum child_op_type)op));
		stat_row("childop_missing_producer", metric, inv);
	}
}

/* Per-childop one-shot latch reason: rendered as the integer
 * enum childop_latch_reason code (see include/child.h).  No
 * string table is materialised at the dump layer -- the
 * operator decodes.  0 (CHILDOP_LATCH_NONE) is skipped so
 * the per-op dump only emits rows for ops that actually
 * latched themselves off.  CHILD_OP_SYSCALL is skipped for
 * the same reason as above. */
static void dump_stats_render_childop_latch_reason(void)
{
	unsigned int op;
	char metric[40];

	for (op = CHILD_OP_SYSCALL + 1;
	     op < NR_CHILD_OP_TYPES; op++) {
		unsigned long v =
			shm->stats.childop.latch_reason[op];
		if (v == 0)
			continue;
		snprintf(metric, sizeof(metric), "%s",
			 alt_op_name((enum child_op_type)op));
		stat_row("childop_latch_reason", metric, v);
	}
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
static void dump_stats_render_childop_would_demote(void)
{
	unsigned int op;
	char metric[40];

	for (op = CHILD_OP_SYSCALL + 1;
	     op < NR_CHILD_OP_TYPES; op++) {
		unsigned long v =
			shm->stats.childop.would_demote[op];
		if (v == 0)
			continue;
		snprintf(metric, sizeof(metric), "%s",
			 alt_op_name((enum child_op_type)op));
		stat_row("childop_would_demote", metric, v);
	}
}

static void dump_stats_render_childop_would_promote(void)
{
	unsigned int op;
	char metric[40];

	for (op = CHILD_OP_SYSCALL + 1;
	     op < NR_CHILD_OP_TYPES; op++) {
		unsigned long v =
			shm->stats.childop.would_promote[op];
		if (v == 0)
			continue;
		snprintf(metric, sizeof(metric), "%s",
			 alt_op_name((enum child_op_type)op));
		stat_row("childop_would_promote", metric, v);
	}
}

void dump_stats_childop_ranked_tables(void)
{
	dump_stats_render_childop_taint_transitions();
	dump_stats_render_childop_pool_race_aborted();
	dump_stats_render_childop_edges_discovered();
	dump_stats_render_childop_calls_with_edges();
	dump_stats_render_childop_last_success_ts();
	dump_stats_render_childop_setup_accepted();
	dump_stats_render_childop_data_path();
	dump_stats_render_childop_setup_bound_permille();
	dump_stats_render_childop_data_path_cold_permille();
	dump_stats_render_childop_missing_producer();
	dump_stats_render_childop_latch_reason();
	dump_stats_render_childop_would_demote();
	dump_stats_render_childop_would_promote();
	dump_stats_render_slab_cache_thrash_runs();
}
