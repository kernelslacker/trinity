/*
 * Per-op outcome snapshotting, the per-window outcome dump and the
 * ranked score-dump tables emitted at shutdown.  Split out of
 * child-altop.c so the shadow-only score derivation compiles
 * separately from the picker/dormancy machinery and the alt-op
 * dispatch table.
 *
 * Every function here is telemetry-only: no scheduler / canary picker
 * / promotion / demotion path reads the numbers this file produces.
 * The score-row helpers stay file-static since they exist purely to
 * factor childop_score_dump's rendering; no other TU consumes them.
 */


#include <string.h>
#include "child.h"
#include "child-internal.h"
#include "params.h"
#include "rnd.h"
#include "shm.h"
#include "stats.h"
#include "strategy.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/socket.h"
#include "kernel/mount.h"
#include "kernel/if_packet.h"

/*
 * Aggregated per-childop outcome record (see struct childop_outcome in
 * include/child.h for the field contract).  Snapshots existing shm
 * counters into one coherent view so downstream policy units (clean /
 * noisy scores, WOULD-DEMOTE recommendations) consume a single record
 * instead of scraping a dozen parallel arrays.
 *
 * Telemetry-only: no scheduler decision currently reads this snapshot.
 * Fields whose producer is not yet wired stay at 0 / false; the
 * subtraction-derived slots clamp at zero because the source counters
 * race under multi-producer RELAXED updates and a few childops bump
 * setup_accepted more than once per dispatch (the existing setup-yield
 * permille dump in dump_stats() clamps for the same reason).
 */
void childop_outcome_snapshot(enum child_op_type op,
			      struct childop_outcome *out)
{
	unsigned long invocations, setup_accepted, discovered, clean;

	memset(out, 0, sizeof(*out));
	out->op = op;

	if (op >= NR_CHILD_OP_TYPES)
		return;

	invocations = __atomic_load_n(&shm->stats.childop.invocations[op],
				      __ATOMIC_RELAXED);
	setup_accepted = __atomic_load_n(&shm->stats.childop.setup_accepted[op],
					 __ATOMIC_RELAXED);
	discovered = __atomic_load_n(&shm->stats.childop.edges_discovered[op],
				     __ATOMIC_RELAXED);
	clean = __atomic_load_n(&shm->stats.childop.edges_clean[op],
				__ATOMIC_RELAXED);

	out->clean_edges = clean;
	out->noisy_edges = sat_sub_ul(discovered, clean);
	out->wall_ns = __atomic_load_n(&shm->stats.childop.wall_ns[op],
				       __ATOMIC_RELAXED);
	out->wedges = (uint32_t)__atomic_load_n(
			&shm->stats.childop.wedge_count[op], __ATOMIC_RELAXED);
	out->timeout_observed = (uint32_t)__atomic_load_n(
			&shm->stats.childop.timeout_observed[op], __ATOMIC_RELAXED);
	out->timeout_missed = (uint32_t)__atomic_load_n(
			&shm->stats.childop.timeout_missed[op], __ATOMIC_RELAXED);
	out->setup_failures = (invocations > setup_accepted)
		? (uint32_t)(invocations - setup_accepted) : 0;
	out->taint_transition = __atomic_load_n(
			&shm->stats.childop.taint_transitions[op], __ATOMIC_RELAXED) > 0;
}

void childop_outcome_window_dump(void)
{
	enum child_op_type op;

	for (op = CHILD_OP_SYSCALL + 1; op < NR_CHILD_OP_TYPES; op++) {
		struct childop_outcome rec;
		unsigned long invocations, latch;

		invocations = __atomic_load_n(
				&shm->stats.childop.invocations[op],
				__ATOMIC_RELAXED);
		if (invocations == 0)
			continue;

		childop_outcome_snapshot(op, &rec);
		latch = __atomic_load_n(
				&shm->stats.childop.latch_reason[op],
				__ATOMIC_RELAXED);

		output(1,
		       "childop_window %s: invocations=%lu wall_ns=%lu clean_edges=%lu noisy_edges=%lu wedges=%u crashes=%u setup_failures=%u timeout_observed=%u timeout_missed=%u latch=%lu\n",
		       alt_op_name(op), invocations,
		       (unsigned long)rec.wall_ns,
		       (unsigned long)rec.clean_edges,
		       (unsigned long)rec.noisy_edges,
		       rec.wedges, rec.crashes, rec.setup_failures,
		       rec.timeout_observed, rec.timeout_missed, latch);
	}
}

/*
 * Derived utility + penalty scores from struct childop_outcome (see
 * include/child.h for the field contract), surfaced as two ranked
 * tables.  The score derivation is shadow-only: no scheduler / canary
 * picker / promotion / demotion path reads these numbers; the function
 * snapshots shm, computes, and emits via output(1, ...) -- nothing
 * else.
 *
 * clean_score = clean_edges * SCALE / wall_ns -- good-utility, i.e.
 * canary-path edges per nanosecond of wall time, scaled up by SCALE so
 * the ratio fits in an integer (edges-per-second when SCALE=1e9 and
 * wall_ns is in nanoseconds).  noisy_score is the same shape over
 * noisy_edges.  Both clamp to 0 when wall_ns is 0 (an op that has
 * never run yet).
 *
 * bad_score sums the wedge / dstate / crash / setup-failure /
 * asan-failure accumulators.  These have producers today, so the
 * bad-utility table surfaces immediately.
 *
 * Under __SANITIZE_ADDRESS__ a third "asan" table is emitted that
 * re-weights bad_score against the failure classes whose runtime cost
 * is several times higher in an ASAN build, and pairs each row with a
 * one-third wall-time budget hint (ASAN runs typically take 2-3x the
 * walltime per syscall).  Class detection reads only existing
 * childop_outcome fields, so no hardcoded childop list is needed and
 * the weighting tracks observed behaviour rather than a hand-curated
 * deny-list:
 *
 *   asan_runtime_failure         -> poisoning CHECK abort (weight x8)
 *   setup_failures > 0           -> allocator / mmap reservation fail
 *                                   against the shadow steal (x3)
 *   wedges && clean_edges == 0   -> no-return-from-sigaltstack, the
 *                                   child wedged without producing
 *                                   any canary edge (per-wedge x4)
 *
 * The non-ASAN weights for wedge / dstate / crash / setup-failure are
 * 1 / 1 / 1 / 1 (matching bad_score); the ASAN profile is strictly an
 * additive re-weight on top.  Under a non-ASAN build this entire
 * compute-and-emit block is omitted, the bad_score table is unchanged,
 * and there is no behavioural difference from before this commit.
 */
#define CHILDOP_SCORE_SCALE	1000000000ULL
#define CHILDOP_SCORE_TOPN	10

/*
 * Wall-normalized utility kill-list thresholds.  An op is flagged
 * "would_demote_utility" when its clean_score (clean_edges * SCALE /
 * wall_ns -- i.e. clean edges per wall second) sits below FLOOR and it
 * has consumed at least WALL_MIN nanoseconds of cumulative child time.
 * The two halves are needed together: the floor on its own would flag
 * ops that have barely run (a few hundred ns, no edges yet), and the
 * wall-min on its own would flag the most productive long-running ops.
 *
 * Start conservative.  FLOOR=100 captures only ops producing fewer
 * than ~100 clean edges per wall second -- well below typical altop
 * yields, so a healthy op won't appear.  WALL_MIN=5s of accumulated
 * wall time keeps newly-unblocked ops off the list until they've had
 * a fair sample.  Telemetry-only: nothing reads either macro at
 * runtime, the score dump is the sole consumer.
 */
#define CHILDOP_UTIL_FLOOR	100UL
#define CHILDOP_UTIL_WALL_MIN	5000000000ULL

#ifdef __SANITIZE_ADDRESS__
#define CHILDOP_ASAN_W_WEDGE_NOEDGE	4UL
#define CHILDOP_ASAN_W_CRASH		2UL
#define CHILDOP_ASAN_W_SETUP_FAIL	3UL
#define CHILDOP_ASAN_W_RUNTIME_FAIL	8UL
#define CHILDOP_ASAN_WALL_BUDGET_DIV	3ULL
#endif

/*
 * Row descriptor populated by score_row_compute() and consumed by
 * score_sort_desc() / score_render_top() when childop_score_dump()
 * emits its per-op ranking tables.
 */
struct score_row {
	enum child_op_type op;
	uint64_t clean_score;
	uint64_t noisy_score;
	uint64_t good_score;
	unsigned long bad_score;
	uint64_t clean_edges;
	uint64_t noisy_edges;
	uint64_t wall_ns;
	uint64_t wall_per_clean_edge;
	unsigned long long wedge_wall_us;
	unsigned int wedges;
	unsigned int dstate_wedges;
	unsigned int crashes;
	unsigned int setup_failures;
	bool asan_runtime_failure;
	bool would_demote_utility;
#ifdef __SANITIZE_ADDRESS__
	unsigned long asan_bad_score;
	uint64_t asan_wall_budget_ns;
#endif
};

static uint64_t score_key_good(const struct score_row *r) { return r->good_score; }
static uint64_t score_key_bad(const struct score_row *r) { return r->bad_score; }
static uint64_t score_key_util(const struct score_row *r) { return r->wall_per_clean_edge; }
#ifdef __SANITIZE_ADDRESS__
static uint64_t score_key_asan(const struct score_row *r) { return r->asan_bad_score; }
#endif

static void score_emit_good(const struct score_row *r)
{
	output(1,
	       "childop_score_good %s: clean_score=%lu noisy_score=%lu clean_edges=%lu noisy_edges=%lu wall_ns=%lu\n",
	       alt_op_name(r->op),
	       (unsigned long)r->clean_score,
	       (unsigned long)r->noisy_score,
	       (unsigned long)r->clean_edges,
	       (unsigned long)r->noisy_edges,
	       (unsigned long)r->wall_ns);
}

static void score_emit_bad(const struct score_row *r)
{
	output(1,
	       "childop_score_bad %s: wedges=%u dstate_wedges=%u crashes=%u setup_failures=%u asan_runtime_failure=%d total=%lu\n",
	       alt_op_name(r->op),
	       r->wedges, r->dstate_wedges,
	       r->crashes, r->setup_failures,
	       r->asan_runtime_failure ? 1 : 0,
	       r->bad_score);
}

static void score_emit_util(const struct score_row *r)
{
	output(1,
	       "childop_score_util %s: clean_score=%lu wall_per_clean_edge=%lu wedge_wall_us=%llu clean_edges=%lu wall_ns=%lu would_demote_utility=%d\n",
	       alt_op_name(r->op),
	       (unsigned long)r->clean_score,
	       (unsigned long)r->wall_per_clean_edge,
	       r->wedge_wall_us,
	       (unsigned long)r->clean_edges,
	       (unsigned long)r->wall_ns,
	       r->would_demote_utility ? 1 : 0);
}

#ifdef __SANITIZE_ADDRESS__
static void score_emit_asan(const struct score_row *r)
{
	output(1,
	       "childop_score_asan %s: wedges=%u dstate_wedges=%u crashes=%u setup_failures=%u asan_runtime_failure=%d clean_edges=%lu wall_budget_ns=%lu total=%lu\n",
	       alt_op_name(r->op),
	       r->wedges, r->dstate_wedges,
	       r->crashes, r->setup_failures,
	       r->asan_runtime_failure ? 1 : 0,
	       (unsigned long)r->clean_edges,
	       (unsigned long)r->asan_wall_budget_ns,
	       r->asan_bad_score);
}
#endif

/*
 * Snapshot one op and derive its scoring row.  Returns false when the
 * op had no invocations and the caller should skip it entirely.
 */
static bool score_row_compute(enum child_op_type op, struct score_row *r)
{
	struct childop_outcome rec;
	unsigned long invocations;

	invocations = __atomic_load_n(
			&shm->stats.childop.invocations[op],
			__ATOMIC_RELAXED);
	if (invocations == 0)
		return false;

	childop_outcome_snapshot(op, &rec);

	r->op = op;
	/* __uint128_t intermediate so a long-running op whose
	 * cumulative edge count approaches UINT64_MAX / SCALE
	 * does not overflow the multiply before the divide. */
	r->clean_score = rec.wall_ns ?
		(uint64_t)(((__uint128_t)rec.clean_edges *
			    CHILDOP_SCORE_SCALE) / rec.wall_ns) : 0;
	r->noisy_score = rec.wall_ns ?
		(uint64_t)(((__uint128_t)rec.noisy_edges *
			    CHILDOP_SCORE_SCALE) / rec.wall_ns) : 0;
	r->good_score = r->clean_score + r->noisy_score;
	r->bad_score = (unsigned long)rec.wedges + rec.dstate_wedges +
		       rec.crashes + rec.setup_failures +
		       (rec.asan_runtime_failure ? 1UL : 0UL);
	r->clean_edges = rec.clean_edges;
	r->noisy_edges = rec.noisy_edges;
	r->wall_ns = rec.wall_ns;
	/* Wall-normalized utility view.  When clean_edges == 0 the
	 * ratio is undefined, so surface the raw wall_ns instead --
	 * a "spent N ns, produced no edges at all" signal is the
	 * worst-case utility outcome and should sort to the top
	 * rather than being silently zeroed. */
	r->wall_per_clean_edge = rec.clean_edges ?
		(rec.wall_ns / rec.clean_edges) : rec.wall_ns;
	r->wedge_wall_us = __atomic_load_n(
			&shm->stats.childop.wedge_total_us[op],
			__ATOMIC_RELAXED);
	r->would_demote_utility =
		(r->clean_score < CHILDOP_UTIL_FLOOR) &&
		(rec.wall_ns >= CHILDOP_UTIL_WALL_MIN);
	r->wedges = rec.wedges;
	r->dstate_wedges = rec.dstate_wedges;
	r->crashes = rec.crashes;
	r->setup_failures = rec.setup_failures;
	r->asan_runtime_failure = rec.asan_runtime_failure;

#ifdef __SANITIZE_ADDRESS__
	{
		unsigned long wedge_w = (rec.clean_edges == 0)
			? CHILDOP_ASAN_W_WEDGE_NOEDGE : 1UL;
		r->asan_bad_score =
			(unsigned long)rec.wedges * wedge_w +
			rec.dstate_wedges +
			(unsigned long)rec.crashes *
				CHILDOP_ASAN_W_CRASH +
			(unsigned long)rec.setup_failures *
				CHILDOP_ASAN_W_SETUP_FAIL +
			(rec.asan_runtime_failure
				? CHILDOP_ASAN_W_RUNTIME_FAIL : 0UL);
		r->asan_wall_budget_ns =
			rec.wall_ns / CHILDOP_ASAN_WALL_BUDGET_DIV;
	}
#endif

	return true;
}

/*
 * Insertion sort descending by the caller-supplied key.  nrows is
 * bounded by NR_CHILD_OP_TYPES (~60), so O(n^2) is fine.
 */
static void score_sort_desc(struct score_row *rows, unsigned int nrows,
			    uint64_t (*key)(const struct score_row *))
{
	unsigned int i, j;

	for (i = 1; i < nrows; i++) {
		struct score_row tmp = rows[i];
		for (j = i; j > 0 && key(&rows[j - 1]) < key(&tmp); j--)
			rows[j] = rows[j - 1];
		rows[j] = tmp;
	}
}

/*
 * Emit up to CHILDOP_SCORE_TOPN rows via the caller-supplied emitter,
 * stopping once the key value drops to zero.  Assumes the caller has
 * already sorted rows[] descending by the same key.
 */
static void score_render_top(const struct score_row *rows, unsigned int nrows,
			     uint64_t (*key)(const struct score_row *),
			     void (*emit)(const struct score_row *))
{
	unsigned int i, n;

	n = nrows < CHILDOP_SCORE_TOPN ? nrows : CHILDOP_SCORE_TOPN;
	for (i = 0; i < n && key(&rows[i]) > 0; i++)
		emit(&rows[i]);
}

void childop_score_dump(void)
{
	struct score_row rows[NR_CHILD_OP_TYPES];
	unsigned int nrows = 0;
	enum child_op_type op;
	bool any_good = false, any_bad = false, any_util = false;
#ifdef __SANITIZE_ADDRESS__
	bool any_asan = false;
#endif

	for (op = CHILD_OP_SYSCALL + 1; op < NR_CHILD_OP_TYPES; op++) {
		struct score_row *r = &rows[nrows];

		if (!score_row_compute(op, r))
			continue;
		nrows++;

		if (r->good_score > 0)
			any_good = true;
		if (r->bad_score > 0)
			any_bad = true;
		if (r->wall_per_clean_edge > 0)
			any_util = true;
#ifdef __SANITIZE_ADDRESS__
		if (r->asan_bad_score > 0)
			any_asan = true;
#endif
	}

	if (nrows == 0)
		return;

	if (any_good) {
		score_sort_desc(rows, nrows, score_key_good);
		score_render_top(rows, nrows, score_key_good, score_emit_good);
	}

	if (any_bad) {
		score_sort_desc(rows, nrows, score_key_bad);
		score_render_top(rows, nrows, score_key_bad, score_emit_bad);
	}

	/*
	 * Wall-normalized utility table.  Ranks ops by ns spent per
	 * clean edge produced (descending) so the least-productive
	 * consumers of child wall time -- typically the wedge-prone
	 * stress ops -- surface at the top.  would_demote_utility flags
	 * the rows that meet both the floor and wall-min thresholds; it
	 * is informational, no demote actually fires.
	 */
	if (any_util) {
		score_sort_desc(rows, nrows, score_key_util);
		score_render_top(rows, nrows, score_key_util, score_emit_util);
	}

#ifdef __SANITIZE_ADDRESS__
	if (any_asan) {
		score_sort_desc(rows, nrows, score_key_asan);
		score_render_top(rows, nrows, score_key_asan, score_emit_asan);
	}
#endif
}
