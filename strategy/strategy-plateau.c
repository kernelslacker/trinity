/*
 * Plateau-intervention machinery: hypothesis classifier, rescue-bias
 * gate, anti-prior accept gate, wall-lever shadow suppression, and
 * the operator-facing intervention-mode name table.  Split from
 * strategy.c so the plateau code compiles independently of the
 * bandit / picker / frontier / cmp-novelty translation units.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "kcov.h"
#include "rnd.h"
#include "shm.h"
#include "stats.h"		/* stats_log_write */
#include "stats_ring.h"		/* parent_stats */
#include "strategy.h"
#include "syscall.h"		/* MAX_NR_SYSCALL */
#include "tables.h"		/* syscalls, max_nr_syscalls */

void strategy_plateau_response(void)
{
	/* Force the strategy picker to rotate on the next syscall dispatch
	 * so the intervention layer in select_next_strategy (returns
	 * STRATEGY_RANDOM with SR_PLATEAU_FORCE while plateau_active is set)
	 * takes effect within seconds rather than waiting up to
	 * STRATEGY_WINDOW (1UL << 17 = ~131K ops, ~65 sec at 2K iter/sec)
	 * for the natural rotation cadence.  Setting syscalls_at_last_switch to 0
	 * makes maybe_rotate_strategy trip on the next call from any child;
	 * the CAS guard there ensures only one child does the rotation work
	 * even though every child sees the trigger.  After this fires once,
	 * the field advances to op_count and the next forced rotation waits
	 * for the usual window — which is fine, because the intervention
	 * stays latched on plateau_active for as long as the plateau
	 * persists. */
	__atomic_store_n(&shm->syscalls_at_last_switch, 0UL, __ATOMIC_RELAXED);

	/* Arm the per-plateau-window snapshot the rule evaluator diffs
	 * against on every subsequent stats tick.  Called on the rising
	 * edge into plateau_active so the entry baseline reflects the
	 * counter values at the moment discovery actually stalled, not
	 * whatever they happened to be at the previous stats tick. */
	strategy_plateau_hypothesis_enter();
}

void plateau_snapshot_capture(struct plateau_window_snapshot *snap)
{
	unsigned int op, nr, nr_max;

	if (snap == NULL)
		return;

	memset(snap, 0, sizeof(*snap));

	if (kcov_shm != NULL) {
		snap->pc_edges = __atomic_load_n(&kcov_shm->coverage.distinct_edges,
						 __ATOMIC_RELAXED);
		snap->cmp_unique = __atomic_load_n(
			&kcov_shm->hints_flat.cmp_hints_unique_inserts, __ATOMIC_RELAXED);
		/* total_calls / remote_calls are read from parent_stats
		 * (drained from per-child stats_ring); kcov_shm->coverage.total_calls
		 * is reserved for the last_edge_at[] / last_efault_at[]
		 * stamp source and the cold-skip gap denominator only,
		 * kcov_shm->coverage.remote_calls is not bumped here.  See
		 * stats_ring.h. */
		snap->remote_calls = parent_stats.remote_calls;
		snap->total_calls = parent_stats.total_calls;

		/* Per-group new-edge attribution.  per_syscall_edges is a
		 * CALL-COUNT signal (a syscall that uncovers 50 distinct
		 * edges in one call bumps by 1, not 50 -- see the field
		 * comment in include/kcov.h) so the per-group sum here is
		 * the headline "how many CALLS in this group produced any
		 * new coverage" series.  The single-group-dominant rule
		 * compares per-group deltas against the total delta; both
		 * sides share the same units so the ratio is well-defined. */
		nr_max = max_nr_syscalls;
		if (nr_max > MAX_NR_SYSCALL)
			nr_max = MAX_NR_SYSCALL;
		for (nr = 0; nr < nr_max; nr++) {
			struct syscallentry *entry;
			unsigned int grp;
			unsigned long e;

			if (syscalls == NULL)
				break;
			entry = syscalls[nr].entry;
			if (entry == NULL)
				continue;
			grp = entry->group;
			if (grp >= NR_GROUPS)
				continue;
			e = per_syscall_edges_total(nr);
			snap->group_edges[grp] += e;
		}
	}

	snap->bandit_edges = __atomic_load_n(
		&shm->stats.picker_bandit.bandit_pool_edges_discovered, __ATOMIC_RELAXED);
	snap->explorer_edges = __atomic_load_n(
		&shm->stats.picker_bandit.explorer_pool_edges_discovered, __ATOMIC_RELAXED);
	snap->frontier_picks = __atomic_load_n(
		&shm->stats.frontier.core.strategy_picks, __ATOMIC_RELAXED);
	/* Bandit-side pulls + intervention-forced picks.  The bandit
	 * counter advances only on policy-chosen windows; the
	 * intervention counter advances only on SR_PLATEAU_FORCE
	 * windows that resolved to STRATEGY_COVERAGE_FRONTIER.  Their
	 * sum is "all rotations that selected the frontier arm",
	 * regardless of selection path.  Without the intervention
	 * term the plateau classifier's frontier_cold rule was
	 * structurally blind to intervention-driven frontier work --
	 * the bandit cannot pull the frontier arm during a plateau,
	 * so frontier_pulls stayed at 0 for the entire window and
	 * the rule's "pulls > 0 && picks == 0" predicate could never
	 * fire even when the intervention layer was already
	 * exercising the frontier picker. */
	snap->frontier_pulls = __atomic_load_n(
		&shm->bandit_pulls[STRATEGY_COVERAGE_FRONTIER],
		__ATOMIC_RELAXED) +
		__atomic_load_n(
			&shm->stats.frontier.core.intervention_pulls,
			__ATOMIC_RELAXED);
	snap->frontier_live_picks = __atomic_load_n(
		&shm->stats.frontier.core.live_picks, __ATOMIC_RELAXED);
	snap->frontier_silent_picks = __atomic_load_n(
		&shm->stats.frontier.core.silent_picks, __ATOMIC_RELAXED);

	for (op = 0; op < NR_CHILD_OP_TYPES; op++) {
		snap->childop_edges_total += __atomic_load_n(
			&shm->stats.childop.edges_discovered[op],
			__ATOMIC_RELAXED);
		snap->childop_calls_total += __atomic_load_n(
			&shm->stats.childop.calls_with_edges[op],
			__ATOMIC_RELAXED);
	}
}

void plateau_snapshot_delta(struct plateau_window_snapshot *out,
			    const struct plateau_window_snapshot *entry,
			    const struct plateau_window_snapshot *now)
{
	unsigned int grp;

	if (out == NULL || entry == NULL || now == NULL)
		return;

	out->pc_edges = sat_sub_ul(now->pc_edges, entry->pc_edges);
	out->cmp_unique = sat_sub_ul(now->cmp_unique, entry->cmp_unique);
	out->bandit_edges = sat_sub_ul(now->bandit_edges, entry->bandit_edges);
	out->explorer_edges = sat_sub_ul(now->explorer_edges,
					 entry->explorer_edges);
	out->childop_edges_total = sat_sub_ul(now->childop_edges_total,
					      entry->childop_edges_total);
	out->childop_calls_total = sat_sub_ul(now->childop_calls_total,
					      entry->childop_calls_total);
	out->remote_calls = sat_sub_ul(now->remote_calls, entry->remote_calls);
	out->total_calls = sat_sub_ul(now->total_calls, entry->total_calls);
	out->frontier_picks = sat_sub_ul(now->frontier_picks,
					 entry->frontier_picks);
	out->frontier_pulls = sat_sub_ul(now->frontier_pulls,
					 entry->frontier_pulls);
	out->frontier_live_picks = sat_sub_ul(now->frontier_live_picks,
					      entry->frontier_live_picks);
	out->frontier_silent_picks = sat_sub_ul(now->frontier_silent_picks,
						entry->frontier_silent_picks);
	for (grp = 0; grp < NR_GROUPS; grp++)
		out->group_edges[grp] = sat_sub_ul(now->group_edges[grp],
						   entry->group_edges[grp]);
}

/*
 * Plateau hypothesis classifier driver.
 *
 * Parent-private state: the tick driver only runs on the parent path
 * (called from print_stats()) so no atomics or locking are needed
 * for the file-local arrays below.  The publish path into
 * shm->plateau_current_hypothesis uses RELAXED atomics so consumer
 * gates in child.c and minicorpus.c read a consistent value -- see
 * the strategy.h consumer-contract block for the gates.
 *
 * hypothesis_entry_snap is captured once on the rising edge into
 * plateau_active and held until the matching falling edge.  Per-tick
 * deltas are diff'd against this snapshot rather than against the
 * previous tick so a rule that requires sustained signal (e.g.
 * cmp_unique delta of 1000+) trips on the cumulative growth across
 * the plateau window rather than racing with whatever the last tick
 * happened to capture.
 *
 * hypothesis_current is the rule that fired on the LAST tick; tracked
 * so we only stats_log_write on transitions (entry to FOO, FOO to BAR,
 * BAR to NONE) instead of every tick.  Long plateaus would otherwise
 * spam stats.log with one line per stats interval per hypothesis.
 */
static struct plateau_window_snapshot hypothesis_entry_snap;
static bool hypothesis_entry_armed;
static struct plateau_window_snapshot hypothesis_last_delta;
static enum plateau_hypothesis hypothesis_current = PLATEAU_HYPOTHESIS_NONE;
static unsigned long hypothesis_fires[NR_PLATEAU_HYPOTHESES];

const char *strategy_plateau_hypothesis_name(enum plateau_hypothesis h)
{
	switch (h) {
	case PLATEAU_HYPOTHESIS_NONE:
		return "NONE";
	case PLATEAU_HYPOTHESIS_CMP_RISING_PC_FLAT:
		return "cmp_rising_pc_flat";
	case PLATEAU_HYPOTHESIS_CHILDOP_DOMINANT:
		return "childop_dominant";
	case PLATEAU_HYPOTHESIS_REMOTE_DOMINANT:
		return "remote_dominant";
	case PLATEAU_HYPOTHESIS_FRONTIER_COLD:
		return "frontier_cold";
	case PLATEAU_HYPOTHESIS_SINGLE_GROUP_DOMINANT:
		return "single_group_dominant";
	case NR_PLATEAU_HYPOTHESES:
		break;	/* sentinel */
	}
	return "?";
}

/* Rule 1: cmp_unique still climbing while pc_edges is flat.
 *
 * Direct evidence the kernel is still emitting novel CMP records that
 * survive bloom + pool dedup, but those records aren't translating
 * into PC-edge coverage gains.  Either the cmp_hints consumer isn't
 * injecting the new constants effectively or the constants are
 * landing on argument slots the syscall doesn't validate against.
 * Either way the operator-meaningful signal is "CMP says progress,
 * PC says stalled". */
#define PHC_CMP_RISING_DELTA		1000UL
#define PHC_CMP_PC_RATIO		1000UL

/* Rule 2: childop alt-op invocations are out-discovering generic
 * syscall picks by 2:1 on the per-pool new-edge attribution.
 * generic_edges is (bandit_edges + explorer_edges) -- both pools
 * dispatch through CHILD_OP_SYSCALL exclusively, so the sum is the
 * non-alt-op denominator the rule needs.  Compared against the
 * childop_calls_total CALL count (not childop_edges_total): the
 * syscall-path counters on the RHS are bumped by 1 per productive
 * call, so the LHS must use the parallel call-count counter or a
 * single alt-op invocation that surfaces 10 edges biases the ratio
 * 10:1 against syscall picks and the rule over-fires. */
#define PHC_CHILDOP_DOMINANT_RATIO	2UL

/* Rule 3: KCOV_REMOTE_ENABLE share has outgrown inline KCOV by 2:1
 * AND the remote-mode delta is non-trivial (the rule only matters
 * when remote is actually contributing -- a kernel without remote
 * KCOV reports remote_calls == 0 forever and the ratio is
 * meaningless).  remote_calls is a SUBSET of total_calls (a call
 * with KCOV_REMOTE_ENABLE bumps both); inline = total - remote. */
#define PHC_REMOTE_DOMINANT_RATIO	2UL
#define PHC_REMOTE_DOMINANT_MIN		100UL

/* Rule 5: one syscall group accounts for more than 70% of the
 * fleet's per-syscall-edges delta.  Conservative: only fires when
 * the total per-group sum is non-trivial so a fresh plateau window
 * with two edges in one group doesn't immediately trip a 100%
 * single-group classification. */
#define PHC_SINGLE_GROUP_PCT		70UL
#define PHC_SINGLE_GROUP_MIN		50UL

enum plateau_hypothesis strategy_plateau_hypothesis_check(
		const struct plateau_window_snapshot *entry,
		const struct plateau_window_snapshot *now)
{
	struct plateau_window_snapshot delta;
	unsigned long generic_edges, total_group_edges, max_group, inline_calls;
	unsigned int grp;

	if (entry == NULL || now == NULL)
		return PLATEAU_HYPOTHESIS_NONE;

	plateau_snapshot_delta(&delta, entry, now);

	/* Rule 1: CMP climbing, PC flat.  delta is cumulative since
	 * plateau entry, so pc_edges == 0 was unsatisfiable for any
	 * non-trivial window; a cmp:pc ratio is duration-invariant. */
	if (delta.cmp_unique > PHC_CMP_RISING_DELTA &&
	    (delta.pc_edges == 0 ||
	     delta.cmp_unique / delta.pc_edges >= PHC_CMP_PC_RATIO))
		return PLATEAU_HYPOTHESIS_CMP_RISING_PC_FLAT;

	/* Rule 2: childop alt-ops dominate.  Call-count vs call-count;
	 * see PHC_CHILDOP_DOMINANT_RATIO comment for the unit rationale. */
	generic_edges = delta.bandit_edges + delta.explorer_edges;
	if (delta.childop_calls_total >
	    PHC_CHILDOP_DOMINANT_RATIO * generic_edges &&
	    delta.childop_calls_total > 0)
		return PLATEAU_HYPOTHESIS_CHILDOP_DOMINANT;

	/* Rule 3: remote KCOV dominates inline KCOV.  inline_calls is
	 * derived rather than stored to avoid carrying redundant state. */
	inline_calls = sat_sub_ul(delta.total_calls, delta.remote_calls);
	if (delta.remote_calls > PHC_REMOTE_DOMINANT_MIN &&
	    delta.remote_calls > PHC_REMOTE_DOMINANT_RATIO * inline_calls)
		return PLATEAU_HYPOTHESIS_REMOTE_DOMINANT;

	/* Rule 4: frontier cold.  The bandit selected the coverage-
	 * frontier arm at least once during the plateau window but the
	 * weighted-accept gate inside the picker rejected every
	 * candidate, so no frontier-weighted call ran.  The pulls > 0
	 * predicate is what makes this a real signal: without it the
	 * rule would also fire on plateaus where the bandit simply
	 * never pulled CFV (uninformative -- could be a policy
	 * accident, could be a starved arm), and the rule classifier
	 * would attribute "frontier cold" to windows that say nothing
	 * about the frontier picker's behaviour. */
	if (delta.frontier_pulls > 0 && delta.frontier_picks == 0)
		return PLATEAU_HYPOTHESIS_FRONTIER_COLD;

	/* Rule 5: single group dominates. */
	total_group_edges = 0;
	max_group = 0;
	for (grp = 0; grp < NR_GROUPS; grp++) {
		total_group_edges += delta.group_edges[grp];
		if (delta.group_edges[grp] > max_group)
			max_group = delta.group_edges[grp];
	}
	if (total_group_edges > PHC_SINGLE_GROUP_MIN &&
	    max_group * 100UL > PHC_SINGLE_GROUP_PCT * total_group_edges)
		return PLATEAU_HYPOTHESIS_SINGLE_GROUP_DOMINANT;

	return PLATEAU_HYPOTHESIS_NONE;
}

void strategy_plateau_hypothesis_enter(void)
{
	plateau_snapshot_capture(&hypothesis_entry_snap);
	hypothesis_entry_armed = true;
	memset(&hypothesis_last_delta, 0, sizeof(hypothesis_last_delta));
	hypothesis_current = PLATEAU_HYPOTHESIS_NONE;
}

void strategy_plateau_hypothesis_tick(void)
{
	struct plateau_window_snapshot now;
	enum plateau_hypothesis fired;

	if (kcov_shm == NULL)
		return;

	if (!__atomic_load_n(&kcov_shm->plateau_active, __ATOMIC_ACQUIRE)) {
		/* Plateau cleared: drop the entry snapshot so the next
		 * plateau gets a fresh baseline.  hypothesis_fires[] is
		 * NOT cleared -- the fire-count distribution is a
		 * cumulative across-plateau statistic. */
		if (hypothesis_entry_armed) {
			hypothesis_entry_armed = false;
			hypothesis_current = PLATEAU_HYPOTHESIS_NONE;
			memset(&hypothesis_last_delta, 0,
			       sizeof(hypothesis_last_delta));
		}
		/* Phase 2: publish the cleared hypothesis so the
		 * select_next_strategy pin-gate drops on the next
		 * rotation.  Done outside the entry_armed guard so a
		 * spurious tick after rearm-cancel (or before the first
		 * arm) still leaves shm in the NONE sentinel state. */
		__atomic_store_n(&shm->plateau_current_hypothesis,
				 (int)PLATEAU_HYPOTHESIS_NONE,
				 __ATOMIC_RELAXED);
		return;
	}

	/* Plateau detector fired before the orchestrator armed the entry
	 * snapshot (e.g. operator started under an existing plateau).
	 * Arm lazily so subsequent ticks see real deltas. */
	if (!hypothesis_entry_armed)
		strategy_plateau_hypothesis_enter();

	plateau_snapshot_capture(&now);
	plateau_snapshot_delta(&hypothesis_last_delta,
			       &hypothesis_entry_snap, &now);
	fired = strategy_plateau_hypothesis_check(&hypothesis_entry_snap, &now);

	if (fired != hypothesis_current) {
		if (fired != PLATEAU_HYPOTHESIS_NONE) {
			hypothesis_fires[fired]++;
			stats_log_write(
				"plateau hypothesis: %s fired (cmp_delta=+%lu/window pc_delta=+%lu/window childop_calls_delta=+%lu childop_edges_delta=+%lu generic_delta=+%lu remote_delta=+%lu/+%lu frontier_pulls=%lu frontier_picks=%lu frontier_live=%lu frontier_silent=%lu)\n",
				strategy_plateau_hypothesis_name(fired),
				hypothesis_last_delta.cmp_unique,
				hypothesis_last_delta.pc_edges,
				hypothesis_last_delta.childop_calls_total,
				hypothesis_last_delta.childop_edges_total,
				hypothesis_last_delta.bandit_edges +
				hypothesis_last_delta.explorer_edges,
				hypothesis_last_delta.remote_calls,
				hypothesis_last_delta.total_calls,
				hypothesis_last_delta.frontier_pulls,
				hypothesis_last_delta.frontier_picks,
				hypothesis_last_delta.frontier_live_picks,
				hypothesis_last_delta.frontier_silent_picks);
		} else {
			stats_log_write(
				"plateau hypothesis: NONE (no rule matched window deltas)\n");
		}
		hypothesis_current = fired;
	}

	/* Phase 2: publish the live hypothesis to shm on every tick (not
	 * just transitions) so a child that missed the transition tick
	 * still observes the current value on its next rotation. */
	__atomic_store_n(&shm->plateau_current_hypothesis,
			 (int)hypothesis_current, __ATOMIC_RELAXED);
}

enum plateau_hypothesis strategy_plateau_hypothesis_current(void)
{
	return hypothesis_current;
}

const struct plateau_window_snapshot *strategy_plateau_hypothesis_delta(void)
{
	return &hypothesis_last_delta;
}

unsigned long strategy_plateau_hypothesis_fires(enum plateau_hypothesis h)
{
	if (h < 0 || h >= NR_PLATEAU_HYPOTHESES)
		return 0;
	return hypothesis_fires[h];
}

bool plateau_rescue_bias_active_for(enum random_rescue_class c)
{
	if (c < 0 || c >= RRC_NR_CLASSES)
		return false;
	if (kcov_shm == NULL ||
	    !__atomic_load_n(&kcov_shm->plateau_active, __ATOMIC_ACQUIRE))
		return false;
	/* ACQUIRE-load current_strategy pairs with the RELEASE-store in
	 * maybe_rotate_strategy.  Callers reach this gate from paths that
	 * may not have done their own acquire (notably the explorer pool,
	 * which short-circuits past set_syscall_nr's hot-picker acquire),
	 * so fence here to guarantee the subsequent relaxed reads of
	 * current_selection_reason and plateau_rescue_amplified_class see
	 * the values the orchestrator published before the rotation. */
	(void)__atomic_load_n(&shm->current_strategy, __ATOMIC_ACQUIRE);
	if (__atomic_load_n(&shm->current_selection_reason, __ATOMIC_RELAXED) !=
	    SR_PLATEAU_FORCE)
		return false;
	return __atomic_load_n(&shm->plateau_rescue_amplified_class,
			       __ATOMIC_RELAXED) == (int)c;
}

/*
 * Anti-prior boost cap.  The acceptance formula is structured so a
 * syscall at the baseline mean accepts at 1/ANTI_PRIOR_MAX_BOOST,
 * cold-end saturates at full uniform acceptance (1.0), and over-picked
 * syscalls bottom out at 1/ANTI_PRIOR_MAX_BOOST^2.  8 keeps the cold-
 * end boost large enough to materially shift the picker's distribution
 * away from its learned priors during the intervention without
 * collapsing the rotation onto a single syscall whose calls=0 reading
 * reflects a genuine broken-in-this-kernel arm rather than picker
 * suppression.  The cap is the SOLE knob trinity exposes against the
 * "100x boost a stuck syscall" pathology the design comment in
 * include/strategy.h warns about.
 */
#define ANTI_PRIOR_MAX_BOOST 8UL

/*
 * Pre-computed threshold range for the rejection-sampling roll.  Held
 * as a literal so the inner-loop divides fold to a single shift on the
 * target ISA; ANTI_PRIOR_MAX_BOOST stays as the human-meaningful knob.
 */
#define ANTI_PRIOR_THRESHOLD_SCALE \
	(ANTI_PRIOR_MAX_BOOST * ANTI_PRIOR_MAX_BOOST)

bool plateau_anti_prior_active(void)
{
	if (kcov_shm == NULL ||
	    !__atomic_load_n(&kcov_shm->plateau_active, __ATOMIC_ACQUIRE))
		return false;
	/* ACQUIRE-load current_strategy pairs with the RELEASE-store in
	 * maybe_rotate_strategy.  Fenced here rather than relying on the
	 * caller because set_syscall_nr_random is also entered from the
	 * explorer path, which bypasses set_syscall_nr's hot-picker
	 * acquire.  Without this fence the subsequent relaxed reads of
	 * current_selection_reason and plateau_intervention_mode_current
	 * could disagree with the just-rotated strategy, e.g. masking an
	 * intended PIM_ANTI_PRIOR window or leaving stale intervention
	 * state visible after a plateau lifts. */
	(void)__atomic_load_n(&shm->current_strategy, __ATOMIC_ACQUIRE);
	if (__atomic_load_n(&shm->current_selection_reason, __ATOMIC_RELAXED) !=
	    SR_PLATEAU_FORCE)
		return false;
	return __atomic_load_n(&shm->plateau_intervention_mode_current,
			       __ATOMIC_RELAXED) == (int)PIM_ANTI_PRIOR;
}

bool plateau_anti_prior_accept(unsigned int nr)
{
	unsigned long baseline;
	uint8_t weight;

	if (nr >= MAX_NR_SYSCALL)
		return true;

	baseline = __atomic_load_n(&shm->plateau_anti_prior_baseline_calls,
				   __ATOMIC_RELAXED);
	/* No baseline yet -- the orchestrator has not selected an
	 * anti-prior rotation in this run.  Pass unconditionally so the
	 * picker degenerates to uniform until the cache is populated.
	 * Also covers the kcov_shm==NULL case: refresh_baseline writes
	 * baseline=0 on that path, so the gate short-circuits without
	 * needing a separate kcov_shm probe here. */
	if (baseline == 0)
		return true;

	/* Read the pre-computed acceptance weight.  Visibility of the
	 * weight table is guaranteed by the caller's prior ACQUIRE-load of
	 * current_strategy (via plateau_anti_prior_active), which pairs
	 * with the RELEASE-store in maybe_rotate_strategy that publishes
	 * every store refresh_baseline made on the rotation path.  See the
	 * weight-array comment in struct shm_s for the publish ordering
	 * contract.  The full inversion math (clamp / divide / cap) lives
	 * in plateau_anti_prior_refresh_baseline so the per-retry inner
	 * loop in set_syscall_nr_random reduces to one relaxed load, one
	 * modulo, and one compare. */
	weight = __atomic_load_n(&shm->plateau_anti_prior_accept_weight[nr],
				 __ATOMIC_RELAXED);

	return rnd_modulo_u32(ANTI_PRIOR_THRESHOLD_SCALE) < weight;
}

void plateau_anti_prior_refresh_baseline(void)
{
	unsigned long calls_snapshot[MAX_NR_SYSCALL];
	unsigned long sum = 0;
	unsigned int i;
	unsigned int nr_active;
	unsigned long baseline;
	unsigned long floor_calls, ceil_calls;

	if (kcov_shm == NULL) {
		__atomic_store_n(&shm->plateau_anti_prior_baseline_calls, 0UL,
				 __ATOMIC_RELAXED);
		return;
	}

	/* Sum per_syscall_calls across the full slot range.  Indexing by
	 * MAX_NR_SYSCALL (not max_nr_syscalls) matches the array
	 * dimension and keeps the snapshot stable across biarch builds
	 * where the per_syscall_calls slot is shared by both arches.
	 * O(MAX_NR_SYSCALL) walk on the rotation path, never on the hot
	 * pick path.  Snapshot each slot into calls_snapshot[] so the
	 * per-slot weight pass below reuses the same observation the
	 * baseline was computed from. */
	for (i = 0; i < MAX_NR_SYSCALL; i++) {
		calls_snapshot[i] = per_syscall_calls_total(i);
		sum += calls_snapshot[i];
	}

	/* Denominator is the count of CURRENTLY ACTIVE syscalls -- mirrors
	 * the (biarch ? nr_active_32 + nr_active_64 : nr_active_syscalls)
	 * pattern in no_syscalls_enabled() and wall_lever_refresh_baseline().
	 * The per_syscall_calls[] array is dimensioned for MAX_NR_SYSCALL
	 * (=1024) slots but only the active subset can ever contribute
	 * observation; dividing the sum by the full slot dimension deflates
	 * the mean by the dead-slot count, makes average-active syscalls
	 * look hot to the accept gate, and lets the per-syscall ceil clamp
	 * fire early.  A cold-start window with no active table yet leaves
	 * baseline=0; the picker gate's "baseline==0 short-circuit to pass"
	 * branch in plateau_anti_prior_accept covers that path. */
	if (biarch)
		nr_active = __atomic_load_n(&shm->nr_active_32bit_syscalls,
					    __ATOMIC_RELAXED) +
			    __atomic_load_n(&shm->nr_active_64bit_syscalls,
					    __ATOMIC_RELAXED);
	else
		nr_active = __atomic_load_n(&shm->nr_active_syscalls,
					    __ATOMIC_RELAXED);

	if (nr_active == 0) {
		__atomic_store_n(&shm->plateau_anti_prior_baseline_calls, 0UL,
				 __ATOMIC_RELAXED);
		return;
	}

	baseline = sum / nr_active;

	/* Publish at least 1 when the mean truncates to zero so the accept
	 * gate's "baseline=0 short-circuit to pass" branch only fires
	 * before any rotation has populated the cache, not when the fleet
	 * is genuinely too young for any syscall to have averaged a full
	 * call.  Without the floor a cold-start run that hit a plateau
	 * within its first MAX_NR_SYSCALL ops would have the anti-prior
	 * rotation silently degenerate to uniform pick. */
	if (baseline == 0 && sum > 0)
		baseline = 1;

	/* Pre-compute the per-syscall acceptance weights so the hot-path
	 * picker only does one load + modulo + compare per candidate.  The
	 * acceptance weight for each syscall slot is:
	 *
	 *   floor   = max(1, baseline / MAX_BOOST)
	 *   ceil    = baseline * MAX_BOOST
	 *   clamped = clamp(calls, floor, ceil)
	 *   weight  = min((MAX_BOOST * baseline) / clamped,
	 *                 ANTI_PRIOR_THRESHOLD_SCALE)
	 *
	 * calls[nr] is snapshotted here at rotation time rather than
	 * re-read on every candidate; an intervention window is short
	 * relative to the rate any single syscall's lifetime count can
	 * shift, and the statistical bias the gate imposes is keyed off
	 * the baseline-relative ratio, not the absolute call count.  The
	 * per-slot reads themselves are taken from calls_snapshot[]
	 * (filled in pass 1 above), so each slot's published weight is
	 * derived from the exact same observation that fed into the
	 * baseline - both passes see the same numbers and a concurrent
	 * mid-rotation increment can't skew one pass relative to the
	 * other.
	 *
	 * weight is bounded by ANTI_PRIOR_THRESHOLD_SCALE (= 64 today, =
	 * MAX_BOOST^2) and never zero, so the uint8_t slot is sufficient.
	 *
	 * The whole array is written under RELAXED ordering; visibility
	 * rides on the RELEASE-store of current_strategy that
	 * maybe_rotate_strategy emits after select_next_strategy returns,
	 * paired with the picker-side ACQUIRE-load inside
	 * plateau_anti_prior_active.  Mirrors the existing publish pattern
	 * for plateau_intervention_mode_current. */
	if (baseline > 0) {
		floor_calls = baseline / ANTI_PRIOR_MAX_BOOST;
		if (floor_calls == 0)
			floor_calls = 1;
		ceil_calls = baseline * ANTI_PRIOR_MAX_BOOST;

		for (i = 0; i < MAX_NR_SYSCALL; i++) {
			unsigned long calls, clamped, weight;

			calls = calls_snapshot[i];
			clamped = calls;
			if (clamped < floor_calls)
				clamped = floor_calls;
			else if (clamped > ceil_calls)
				clamped = ceil_calls;

			weight = (ANTI_PRIOR_MAX_BOOST * baseline) / clamped;
			if (weight > ANTI_PRIOR_THRESHOLD_SCALE)
				weight = ANTI_PRIOR_THRESHOLD_SCALE;

			__atomic_store_n(
				&shm->plateau_anti_prior_accept_weight[i],
				(uint8_t)weight, __ATOMIC_RELAXED);
		}
	}

	__atomic_store_n(&shm->plateau_anti_prior_baseline_calls, baseline,
			 __ATOMIC_RELAXED);
}

/*
 * Wall-lever shadow gate tunables.  The eligibility predicate
 * is "high calls, zero edges" measured against the fleet's current mean
 * per_syscall_calls, so the candidate set adapts to fleet state instead
 * of relying on a hardcoded denylist.
 *
 * WALL_LEVER_HIGH_MULT
 *     Multiplier on the fleet mean for the high-calls clause: a syscall
 *     qualifies only when calls_total >= MULT * baseline.  4 is enough
 *     to single out the dead-weight tail (mq_timedsend / io_destroy /
 *     munlockall / shmget / setsid / personality / unshare were all
 *     >4x mean per_syscall_calls in the run that motivated the lever)
 *     without sweeping up syscalls sitting at typical-active rates.
 * WALL_LEVER_MIN_FLOOR
 *     Absolute lower bound on calls_total before the predicate can
 *     fire, so a cold-start window where mean is still tiny does not
 *     have a fleet-of-three-calls syscall qualify against a 0.5 mean.
 *     Sized 1 step above KCOV_SAT_CAP_CALLS (200) so the wall lever
 *     is strictly downstream of the existing saturation cap -- a
 *     syscall this lever targets has already proven itself dead under
 *     the cap's own evidence floor.
 */
#define WALL_LEVER_HIGH_MULT	4UL
#define WALL_LEVER_MIN_FLOOR	((unsigned long)KCOV_SAT_CAP_CALLS + 1UL)

bool wall_lever_should_suppress_shadow(unsigned int nr)
{
	unsigned long baseline;

	if (kcov_shm == NULL || nr >= MAX_NR_SYSCALL)
		return false;
	/* ACQUIRE pairs with the parent's RELEASE-store of plateau_active in
	 * kcov_plateau_check(); the per-syscall byte the picker reads below
	 * is published under the rotation's RELEASE-store of current_strategy
	 * but plateau_active gates that entire publish, so an ACQUIRE here
	 * lets the gate degrade gracefully (return false) when the plateau
	 * detector is off and the suppress table is stale or never written. */
	if (!__atomic_load_n(&kcov_shm->plateau_active, __ATOMIC_ACQUIRE))
		return false;
	baseline = __atomic_load_n(&shm->wall_lever_baseline_calls,
				   __ATOMIC_RELAXED);
	if (baseline == 0)
		return false;
	return __atomic_load_n(&shm->wall_lever_suppress[nr],
			       __ATOMIC_RELAXED) != 0;
}

void wall_lever_refresh_baseline(void)
{
	unsigned long calls_snapshot[MAX_NR_SYSCALL];
	unsigned long edges_snapshot[MAX_NR_SYSCALL];
	unsigned long sum = 0;
	unsigned long baseline, qualify_at;
	unsigned int nr_active;
	unsigned int i;

	if (kcov_shm == NULL) {
		__atomic_store_n(&shm->wall_lever_baseline_calls, 0UL,
				 __ATOMIC_RELAXED);
		return;
	}

	/* Snapshot calls AND edges per slot, folding warm-loaded priors so
	 * the eligibility test fires on cross-session evidence the
	 * cold-skip path would otherwise have to re-accumulate from scratch
	 * every run (mirrors the prior-fold in kcov_syscall_cold_skip_pct
	 * for the same reason).  Each slot is snapshotted exactly once so
	 * the baseline sum below and the per-slot decision pass that
	 * follows are derived from the SAME observation; a concurrent
	 * mid-rotation bump cannot skew one pass relative to the other. */
	for (i = 0; i < MAX_NR_SYSCALL; i++) {
		unsigned long c, e;

		c = per_syscall_calls_total(i) +
		    per_syscall_calls_prior_total(i);
		e = per_syscall_edges_total(i) +
		    per_syscall_edges_prior_total(i);
		calls_snapshot[i] = c;
		edges_snapshot[i] = e;
		sum += c;
	}

	/* Denominator is the count of CURRENTLY ACTIVE syscalls -- mirrors
	 * the (biarch ? nr_active_32 + nr_active_64 : nr_active_syscalls)
	 * pattern in no_syscalls_enabled().  The per_syscall_calls[] array
	 * is dimensioned for MAX_NR_SYSCALL (=1024) slots but only the
	 * active subset can ever contribute observation; dividing the sum
	 * by the full slot dimension deflates the mean by the dead-slot
	 * count and silently lowers the WALL_LEVER_HIGH_MULT threshold
	 * below what the comment block above advertises.  A cold-start
	 * window with no active table yet leaves baseline=0; the picker's
	 * "baseline==0 -> not-suppressed" short-circuit in wall_lever_
	 * should_suppress_shadow covers that path. */
	if (biarch)
		nr_active = __atomic_load_n(&shm->nr_active_32bit_syscalls,
					    __ATOMIC_RELAXED) +
			    __atomic_load_n(&shm->nr_active_64bit_syscalls,
					    __ATOMIC_RELAXED);
	else
		nr_active = __atomic_load_n(&shm->nr_active_syscalls,
					    __ATOMIC_RELAXED);

	if (nr_active == 0) {
		__atomic_store_n(&shm->wall_lever_baseline_calls, 0UL,
				 __ATOMIC_RELAXED);
		return;
	}

	baseline = sum / nr_active;

	/* Publish at least 1 when the mean truncates to zero so the picker
	 * gate's "baseline==0 short-circuit to not-suppressed" branch only
	 * fires before any plateau-active rotation has populated the cache,
	 * not when the fleet is genuinely too young for any syscall to have
	 * averaged a full call.  Mirrors plateau_anti_prior_refresh_baseline's
	 * floor for the same reason. */
	if (baseline == 0 && sum > 0)
		baseline = 1;

	/* qualify_at is the integer threshold for the high-calls clause,
	 * hoisted out of the per-slot loop so the inner pass reduces to one
	 * compare + one zero-edges branch per slot.  WALL_LEVER_MIN_FLOOR
	 * keeps cold-start windows from flagging a tiny-mean fleet's
	 * single moderately-busy syscall; the max() between the two terms
	 * means whichever floor is currently tighter wins. */
	qualify_at = WALL_LEVER_HIGH_MULT * baseline;
	if (qualify_at < WALL_LEVER_MIN_FLOOR)
		qualify_at = WALL_LEVER_MIN_FLOOR;

	for (i = 0; i < MAX_NR_SYSCALL; i++) {
		uint8_t suppress = 0;

		if (baseline > 0 &&
		    edges_snapshot[i] == 0 &&
		    calls_snapshot[i] >= qualify_at)
			suppress = 1;
		__atomic_store_n(&shm->wall_lever_suppress[i], suppress,
				 __ATOMIC_RELAXED);
	}

	__atomic_store_n(&shm->wall_lever_baseline_calls, baseline,
			 __ATOMIC_RELAXED);
}

const char *plateau_intervention_mode_name(enum plateau_intervention_mode m)
{
	switch (m) {
	case PIM_UNIFORM_RANDOM:	return "UNIFORM_RANDOM";
	case PIM_ANTI_PRIOR:		return "ANTI_PRIOR";
	case PIM_RRC_BIASED:		return "RRC_BIASED";
	case PIM_COVERAGE_FRONTIER:	return "COVERAGE_FRONTIER";
	case NR_PIM_MODES:		break;	/* sentinel */
	}
	return "?";
}
