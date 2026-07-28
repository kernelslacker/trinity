/*
 * Strategy-window rotation gate: the SR_* rotation logic that decides
 * when a strategy window has expired, atomically claims the switch,
 * feeds the just-finished window into the bandit, selects the next
 * arm, and publishes the switch to the fleet.
 *
 * Carved out of strategy-accounting.c; the sibling seams (remote-
 * adaptive decide, per-syscall edge accounting, warm-cold reserve,
 * fd+group accounting) live in their own TUs under random_syscall/.
 *
 * maybe_rotate_strategy is cross-cluster private and declared in
 * random_syscall/strategy-accounting-internal.h.
 */

#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include "arch.h"	// biarch
#include "arg-decoder.h"
#include "child.h"
#include "cmp-frontier.h"
#include "cmp_hints.h"
#include "cred_throttle.h"
#include "debug.h"
#include "fd.h"
#include "kcov.h"
#include "locks.h"
#include "minicorpus.h"
#include "params.h"
#include "pids.h"
#include "pre_crash_ring.h"
#include "prop_ring.h"
#include "random.h"
#include "random-syscall-internal.h"
#include "reach-band.h"
#include "rnd.h"
#include "rotation_event.h"
#include "sequence.h"
#include "shm.h"
#include "signals.h"
#include "sanitise.h"
#include "stats.h"
#include "stats_ring.h"
#include "strategy-accounting-internal.h"
#include "strategy.h"
#include "syscall.h"
#include "syscall_record.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"
#include "utils-proc.h"

/*
 * Check the rotation boundary and, if crossed, atomically claim the
 * switch and update shm->current_strategy to whatever the configured
 * picker (round-robin or UCB1 bandit, see strategy.h) selects next.
 *
 * The rotation clock is shm_published->fleet_op_count, which mirrors
 * the parent-private fleet op_count (every child contributes ticks at
 * the same rate, including non-syscall alt-ops).  A child that observes
 * (op_count - syscalls_at_last_switch) >= STRATEGY_WINDOW tries to CAS
 * syscalls_at_last_switch forward to the current op_count; the CAS
 * winner performs the switch and emits the
 * stats line, the losers fall through and continue with the new strategy
 * on their next syscall pick.
 *
 * Per-strategy attribution: the just-finished window's call-count delta
 * is pc_edge_calls_by_strategy[prev] - pc_edge_calls_at_window_start and
 * the parallel real bucket-count delta is pc_edge_count_by_strategy[prev]
 * - pc_edge_count_at_window_start.  After the switch, both *at_window_start
 * snapshots are reseeded from the new strategy's current cumulative
 * counters, so the next switch will compute the deltas correctly even if
 * other strategies' counters are bumped during the grace period.
 */
void maybe_rotate_strategy(void)
{
	unsigned long now;
	unsigned long last;
	int prev, next;
	int prev_reason_raw;
	int prev_intervention_mode_raw;
	enum strategy_selection_reason prev_reason;
	enum strategy_selection_reason next_reason = SR_NORMAL_UCB;
	unsigned long calls_now, calls_in_window;
	unsigned long edges_now, edges_in_window;
	unsigned long syscalls_in_window;
	unsigned long cmp_now, cmp_in_window;
	unsigned long warn_now = 0;
	unsigned long warn_in_window = 0;
	bool was_chaos;

	/* Read fleet op_count off the parent-published mirror page; the
	 * canonical aggregate is parent-private and not visible to children.
	 * The mirror is republished once per parent main_loop iteration so
	 * a stale read here only delays the rotation by drain cadence. */
	now = (shm_published != NULL)
	      ? __atomic_load_n(&shm_published->fleet_op_count, __ATOMIC_RELAXED)
	      : 0;
	last = __atomic_load_n(&shm->syscalls_at_last_switch, __ATOMIC_RELAXED);

	/* Tighten the rotation window while the plateau detector is latched
	 * on, so the plateau-intervention layer (SR_PLATEAU_FORCE etc.) re-
	 * applies many times inside one 600s detector window rather than
	 * ~1.6 times.  ACQUIRE pairs with the parent's RELEASE-store of
	 * plateau_active in kcov_plateau_check(); kcov_shm may be NULL when
	 * kcov is disabled, fall back to the healthy-run cadence. */
	{
		unsigned long window = STRATEGY_WINDOW;

		if (kcov_shm != NULL &&
		    __atomic_load_n(&kcov_shm->plateau.plateau_active,
				    __ATOMIC_ACQUIRE))
			window = PLATEAU_STRATEGY_WINDOW;

		if (now - last < window)
			return;
	}

	if (!__atomic_compare_exchange_n(&shm->syscalls_at_last_switch,
					 &last, now,
					 false,
					 __ATOMIC_RELAXED, __ATOMIC_RELAXED))
		return;

	prev = __atomic_load_n(&shm->current_strategy, __ATOMIC_RELAXED);
	if (prev < 0 || prev >= NR_STRATEGIES)
		prev = STRATEGY_HEURISTIC;

	/* Selection reason for the just-finished window -- the intervention
	 * orchestrator stamped this when it picked prev.  Treated as raw int
	 * across the shm boundary and re-validated here so a wild write
	 * landing on the field falls back to the "policy chose this" path
	 * rather than skipping the learner update spuriously. */
	prev_reason_raw = __atomic_load_n(&shm->current_selection_reason,
					  __ATOMIC_RELAXED);
	switch (prev_reason_raw) {
	case SR_NORMAL_UCB:
	case SR_ROUND_ROBIN:
	case SR_COLD_START:
	case SR_PLATEAU_FORCE:
		prev_reason = (enum strategy_selection_reason)prev_reason_raw;
		break;
	default:
		prev_reason = SR_NORMAL_UCB;
		break;
	}

	/* Latch the plateau intervention mode BEFORE select_next_strategy
	 * publishes the next mode below.  Attribution rule: the numerator
	 * for the just-closing window belongs to the mode that was ACTIVE
	 * across it, i.e. the mode select_plateau_intervention_strategy
	 * stamped when this window was entered.  Reading current before
	 * select_next_strategy runs pins it to the closing-window mode; a
	 * concurrent parent republish cannot shift the attribution.
	 *
	 * Effective-mode attribution rides for free: mode_current is stored
	 * post-substitution at the pick site (a cold-ring FRONTIER window
	 * degrades to UNIFORM_RANDOM there), so a degraded FRONTIER window
	 * lands its outcomes under UNIFORM_RANDOM and matches the effective-
	 * mode denominator bumped in the same block.
	 *
	 * Held as int and range-checked so a wild write into the shm field
	 * skips the outcome update rather than corrupts adjacent arrays;
	 * only consumed under prev_reason == SR_PLATEAU_FORCE below. */
	prev_intervention_mode_raw = __atomic_load_n(
		&shm->plateau_intervention_mode_current, __ATOMIC_RELAXED);

	calls_now = __atomic_load_n(&shm->pc_edge_calls_by_strategy[prev],
				    __ATOMIC_RELAXED);
	calls_in_window = calls_now -
		__atomic_load_n(&shm->pc_edge_calls_at_window_start,
				__ATOMIC_RELAXED);
	edges_now = __atomic_load_n(&shm->pc_edge_count_by_strategy[prev],
				    __ATOMIC_RELAXED);
	edges_in_window = edges_now -
		__atomic_load_n(&shm->pc_edge_count_at_window_start,
				__ATOMIC_RELAXED);
	syscalls_in_window = now - last;

	/* CMP-novelty delta: number of comparison constants the active arm
	 * exposed for the first time within CMP_NOVELTY_DECAY_WINDOWS this
	 * window.  Folded into the bandit reward by bandit_record_pull as
	 * a 0.25-weight secondary signal so an arm whose PC growth has
	 * plateaued but whose validation surface is still mutating doesn't
	 * lose to a noisier arm on PC delta alone. */
	cmp_now = __atomic_load_n(&shm->bandit_cmp_new_constants[prev],
				  __ATOMIC_RELAXED);
	cmp_in_window = cmp_now -
		__atomic_load_n(&shm->bandit_cmp_at_window_start,
				__ATOMIC_RELAXED);

	/* Per-PIM-mode outcome accounting (observation-only substrate).
	 * When the just-closed window was an SR_PLATEAU_FORCE intervention,
	 * add its deltas to the numerator arrays that pair with
	 * plateau_intervention_mode_windows[].  Attribution uses the mode
	 * latched at the top of the close path (see comment there), and
	 * calls uses the raw op-count delta so the invariant
	 *
	 *   sum over m of plateau_intervention_mode_calls[m]
	 *     == total fleet ops elapsed while SR_PLATEAU_FORCE was active
	 *
	 * holds by construction.  No dependency on bandit_record_pull's
	 * per-arm learner exclusion of SR_PLATEAU_FORCE: mode outcomes are
	 * a separate diagnostic surface.  RELAXED writes, single-writer
	 * ordering piggybacks on the CAS above the same way the existing
	 * denominator does. */
	if (prev_reason == SR_PLATEAU_FORCE &&
	    prev_intervention_mode_raw >= 0 &&
	    prev_intervention_mode_raw < NR_PIM_MODES) {
		int pm = prev_intervention_mode_raw;

		__atomic_fetch_add(&shm->plateau_intervention_mode_calls[pm],
				   syscalls_in_window, __ATOMIC_RELAXED);
		__atomic_fetch_add(
			&shm->plateau_intervention_mode_pc_edge_calls[pm],
			calls_in_window, __ATOMIC_RELAXED);
		__atomic_fetch_add(
			&shm->plateau_intervention_mode_pc_edges[pm],
			edges_in_window, __ATOMIC_RELAXED);
		__atomic_fetch_add(
			&shm->plateau_intervention_mode_cmp_wins[pm],
			cmp_in_window, __ATOMIC_RELAXED);
	}

	/* WARN-fires delta + chaos-cohort snapshot for the chaos-mode V2
	 * attribution.  warn_now reads the live counter kmsg-monitor bumps
	 * on every classified kernel diagnostic; the at-window-start
	 * snapshot was reseeded at the bottom of the previous rotation (or
	 * is zero on the very first window).  was_chaos samples
	 * cmp_hints_chaos_active BEFORE cmp_hints_chaos_tick advances the
	 * schedule below, so it reflects the chaos state that was in effect
	 * across the just-finished window -- which is the cohort the delta
	 * should be attributed to.  Skipped when kcov_shm is NULL (kcov
	 * unavailable, no kmsg counter to read): the delta is zero and the
	 * cohort sample becomes a no-op for that window. */
	if (kcov_shm != NULL) {
		warn_now = __atomic_load_n(&kcov_shm->kmsg.kmsg_warn_fires,
					   __ATOMIC_RELAXED);
		warn_in_window = warn_now -
			__atomic_load_n(&shm->kmsg_warn_fires_at_window_start,
					__ATOMIC_RELAXED);
	} else {
		warn_in_window = 0UL;
	}
	was_chaos = cmp_hints_chaos_query();

	/* Feed the just-finished window into the bandit before asking
	 * the picker to choose the next arm, so UCB1 sees up-to-date
	 * pulls/reward when scoring.  The learner consumes the call-count
	 * delta as today; the real bucket-count delta is recorded into the
	 * parallel diagnostic reward series so the operator can compare the
	 * two reward shapes without changing the learner's behaviour.
	 * Round-robin mode ignores the counters but the bookkeeping is
	 * harmless and lets the end-of-run summary print pulls under either
	 * picker.
	 *
	 * Called on EVERY window including SR_PLATEAU_FORCE.  The
	 * per-arm-per-reason bucketing inside bandit_record_pull captures
	 * every cohort (forced included) so dump-side analysis can split
	 * each arm's exposure by selection path, while the learner-facing
	 * update (bandit_pulls[] / bandit_reward_calls[] / EMA) skips
	 * SR_PLATEAU_FORCE internally to keep the UCB scorer's view of
	 * RANDOM uncontaminated.  All other bookkeeping
	 * (bandit_window_count tick, frontier ring advance, window-start
	 * snapshot reseed) runs unconditionally -- those are coverage-side
	 * structures and must stay aligned with the rotation cadence. */
	bandit_record_pull(prev, prev_reason, calls_in_window,
			   edges_in_window, cmp_in_window,
			   warn_in_window, was_chaos);

	/* Tick the rotation counter so bandit_cmp_observe()'s per-syscall
	 * bloom decay sees the new window index on subsequent calls.
	 * Bumped after bandit_record_pull so a concurrent observer racing
	 * the rotation either sees the old (still-valid) window or the
	 * fresh one — both attribute correctly. */
	__atomic_fetch_add(&shm->bandit_window_count, 1UL, __ATOMIC_RELAXED);

	/* Roll the per-syscall frontier-edge ring forward and zero the new
	 * slot so it represents only edges discovered in the upcoming
	 * window.  Same K-window decay horizon as the CMP-novelty bloom
	 * above. */
	frontier_window_advance();

	/* Advance the cmp_hints chaos-mode window counter.  Flips the
	 * hint-suppression toggle on every CHAOS_WINDOW_MODULO'th window
	 * so random-arg generation gets a fair shot at the
	 * invalid-combination space that the kernel-validated cmp_hints
	 * pool otherwise biases away from. */
	cmp_hints_chaos_tick();

	next = select_next_strategy(prev, &next_reason);
	if (next < 0 || next >= NR_STRATEGIES) {
		next = (prev + 1) % NR_STRATEGIES;
		next_reason = SR_ROUND_ROBIN;
	}

	__atomic_store_n(&shm->pc_edge_calls_at_window_start,
			 __atomic_load_n(&shm->pc_edge_calls_by_strategy[next],
					 __ATOMIC_RELAXED),
			 __ATOMIC_RELAXED);
	__atomic_store_n(&shm->pc_edge_count_at_window_start,
			 __atomic_load_n(&shm->pc_edge_count_by_strategy[next],
					 __ATOMIC_RELAXED),
			 __ATOMIC_RELAXED);
	__atomic_store_n(&shm->bandit_cmp_at_window_start,
			 __atomic_load_n(&shm->bandit_cmp_new_constants[next],
					 __ATOMIC_RELAXED),
			 __ATOMIC_RELAXED);
	/* Reseed the transition reward window-start snapshots so the per-
	 * window delta bandit_record_pull reads on the next rotation
	 * matches the (next, this-window) cohort.  Same RELAXED cadence
	 * and single-writer ordering as the pc_edge_*_at_window_start
	 * pair above; consumed by bandit_record_pull under COMBINED mode
	 * (it folds (transition_edge_count_by_strategy[arm] - this
	 * snapshot) / TRANSITION_BANDIT_REWARD_WEIGHT_RECIPROCAL into the
	 * per-arm reward total).  Reseeded unconditionally so OFF/SHADOW_
	 * ONLY runs keep the snapshot fresh; COMBINED can be flipped on
	 * mid-run without the bandit reading a stale window-start. */
	__atomic_store_n(&shm->stats.transition_edge.count_at_window_start,
			 __atomic_load_n(&shm->stats.transition_edge.count_by_strategy[next],
					 __ATOMIC_RELAXED),
			 __ATOMIC_RELAXED);
	__atomic_store_n(&shm->stats.transition_edge.calls_at_window_start,
			 __atomic_load_n(&shm->stats.transition_edge.calls_by_strategy[next],
					 __ATOMIC_RELAXED),
			 __ATOMIC_RELAXED);
	/* Reseed the kmsg_warn_fires snapshot from the live counter (not a
	 * per-strategy mirror -- the underlying counter is global).  A
	 * future commit in this stack reads this snapshot at the top of the
	 * rotation handler to compute the per-window WARN delta and feeds
	 * it through bandit_record_pull for chaos cohort attribution.
	 * Reseeded under RELAXED matching the other *_at_window_start stores
	 * above; the snapshot tolerates a race between read and store
	 * because the delta is a coarse cohort-level signal, not a precise
	 * per-call attribution. */
	__atomic_store_n(&shm->kmsg_warn_fires_at_window_start,
			 kcov_shm != NULL ?
				 __atomic_load_n(&kcov_shm->kmsg.kmsg_warn_fires,
						 __ATOMIC_RELAXED) :
				 0UL,
			 __ATOMIC_RELAXED);
	/* Publish the selection reason BEFORE current_strategy: the RELEASE
	 * store on current_strategy below pairs with the picker's and the
	 * plateau gates' ACQUIRE loads of current_strategy, making the
	 * reason and the companion plateau fields (published earlier under
	 * RELAXED in select_next_strategy) visible to any child that
	 * observes the new strategy. */
	__atomic_store_n(&shm->current_selection_reason,
			 (int)next_reason, __ATOMIC_RELAXED);
	__atomic_store_n(&shm->current_strategy, next, __ATOMIC_RELEASE);

	output(0, "strategy: switched to %s (%d) [%s] (prev %s (%d) [%s]: edge_calls=%lu, edge_count=%lu, syscalls=%lu, cmp_novel=%lu%s)\n",
	       strategy_name(next), next,
	       strategy_selection_reason_name(next_reason),
	       strategy_name(prev), prev,
	       strategy_selection_reason_name(prev_reason),
	       calls_in_window, edges_in_window, syscalls_in_window,
	       cmp_in_window,
	       prev_reason == SR_PLATEAU_FORCE ?
	       ", learner-update skipped" : "");

	/* Durable per-rotation-block event: one JSONL record per closed
	 * window, assembled from the counters we already loaded above.
	 * Emitted AFTER the RELEASE-store of current_strategy so a
	 * reader that observes the record has also seen the corresponding
	 * next-arm publish -- an offline consumer joining records to
	 * subsequent per-arm coverage does not race the publish.
	 *
	 * pim_mode: reported as -1 for non-intervention windows to keep
	 * the per-block schema stable; matches the "only SR_PLATEAU_FORCE
	 * windows attribute to the per-PIM numerator arrays" contract in
	 * the outcome-accounting block above.
	 *
	 * plateau_active reads through kcov_shm and tolerates a NULL
	 * kcov_shm (kcov disabled) by reporting false -- same tolerant
	 * shape as the window-tightening load at the top of this function. */
	{
		struct rotation_event ev;

		ev.t_close_mono_ns = mono_ns();
		ev.start_mono_ns = shm->start_mono_ns;
		ev.op_count_start = last;
		ev.op_count_end = now;
		ev.syscalls_in_window = syscalls_in_window;
		ev.strategy_prev = prev;
		ev.strategy_next = next;
		ev.selection_reason_prev = (int)prev_reason;
		ev.selection_reason_next = (int)next_reason;
		ev.pim_mode = (prev_reason == SR_PLATEAU_FORCE &&
			       prev_intervention_mode_raw >= 0 &&
			       prev_intervention_mode_raw < NR_PIM_MODES)
			? prev_intervention_mode_raw : -1;
		ev.pc_edge_calls_in_window = calls_in_window;
		ev.pc_edges_in_window = edges_in_window;
		ev.cmp_wins_in_window = cmp_in_window;
		ev.warn_fires_in_window = warn_in_window;
		ev.was_chaos = was_chaos;
		ev.plateau_active = (kcov_shm != NULL) &&
			__atomic_load_n(&kcov_shm->plateau.plateau_active,
					__ATOMIC_RELAXED);
		ev.distinct_edges_now = (kcov_shm != NULL) ?
			__atomic_load_n(&kcov_shm->coverage.distinct_edges,
					__ATOMIC_RELAXED) : 0UL;

		stats_rotation_event_emit(&ev);
	}
}
