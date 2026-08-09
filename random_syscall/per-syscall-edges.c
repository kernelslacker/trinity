/*
 * Per-syscall edge attribution + per-dispatch cohort denominators.
 * Post-collect bookkeeping ran once per dispatch by dispatch_step:
 *   - account_reexec_ab_cohort:      re-exec A/B cohort denominators
 *                                    (parent CMP call, per-fork arm)
 *   - account_per_syscall_new_edges: per-syscall edge attribution
 *                                    + frontier yield / kill-list
 *                                    feedstock accounting
 *   - account_pc_edge_only:          PC-edge-only bookkeeping
 *                                    (snapshot cadence, per-strategy
 *                                    attribution, random-rescue class)
 *   - account_transition_reward:     per-strategy transition-reward
 *                                    attribution
 *
 * Carved out of strategy-accounting.c; the sibling seams (rotation,
 * remote-adaptive decide, warm-cold reserve, fd+group accounting)
 * live in their own TUs under random_syscall/.
 *
 * All entry points are cross-cluster private and declared in
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

/* A/B cohort denominators for the reexec_* lift signal.
 * This is the parent CMP call: every CMP-mode child reaches
 * here exactly once per dispatch, and child->redqueen_enabled
 * is the stable per-fork stamp that partitions CMP-mode
 * children 50/50 into the enabled vs control arms.  Bumping
 * once per parent call (and accumulating new_cmp into the
 * matching cohort sum) gives the missing denominator the
 * existing reexec_* numerator counters need so the per-
 * parent-call lift question is answerable from the periodic
 * dump.  Bump unconditionally on the cohort path -- even a
 * parent call that returned new_cmp == 0 is a parent-call
 * the re-exec gate could have sampled, so excluding it would
 * bias the denominator. */
void account_reexec_ab_cohort(struct childdata *child, unsigned long new_cmp)
{
	if (kcov_shm == NULL)
		return;

	if (child->redqueen_enabled) {
		__atomic_fetch_add(&kcov_shm->cmp_parent.cmp_parent_calls_enabled,
				   1UL, __ATOMIC_RELAXED);
		if (new_cmp > 0)
			__atomic_fetch_add(
				&kcov_shm->cmp_parent.cmp_parent_new_cmps_enabled,
				new_cmp, __ATOMIC_RELAXED);
	} else {
		__atomic_fetch_add(&kcov_shm->cmp_parent.cmp_parent_calls_control,
				   1UL, __ATOMIC_RELAXED);
		if (new_cmp > 0)
			__atomic_fetch_add(
				&kcov_shm->cmp_parent.cmp_parent_new_cmps_control,
				new_cmp, __ATOMIC_RELAXED);
	}
}

/* Per-syscall new-edge attribution split by strategy pool, plus the
 * companion frontier-yield (kill-list feedstock) accounting.  Both
 * blocks key off rec->nr / new_edge_count / frontier_pick_regime and
 * neither touches kcov_shm, so they collapse into a single helper that
 * runs immediately after the kcov-collect path.  Behaviour is the
 * sequential composition of the two original blocks.
 *
 * First block (strategy-pool split):
 *   Skipped when the call produced no new edges (the dump only
 *   consumes the positive delta side) and when rec->nr falls outside
 *   the table.  Biarch attribution follows the same raw-rec->nr
 *   indexing the existing kcov_shm->per_syscall.per_syscall_edges array uses; the
 *   dump iterates only the active 64-bit table when biarch, so 32-bit
 *   calls are effectively ignored there as they are everywhere else.
 *
 * Second block (frontier-yield kill-list feedstock):
 *   Reads the per-call frontier_pick_regime stamp the picker wrote at
 *   one of the two coverage-frontier accept sites; non-frontier
 *   strategy picks leave the stamp at NONE and naturally skip this
 *   whole block.  The decision is keyed off the live new_edge_count
 *   count -- a frontier pick that earned at least one PC edge bumps
 *   the regime-agnostic productive_wins counter and stamps the current
 *   rotation window into frontier_last_productive_window so the kill-
 *   list analyser can read "windows since last productive frontier
 *   pick on this syscall" without retaining a per-window time series;
 *   a LIVE-regime frontier pick that earned zero edges bumps the
 *   live_misses counter, the headline kill-list signal for "the live
 *   ring keeps biasing toward this syscall but it never converts".
 *   Silent-regime misses are NOT tallied -- silent picks are by
 *   definition operating in the plateau-fallback regime where low
 *   yield is the expected baseline and folding them into the same
 *   counter would bury the live-regime signal.
 *
 *   ADDITIVE / SHADOW: no live-path code reads any of the per-syscall
 *   frontier yield arrays; the bumps run strictly AFTER the per-call
 *   new-edge attribution decision and the picker accept/retry math is
 *   byte-identical to the pre-row baseline.  Pre-kernel-exit dispatches
 *   (validator-rejected early-EINVAL skip and --dry-run) reach here with
 *   new_edge_count = 0 forced above; treating those as live_misses would
 *   over-count the kill-list signal with picks the kernel never actually
 *   saw, so the live_miss branch additionally gates on
 *   rec->kernel_entered (the canonical flag for this distinction).
 *   Same MAX_NR_SYSCALL bound the sibling
 *   edges_per_syscall_bandit[] block above uses. */
void account_per_syscall_new_edges(struct childdata *child,
					  struct syscallrecord *rec,
					  unsigned long new_edge_count)
{
	if (new_edge_count > 0 && rec->nr < MAX_NR_SYSCALL) {
		unsigned long *bucket = child->is_explorer
			? shm->stats.picker_bandit.edges_per_syscall_explorer
			: shm->stats.picker_bandit.edges_per_syscall_bandit;
		__atomic_fetch_add(&bucket[rec->nr], new_edge_count,
				   __ATOMIC_RELAXED);
	}

	if (child->frontier_pick_regime != FRONTIER_PICK_NONE &&
	    rec->nr < MAX_NR_SYSCALL) {
		if (new_edge_count > 0) {
			__atomic_fetch_add(
				&shm->stats.frontier.per_syscall.productive_wins_per_syscall[rec->nr],
				1UL, __ATOMIC_RELAXED);
			__atomic_store_n(
				&shm->stats.frontier.per_syscall.last_productive_window_per_syscall[rec->nr],
				__atomic_load_n(&shm->bandit_window_count,
						__ATOMIC_RELAXED),
				__ATOMIC_RELAXED);
		} else if (child->frontier_pick_regime == FRONTIER_PICK_LIVE &&
			   rec->kernel_entered) {
			unsigned long streak;

			__atomic_fetch_add(
				&shm->stats.frontier.per_syscall.live_misses_per_syscall[rec->nr],
				1UL, __ATOMIC_RELAXED);

			/* SHADOW-ONLY per-syscall LIVE-regime miss-streak
			 * accounting.  Mirrors the silent-streak shadow
			 * decay block at the silent-regime accept site: the
			 * per-syscall counter advances strictly AFTER the
			 * existing live_misses bump above, and the two
			 * scalar companions edge-trigger and accumulate on
			 * the threshold-crossing pick.  Frontier_record_new_
			 * edge() / _record_transition_edge() reset the per-
			 * syscall counter on any productive event, so the
			 * streak captures the run-length of CONSECUTIVE
			 * zero-edge LIVE-regime picks of this syscall since
			 * it last earned coverage.
			 *
			 *  frontier_live_cooldown_candidates
			 *      Edge bump: fires on the (streak ==
			 *      FRONTIER_LIVE_MISS_COOLDOWN) crossing -- one
			 *      bump per distinct cooldown episode for this
			 *      syscall.
			 *  frontier_live_would_skip
			 *      Cumulative bump on every LIVE-regime miss
			 *      that lands with the post-increment streak at
			 *      or past the threshold -- the projected demote
			 *      count a live cooldown variant of the picker
			 *      would produce.
			 *
			 * Selection-byte-identical contract: the picker
			 * accept/retry math at the LIVE accept site is
			 * untouched; these bumps run strictly after the per-
			 * call attribution decision and write only NEW
			 * counters that no live-path code reads.  Same
			 * MAX_NR_SYSCALL bound the surrounding per-syscall
			 * arrays use. */
			streak = __atomic_add_fetch(
				&shm->stats.frontier.per_syscall.live_miss_streak_per_syscall[rec->nr],
				1UL, __ATOMIC_RELAXED);
			if (streak >= FRONTIER_LIVE_MISS_COOLDOWN) {
				__atomic_fetch_add(
					&shm->stats.frontier.cooldown.live_would_skip,
					1UL, __ATOMIC_RELAXED);
				__atomic_fetch_add(
					&shm->stats.frontier.cooldown.live_would_skip_per_syscall[rec->nr],
					1UL, __ATOMIC_RELAXED);

				/* SHADOW-ONLY LIVE-regime cooldown discriminator
				 * (gated by --frontier-live-cooldown-mode != off).
				 * Sits inside the same threshold-crossing branch as
				 * the F3 frontier_live_would_skip bumps above so the
				 * undiscriminated projection and the discriminated
				 * projection share the candidate gate (post-increment
				 * streak >= FRONTIER_LIVE_MISS_COOLDOWN) and the
				 * (live_cool_would_skip / live_would_skip) ratio
				 * reads off exactly how much over-cool the
				 * discriminator removes -- the SHADOW_ONLY
				 * measurement the ramp discipline needs before
				 * flipping COMBINED.  Helper applies its own outer
				 * mode gate, the FRONTIER_LIVE_COOL_CMIN low live
				 * floor (NOT FRONTIER_SATCOOL_CMIN -- see the
				 * include/strategy.h comment for the rationale), and
				 * the spare-lane evaluation; the bumps land in the
				 * frontier_live_cool_* shadow counter family and no
				 * live-path code reads them.  Same MAX_NR_SYSCALL
				 * bound the surrounding per-syscall arrays use. */
				frontier_live_cool_spare(rec->nr, rec->do32bit);
			}
			if (streak == FRONTIER_LIVE_MISS_COOLDOWN)
				__atomic_fetch_add(
					&shm->stats.frontier.cooldown.live_cooldown_candidates,
					1UL, __ATOMIC_RELAXED);
		}
	}
}

/* PC-edge-only bookkeeping.  Deliberately separate from the
 * found_something save block back in dispatch_step so CMP-source saves
 * can't trigger snapshot cadence, per-strategy edge attribution, or
 * pool edge counters -- see the new_edges/new_cmp gating comment for
 * why those must stay PC-only.
 *
 * Gated on new_edges (caller short-circuits in the !new_edges hot
 * path).  Three pieces, in execution order:
 *   - minicorpus_maybe_snapshot()   -- coverage-delta-triggered
 *                                       persistence cadence
 *   - explorer/bandit pool split    -- per-strategy edge attribution
 *                                       for the bandit arms, skipped
 *                                       for explorer-pool children
 *   - random-rescue classification  -- only meaningful under
 *                                       SR_PLATEAU_FORCE windows */
void account_pc_edge_only(struct childdata *child,
				 struct syscallrecord *rec,
				 unsigned long new_edge_count,
				 unsigned int rescue_cold_skip_pct_before)
{
	/* Coverage-delta-triggered persistence: snapshot the
	 * minicorpus to disk every MINICORPUS_SNAPSHOT_EDGES
	 * fleet-wide edges so a crash mid-run only loses the
	 * last cadence window of state, not the whole run.
	 * Cheap fast path when the gap isn't reached; only one
	 * caller per window actually runs the save. */
	minicorpus_maybe_snapshot();

	if (child->is_explorer) {
		/* Explorer-pool discoveries are real edges and count
		 * toward the run-wide fleet totals, but skip the
		 * per-strategy reward attribution: explorers always
		 * run STRATEGY_RANDOM, so feeding their edges into
		 * the bandit's current arm would either inflate a
		 * non-RANDOM arm's reward (when the bandit picked
		 * something else) or double-count when the bandit
		 * also picked RANDOM. */
		__atomic_fetch_add(&shm->stats.picker_bandit.explorer_pool_edges_discovered,
				   1, __ATOMIC_RELAXED);
	} else {
		/* Attribute this new-edge call to the strategy that
		 * PICKED the syscall, not whichever strategy happens
		 * to be shm->current_strategy by the time the syscall
		 * has returned and we got around to scoring the
		 * reward.  The two values can disagree any time a
		 * rotation lands between set_syscall_nr() and here,
		 * which is frequent for long or blocking syscalls;
		 * reading the pick-time stamp keeps the bandit's
		 * reward signal pointed at the arm that actually
		 * earned the credit.
		 *
		 * Two parallel cumulative counters:
		 * pc_edge_calls_by_strategy[] bumps by 1 (the
		 * historical "edges_by_strategy[]" signal under its
		 * honest name -- calls-with-≥1-edge) and
		 * pc_edge_count_by_strategy[] bumps by the real
		 * bucket-edge count from kcov_collect().  Window
		 * deltas are computed by maybe_rotate_strategy against
		 * the matching *_at_window_start snapshots. */
		int strat = child->strategy_at_pick;
		if (strat >= 0 && strat < NR_STRATEGIES) {
			__atomic_fetch_add(&shm->pc_edge_calls_by_strategy[strat],
					   1, __ATOMIC_RELAXED);
			__atomic_fetch_add(&shm->pc_edge_count_by_strategy[strat],
					   new_edge_count,
					   __ATOMIC_RELAXED);
		}
		__atomic_fetch_add(&shm->stats.picker_bandit.bandit_pool_edges_discovered,
				   1, __ATOMIC_RELAXED);

		/* Random-rescue classification.  Only meaningful when
		 * the current window is a SR_PLATEAU_FORCE intervention
		 * -- the classifier exists to explain why a forced
		 * RANDOM rescue produced the edge a structured picker
		 * missed.  Reading current_selection_reason rather than
		 * stamping it at pick-time is fine here: the
		 * intervention windows are long (~100 sec at 10K
		 * iter/sec) and a child whose syscall straddled a
		 * rotation boundary is rare enough that misattributing
		 * a handful of rescues per rotation is below the
		 * noise floor on the per-class counts.  The orchestrator
		 * reads the cumulative distribution at the next
		 * rotation boundary to decide which class to amplify. */
		if (__atomic_load_n(&shm->current_selection_reason,
				    __ATOMIC_RELAXED) ==
		    SR_PLATEAU_FORCE) {
			enum random_rescue_class rrc =
				classify_random_rescue(rec, child,
					rescue_cold_skip_pct_before);
			if (rrc >= 0 && rrc < RRC_NR_CLASSES)
				__atomic_fetch_add(
					&shm->random_rescue_class_count[rrc],
					1UL, __ATOMIC_RELAXED);
		}
	}
}

/* Per-strategy transition-reward attribution.  Independent of the
 * new_edges gate above: a call can flip transition slots (a new
 * ordering between two PCs) without flipping any new bucket bit
 * -- the canonical "transition fires on warm-known PCs through a
 * new route" case is exactly the signal the operator wants
 * separated from the PC-edge stream.  The kcov_collect path
 * already filters pcres.transition_edges_real_local on
 * !kc->remote_mode and on kcov_transition_reward_mode != OFF
 * (see the result-population branch in kcov_collect), so a
 * non-zero value here means a local-mode call earned a reward-
 * eligible transition delta.
 *
 * Explorer-pool calls are skipped for the same reason PC-edge
 * attribution skips them above: explorers always run STRATEGY_
 * RANDOM, so crediting the active bandit arm here would either
 * inflate a non-RANDOM arm's reward (when the bandit picked
 * something else) or double-count when both pools picked RANDOM.
 *
 * The raw transition count is capped at TRANSITION_PER_CALL_
 * REWARD_CAP before being added to transition_edge_count_by_
 * strategy[] so a single pathological trace (e.g. a syscall that
 * opens a brand-new control-flow region and flips thousands of
 * transition slots in one call) cannot monopolize the per-window
 * delta the bandit reads as reward.  The uncapped real-flip
 * counter per_syscall_transition_edges_real keeps reporting the
 * full magnitude for the stats-dump top-N; the cap only applies
 * to the reward-attribution path. */
void account_transition_reward(struct childdata *child,
				      struct syscallrecord *rec,
				      const struct kcov_pc_result *pcres)
{
	int strat;
	unsigned long capped;

	if (pcres->transition_edges_real_local == 0 ||
	    child->is_explorer || rec->nr >= MAX_NR_SYSCALL)
		return;

	strat = child->strategy_at_pick;
	if (strat < 0 || strat >= NR_STRATEGIES)
		return;

	capped = pcres->transition_edges_real_local;
	if (capped > TRANSITION_PER_CALL_REWARD_CAP)
		capped = TRANSITION_PER_CALL_REWARD_CAP;
	__atomic_fetch_add(
		&shm->stats.transition_edge.calls_by_strategy[strat],
		1UL, __ATOMIC_RELAXED);
	__atomic_fetch_add(
		&shm->stats.transition_edge.count_by_strategy[strat],
		capped, __ATOMIC_RELAXED);
}
