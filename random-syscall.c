/*
 * Call a single random syscall with random args.
 */

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "arch.h"	// biarch
#include "arg-decoder.h"
#include "child.h"
#include "cmp_hints.h"
#include "debug.h"
#include "edgepair.h"
#include "kcov.h"
#include "locks.h"
#include "minicorpus.h"
#include "params.h"
#include "pids.h"
#include "pre_crash_ring.h"
#include "random.h"
#include "rnd.h"
#include "sequence.h"
#include "shm.h"
#include "signals.h"
#include "sanitise.h"
#include "stats.h"
#include "stats_ring.h"
#include "strategy.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

/*
 * Number of candidate syscall numbers sampled per mid-chain edgepair pick.
 * Small enough that the K edgepair_score() lookups (each one mirror-page
 * load + a hash probe) stay cheap relative to a syscall dispatch, large
 * enough that the picker has a real shot at landing on a productive
 * outgoing pair when one exists.  See set_syscall_nr_edgepair_chain().
 */
#define EDGEPAIR_CHAIN_SAMPLE_K 16

/*
 * This function decides if we're going to be doing a 32bit or 64bit syscall.
 * There are various factors involved here, from whether we're on a 32-bit only arch
 * to 'we asked to do a 32bit only syscall' and more.. Hairy.
 */

/*
 * Biarch-only: pick which syscall table this call uses, refresh the
 * caller's per-child active_syscalls pointer, and return do32.  Uniarch
 * builds bypass this entirely — child->active_syscalls is set once at
 * init time to shm->active_syscalls and never re-evaluated.
 */
bool choose_syscall_table(struct childdata *child,
			  unsigned int *nr_syscalls_out)
{
	bool do32 = false;

	/* First, check that we have syscalls enabled in either table.
	 * Read the cached validity bits maintained by validate_syscall_table_*
	 * and the deactivate_syscall{32,64}() paths instead of re-running the
	 * walk on every pick. */
	if (__atomic_load_n(&shm->valid_syscall_table_64, __ATOMIC_RELAXED) == false) {
		use_64bit = false;
		/* If no 64bit syscalls enabled, force 32bit. */
		do32 = true;
	}

	if (__atomic_load_n(&shm->valid_syscall_table_32, __ATOMIC_RELAXED) == false)
		use_32bit = false;

	/* If both tables enabled, pick randomly. */
	if ((use_64bit == true) && (use_32bit == true)) {
		/* 10% possibility of a 32bit syscall */
		if (ONE_IN(10))
			do32 = true;
	}

	if (do32 == false) {
		syscalls = syscalls_64bit;
		child->active_syscalls = shm->active_syscalls64;
		*nr_syscalls_out = max_nr_64bit_syscalls;
	} else {
		syscalls = syscalls_32bit;
		child->active_syscalls = shm->active_syscalls32;
		*nr_syscalls_out = max_nr_32bit_syscalls;
	}
	return do32;
}

/*
 * Validation-failure resilience: a syscallnr drawn by the picker is
 * deactivated only after VALIDATE_FAIL_THRESHOLD consecutive picks of
 * that syscall fail validate_specific_syscall_silent().  A transient
 * flap (e.g. a probe that EAGAIN'd once or briefly tripped a kernel
 * gate) used to permanently kill the entry on the first failure with
 * no log; now the counter has to build up and the deactivation is
 * announced.  The counter (shm->syscall_validation_failures[]) is
 * shared across children so observation accumulates fleet-wide, and
 * resets to 0 on the first successful validation for that slot.
 */
#define VALIDATE_FAIL_THRESHOLD 3

static void note_validation_success(unsigned int syscallnr, bool do32)
{
	unsigned int arch = do32 ? 1 : 0;

	if (__atomic_load_n(&shm->syscall_validation_failures[arch][syscallnr],
			    __ATOMIC_RELAXED) != 0)
		__atomic_store_n(&shm->syscall_validation_failures[arch][syscallnr],
				 0, __ATOMIC_RELAXED);
}

static void note_validation_failure(unsigned int syscallnr, bool do32)
{
	unsigned int arch = do32 ? 1 : 0;
	unsigned int count;
	struct syscallentry *entry;
	const char *name;

	count = (unsigned int)__atomic_add_fetch(
		&shm->syscall_validation_failures[arch][syscallnr], 1,
		__ATOMIC_RELAXED);
	if (count < VALIDATE_FAIL_THRESHOLD)
		return;

	entry = get_syscall_entry(syscallnr, do32);
	name = (entry != NULL) ? entry->name : "<unknown>";
	output(0, "deactivating syscall %s (nr=%u) after %u validation failures\n",
	       name, syscallnr, count);
	__atomic_store_n(&shm->syscall_validation_failures[arch][syscallnr], 0,
			 __ATOMIC_RELAXED);
	deactivate_syscall_locked(syscallnr, do32);
}

/*
 * Check if a syscall entry belongs to the target group.
 * Used by group biasing to filter candidates.
 */
static bool syscall_in_group(unsigned int nr, bool do32, unsigned int target_group)
{
	struct syscallentry *entry;

	entry = get_syscall_entry(nr, do32);
	if (entry == NULL)
		return false;

	return entry->group == target_group;
}

/*
 * Pick the syscall to run under STRATEGY_HEURISTIC: uniform draw from
 * active_syscalls, then layered biases — group affinity (70% prefer last
 * group), kcov cold-skip (probabilistic), edgepair freshness (50% skip
 * cold pairs).  This is trinity's pre-rotation default behaviour.
 */
static bool set_syscall_nr_heuristic(struct syscallrecord *rec,
				     struct childdata *child)
{
	struct syscallentry *entry;
	unsigned int syscallnr;
	int val;
	bool do32;
	unsigned int group_attempts = 0;
	unsigned int kcov_attempts = 0;
	unsigned int edgepair_attempts = 0;
	unsigned int outer_attempts = 0;
	unsigned int nr_syscalls;

	/* Pick the syscall table once per call: in uniarch the result is
	 * a constant, and even in biarch the do32 dice rolls once per
	 * pick — re-rolling under the retry budget (up to 10 000 spins
	 * on a sparse table) burned ~5 cycles per iteration for nothing. */
	if (biarch) {
		do32 = choose_syscall_table(child, &nr_syscalls);
	} else {
		do32 = false;
		nr_syscalls = max_nr_syscalls;
	}

retry:
	if (no_syscalls_enabled() == true) {
		output(0, "[%d] No more syscalls enabled. Exiting\n", mypid());
		__atomic_store_n(&shm->exit_reason, EXIT_NO_SYSCALLS_ENABLED, __ATOMIC_RELAXED);
		return FAIL;
	}

	/* Bail if we have spent too many iterations failing to pick a
	 * usable syscall.  Without this cap, a sparse active_syscalls
	 * table or a table dominated by EXPENSIVE syscalls (kept at
	 * 1-in-1000) can wedge the child in a tight retry loop. */
	if (outer_attempts++ > 10000) {
		output(0, "[%d] set_syscall_nr exceeded retry budget\n", mypid());
		return FAIL;
	}

	syscallnr = rnd_modulo_u32(nr_syscalls);

	/* If we got a syscallnr which is not active repeat the attempt,
	 * since another child has switched that syscall off already.*/
	val = child->active_syscalls[syscallnr];
	if (val == 0)
		goto retry;

	syscallnr = val - 1;

	/*
	 * EXPENSIVE early-out: bitmap test before validate + entry fetch,
	 * so the 999/1000 reject path skips the cache miss on the
	 * syscallentry that the EXPENSIVE block below used to require.
	 */
	if (syscall_is_expensive(syscallnr, do32) && !ONE_IN(1000))
		goto retry;

	if (validate_specific_syscall_silent(syscalls, syscallnr) == false) {
		note_validation_failure(syscallnr, do32);
		goto retry;
	}
	note_validation_success(syscallnr, do32);

	entry = get_syscall_entry(syscallnr, do32);
	if (entry == NULL)
		goto retry;

	/*
	 * Group biasing: when enabled and we have a previous group context,
	 * bias selection toward syscalls in the same group.
	 *
	 * 70% of the time: prefer same group as last call
	 * 25% of the time: accept any syscall (no bias)
	 *  5% of the time: accept any syscall (exploration)
	 *
	 * If we can't find a same-group syscall after 20 attempts,
	 * fall through and accept whatever we picked.
	 */
	if (group_bias && child->last_group != GROUP_NONE) {
		unsigned int dice = rnd_modulo_u32(100);

		if (dice < 70) {
			/* Try to pick from same group */
			if (!syscall_in_group(syscallnr, do32, child->last_group)) {
				group_attempts++;
				if (group_attempts < 20)
					goto retry;
				/* Gave up, accept this one. */
			}
		}
		/* dice >= 70: accept any syscall */
	}

	/* Coverage-guided cold avoidance: if this syscall has stopped
	 * finding new edges, skip it with a probability that grows the
	 * staler it gets — a syscall stuck for one threshold-window gets
	 * the same 50% baseline as before, but one stuck for ten gets
	 * skipped 90% of the time.
	 *
	 * Suppressed inside a SR_PLATEAU_FORCE intervention when the
	 * random-rescue classifier has accumulated enough RRC_COLD_SKIP
	 * evidence to amplify that class: the rescues that have been
	 * carrying the fleet past the plateau are mostly cold-skipped
	 * syscalls, and structured replay means letting the heuristic
	 * actually pick them.  Both gates checked because either alone
	 * is insufficient -- plateau_active without amplification means
	 * a different class won, and amplification cannot stay live
	 * after the plateau lifts (the orchestrator clears the field on
	 * its next non-intervention rotation). */
	if (!plateau_rescue_bias_active_for(RRC_COLD_SKIP)) {
		unsigned int skip_pct = kcov_syscall_cold_skip_pct(syscallnr);

		if (skip_pct > 0 && rnd_modulo_u32(100) < skip_pct) {
			kcov_attempts++;
			if (kcov_attempts < 20)
				goto retry;
		}
	}

	/* Edge-pair sequence biasing: if we have a previous syscall,
	 * prefer pairs that have produced new edges before.
	 * Skip cold pairs (haven't found new edges recently) 50% of
	 * the time.  Boost productive pairs by accepting them
	 * immediately when we'd otherwise retry. */
	if (child->last_syscall_nr != EDGEPAIR_NO_PREV) {
		if (edgepair_is_cold(child->last_syscall_nr, syscallnr) &&
		    RAND_BOOL()) {
			edgepair_attempts++;
			if (edgepair_attempts < 20)
				goto retry;
		}
	}

	/* critical section for shm updates. */
	lock(&rec->lock);
	rec->do32bit = do32;
	rec->nr = syscallnr;
	unlock(&rec->lock);

	return true;
}

/*
 * Anti-prior reject-retry budget.  The accept gate's per-call rejection
 * rate sits at 1 - 1/MAX_BOOST = 87.5% at the median; over a sparse
 * active table this still resolves in a handful of retries on average,
 * but a pathological mix (e.g. every active syscall sitting at the
 * over-picked saturation point, accept = 1/MAX_BOOST^2) could push past
 * the natural recovery budget.  Bound at 64 so the inner loop never
 * burns more than the per-iteration cost is worth; falling through
 * means accepting whatever the picker happened to land on, which
 * degrades anti-prior gracefully to uniform pick rather than wedging
 * the syscall picker.  Kept well below the outer 10000 budget so the
 * gate cannot starve the rest of the validate / EXPENSIVE gates.
 */
#define ANTI_PRIOR_RETRY_CAP 64U

/*
 * Bound for the PAIR_UNSEEN intervention's bounded re-roll.  When the
 * orchestrator amplifies RRC_PAIR_UNSEEN, the picker re-rolls a bounded
 * number of times trying to land on an unseen (prev, curr) successor
 * instead of accepting a seen one.  High enough to meaningfully steer
 * toward unseen successors, low enough that an already-saturated pair
 * table cannot livelock the picker.
 */
#define UNSEEN_SEEK_RETRY_CAP 8U

/*
 * Pick the syscall to run under STRATEGY_RANDOM: uniform draw from
 * active_syscalls with no further biasing.  The "shake the dust off"
 * pass — useless on its own, but exposes paths the heuristic biases
 * systematically suppress (cold syscalls, productive-pair-only flow).
 *
 * Active_syscalls + EXPENSIVE + AVOID_SYSCALL gating remain because
 * those are correctness gates, not selection biases — bypassing them
 * just wastes iterations on calls we know we can't make.
 *
 * Anti-prior plateau intervention: during an SR_PLATEAU_FORCE window
 * the orchestrator may have rotated into PIM_ANTI_PRIOR mode, in which
 * case the per-candidate accept gate inverts the picker's learned
 * per-syscall pick-rate distribution -- syscalls the bandit has been
 * over-selecting get rejected at up to MAX_BOOST^2:1, low-count
 * syscalls accept at full uniform rate.  Outside the intervention the
 * gate's atomic load short-circuits and the picker is the historical
 * pure-uniform draw.
 */
bool set_syscall_nr_random(struct syscallrecord *rec,
			    struct childdata *child)
{
	unsigned int syscallnr;
	int val;
	bool do32;
	unsigned int outer_attempts = 0;
	unsigned int nr_syscalls;
	unsigned int anti_prior_attempts = 0;
	unsigned int edgepair_attempts = 0;
	unsigned int unseen_seek_attempts = 0;
	bool anti_prior_on;

	/* See the matching comment in set_syscall_nr_heuristic — the table
	 * pick is a per-call decision, not a per-retry one. */
	if (biarch) {
		do32 = choose_syscall_table(child, &nr_syscalls);
	} else {
		do32 = false;
		nr_syscalls = max_nr_syscalls;
	}

	/* Latch the anti-prior mode once per pick so the per-retry inner
	 * loop reads a stable answer; a rotation that lands mid-pick is
	 * harmless either way (we either over-shoot one retry budget or
	 * under-shoot one) but caching avoids redoing the relaxed atomic
	 * load on every retry. */
	anti_prior_on = plateau_anti_prior_active();

retry:
	if (no_syscalls_enabled() == true) {
		output(0, "[%d] No more syscalls enabled. Exiting\n", mypid());
		__atomic_store_n(&shm->exit_reason, EXIT_NO_SYSCALLS_ENABLED, __ATOMIC_RELAXED);
		return FAIL;
	}

	if (outer_attempts++ > 10000) {
		output(0, "[%d] set_syscall_nr_random exceeded retry budget\n", mypid());
		return FAIL;
	}

	syscallnr = rnd_modulo_u32(nr_syscalls);

	val = child->active_syscalls[syscallnr];
	if (val == 0)
		goto retry;

	syscallnr = val - 1;

	/* EXPENSIVE early-out: bitmap test before validate + entry fetch,
	 * so the 999/1000 reject path skips the cache miss on the
	 * syscallentry that the EXPENSIVE block below used to require. */
	if (syscall_is_expensive(syscallnr, do32) && !ONE_IN(1000))
		goto retry;

	if (validate_specific_syscall_silent(syscalls, syscallnr) == false) {
		note_validation_failure(syscallnr, do32);
		goto retry;
	}
	note_validation_success(syscallnr, do32);

	/* Edge-pair gates, guarded on a valid previous syscall.  Mirrors the
	 * heuristic picker's cold-pair filter (saturated (prev, curr) pairs
	 * whose reachable PCs have already been exhausted waste explorer
	 * iterations on territory the heuristic side is also actively
	 * avoiding) and adds an immediate-accept short-circuit for
	 * never-seen pairs so the explorer drives toward unexplored
	 * territory rather than re-treading stale ground.
	 *
	 * Never-seen detection uses edgepair_get_stats() returning {0, 0}
	 * -- no record exists in the hash table, distinct from a recorded
	 * pair that simply happens to have produced no new edges yet.
	 * Accept short-circuits past the anti-prior gate so an unexplored
	 * pair is taken on its first sighting regardless of the bandit's
	 * per-syscall pick-rate distribution.
	 *
	 * Cold-pair rejection uses the same RAND_BOOL gate and 20-retry
	 * cap as the heuristic picker.  Sits before anti-prior so the cold
	 * filter runs on the unbiased candidate stream; a rejected cold
	 * pair retries from the top of the loop where the next pick is a
	 * fresh uniform draw. */
	if (child->last_syscall_nr != EDGEPAIR_NO_PREV) {
		struct edgepair_stats ps =
			edgepair_get_stats(child->last_syscall_nr, syscallnr);

		if (ps.new_edges == 0 && ps.total == 0) {
			__atomic_fetch_add(
				&shm->stats.explorer_unseen_pair_accepts,
				1UL, __ATOMIC_RELAXED);
			goto commit;
		}

		/* RRC_PAIR_UNSEEN intervention: when the orchestrator has
		 * amplified PAIR_UNSEEN, re-roll a bounded number of times
		 * trying to land on an unseen (prev, curr) successor
		 * instead of accepting a seen one.  Bounded by
		 * UNSEEN_SEEK_RETRY_CAP so an extreme distribution falls
		 * back to the normal accept path instead of livelocking the
		 * picker. */
		if (plateau_rescue_bias_active_for(RRC_PAIR_UNSEEN) &&
		    unseen_seek_attempts < UNSEEN_SEEK_RETRY_CAP) {
			unseen_seek_attempts++;
			__atomic_fetch_add(
				&shm->stats.explorer_unseen_pair_seek_retries,
				1UL, __ATOMIC_RELAXED);
			goto retry;
		}

		/* RRC_PAIR_COLD intervention: when the orchestrator has
		 * amplified PAIR_COLD, suppress the cold-pair RAND_BOOL
		 * rejection so the intervention actually reaches the cold
		 * pairs the picker is otherwise throttling.  Outside the
		 * intervention the gate stays exactly as before. */
		if (edgepair_is_cold(child->last_syscall_nr, syscallnr) &&
		    !plateau_rescue_bias_active_for(RRC_PAIR_COLD) &&
		    RAND_BOOL()) {
			__atomic_fetch_add(
				&shm->stats.explorer_cold_pair_rejects,
				1UL, __ATOMIC_RELAXED);
			edgepair_attempts++;
			if (edgepair_attempts < 20)
				goto retry;
		}
	}

	/* Anti-prior accept gate.  Applied AFTER the active/validate/
	 * EXPENSIVE correctness gates so a rejected anti-prior candidate
	 * goes back through the uniform pick rather than burning the gate
	 * budget on disabled or AVOID-flagged syscalls.  Bounded retry
	 * budget so an extreme distribution falls back to uniform instead
	 * of wedging the picker. */
	if (anti_prior_on && !plateau_anti_prior_accept(syscallnr)) {
		anti_prior_attempts++;
		if (anti_prior_attempts < ANTI_PRIOR_RETRY_CAP)
			goto retry;
		/* Budget exhausted -- accept the current candidate and let
		 * the next pick re-roll.  The intervention's per-window
		 * shape stays anti-prior on average even if individual
		 * picks fall through. */
	}

commit:
	lock(&rec->lock);
	rec->do32bit = do32;
	rec->nr = syscallnr;
	unlock(&rec->lock);

	return true;
}

/*
 * Pick the syscall to run under STRATEGY_COVERAGE_FRONTIER: uniform draw
 * from active_syscalls, then biased acceptance against the per-syscall
 * frontier-edge weight via rejection sampling.  Each candidate is
 * accepted with probability (frontier_recent_count(nr) + 1) /
 * (max_weight + 1); the +1 keeps cold syscalls from starving completely
 * and lets the strategy still drive forward when no syscall has
 * produced a frontier edge in the last K windows (every weight is 1, so
 * acceptance reduces to uniform).
 *
 * max_weight is read once at the top of the function from the cached
 * shm->frontier_max_weight_cached so the bias mass stays stable across
 * the inner retry loop, and so concurrent kcov_collect-driven bumps to
 * frontier_history during the pick don't perturb the acceptance
 * probability mid-call.  The cache is recomputed authoritatively on
 * each window rotation by frontier_window_advance() and ratcheted
 * upward on new-edge bumps by frontier_record_new_edge(), turning what
 * used to be an O(MAX_NR_SYSCALL) walk per pick into a single RELAXED
 * load.
 *
 * The validate / EXPENSIVE / AVOID_SYSCALL retry budget mirrors the
 * other set_syscall_nr_* variants because those are correctness gates,
 * not selection biases.
 */
static bool set_syscall_nr_coverage_frontier(struct syscallrecord *rec,
					     struct childdata *child)
{
	unsigned int syscallnr;
	unsigned int val;
	bool do32;
	unsigned int outer_attempts = 0;
	unsigned int nr_syscalls;
	unsigned long max_weight;

	if (biarch) {
		do32 = choose_syscall_table(child, &nr_syscalls);
	} else {
		do32 = false;
		nr_syscalls = max_nr_syscalls;
	}

	max_weight = __atomic_load_n(&shm->frontier_max_weight_cached,
				     __ATOMIC_RELAXED);

retry:
	if (no_syscalls_enabled() == true) {
		output(0, "[%d] No more syscalls enabled. Exiting\n", mypid());
		__atomic_store_n(&shm->exit_reason, EXIT_NO_SYSCALLS_ENABLED, __ATOMIC_RELAXED);
		return FAIL;
	}

	if (outer_attempts++ > 10000) {
		output(0, "[%d] set_syscall_nr_coverage_frontier exceeded retry budget\n", mypid());
		return FAIL;
	}

	syscallnr = rnd_modulo_u32(nr_syscalls);

	val = child->active_syscalls[syscallnr];
	if (val == 0)
		goto retry;

	syscallnr = val - 1;

	/* EXPENSIVE early-out: bitmap test before validate + entry fetch,
	 * so the 999/1000 reject path skips the cache miss on the
	 * syscallentry that the EXPENSIVE block below used to require. */
	if (syscall_is_expensive(syscallnr, do32) && !ONE_IN(1000))
		goto retry;

	if (validate_specific_syscall_silent(syscalls, syscallnr) == false) {
		note_validation_failure(syscallnr, do32);
		goto retry;
	}
	note_validation_success(syscallnr, do32);

	/* Frontier-weighted acceptance.  When max_weight is 0 (no syscall
	 * has registered a frontier edge in the last FRONTIER_DECAY_WINDOWS
	 * rotations -- typical at run start or in a heavily-explored
	 * codebase where everything has plateaued), the (w+1)/(max+1) ratio
	 * is 1 for every candidate and the acceptance gate is bypassed,
	 * degenerating gracefully to uniform pick. */
	if (max_weight > 0) {
		unsigned long w = frontier_recent_count(syscallnr);
		unsigned long denom = max_weight + 1UL;
		unsigned long roll = (unsigned long)rnd_modulo_u64(denom);

		if (roll >= w + 1UL)
			goto retry;
	}

	lock(&rec->lock);
	rec->do32bit = do32;
	rec->nr = syscallnr;
	unlock(&rec->lock);

	__atomic_fetch_add(&shm->stats.frontier_strategy_picks, 1UL,
			   __ATOMIC_RELAXED);

	return true;
}

/*
 * Pick the syscall to run under STRATEGY_EDGEPAIR_FRONTIER: uniform draw
 * from active_syscalls, then biased acceptance via
 * edgepair_score(child->last_syscall_nr, candidate, mode).  mode flips
 * 50/50 between EXPLORATION (favours never-seen outgoing pairs) and
 * EXPLOITATION (favours productive-fresh outgoing pairs) per call, so
 * both axes get airtime without a tuning knob.
 *
 * When the child has no predecessor (last_syscall_nr == EDGEPAIR_NO_PREV)
 * the score is undefined; fall back to a uniform validate-and-accept loop
 * without the score gate so the first syscall of each child still gets
 * normal cover.
 *
 * The validate / EXPENSIVE / AVOID_SYSCALL retry budget mirrors
 * set_syscall_nr_coverage_frontier(): correctness gates apply regardless
 * of strategy.
 */
static bool set_syscall_nr_edgepair_frontier(struct syscallrecord *rec,
					     struct childdata *child)
{
	unsigned int syscallnr;
	unsigned int val;
	bool do32;
	unsigned int outer_attempts = 0;
	unsigned int nr_syscalls;
	enum edgepair_score_mode mode;
	bool have_prev;

	if (biarch) {
		do32 = choose_syscall_table(child, &nr_syscalls);
	} else {
		do32 = false;
		nr_syscalls = max_nr_syscalls;
	}

	have_prev = (child->last_syscall_nr != EDGEPAIR_NO_PREV);
	mode = RAND_BOOL() ? EDGEPAIR_SCORE_EXPLORATION
			   : EDGEPAIR_SCORE_EXPLOITATION;

retry:
	if (no_syscalls_enabled() == true) {
		output(0, "[%d] No more syscalls enabled. Exiting\n", mypid());
		__atomic_store_n(&shm->exit_reason, EXIT_NO_SYSCALLS_ENABLED, __ATOMIC_RELAXED);
		return FAIL;
	}

	if (outer_attempts++ > 10000) {
		output(0, "[%d] set_syscall_nr_edgepair_frontier exceeded retry budget\n", mypid());
		return FAIL;
	}

	syscallnr = rnd_modulo_u32(nr_syscalls);

	val = child->active_syscalls[syscallnr];
	if (val == 0)
		goto retry;

	syscallnr = val - 1;

	if (syscall_is_expensive(syscallnr, do32) && !ONE_IN(1000))
		goto retry;

	if (validate_specific_syscall_silent(syscalls, syscallnr) == false) {
		note_validation_failure(syscallnr, do32);
		goto retry;
	}
	note_validation_success(syscallnr, do32);

	/* Edgepair-weighted acceptance.  edgepair_score returns a weight in
	 * [0, 1024]; treat it as a rejection-sampling probability against the
	 * max weight 1024.  A weight of 0 still accepts on a 1024-sided roll
	 * of 0, keeping a non-starving floor for cold pairs in this arm so it
	 * does not livelock when every pair score is currently low. */
	if (have_prev) {
		unsigned int w = edgepair_score(child->last_syscall_nr,
						syscallnr, mode);
		unsigned int roll = (unsigned int)rnd_modulo_u32(1024U + 1U);

		if (roll > w)
			goto retry;
	}

	lock(&rec->lock);
	rec->do32bit = do32;
	rec->nr = syscallnr;
	unlock(&rec->lock);

	__atomic_fetch_add(&shm->stats.edgepair_frontier_strategy_picks, 1UL,
			   __ATOMIC_RELAXED);

	return true;
}

/*
 * Mid-chain edgepair-guided pick.  Sample up to EDGEPAIR_CHAIN_SAMPLE_K
 * syscall numbers from the active table, drop any that can't be called
 * right now (active_syscalls slot empty, validate_specific_syscall_silent
 * rejects), score the survivors by edgepair_score(prev, candidate, mode)
 * against child->last_syscall_nr, and commit the highest-scoring one.
 *
 * Mode flips per call between EDGEPAIR_SCORE_EXPLORATION (favours
 * never-seen outgoing pairs) and EDGEPAIR_SCORE_EXPLOITATION (favours
 * productive-fresh outgoing pairs) on a 50/50 coin, so both axes get
 * airtime without a tuning knob.
 *
 * On a successful pick the function writes rec->nr / rec->do32bit and
 * returns true; the caller (set_syscall_nr) short-circuits and skips
 * the bandit's strategy_picks[] / strategy_at_pick stamp so chain mid-
 * step dispatches inherit step 0's attribution.  On failure (no candidate
 * survived K tries) returns false and the caller falls through to the
 * normal bandit dispatch, where strategy_at_pick / strategy_picks[] get
 * stamped exactly once for this call.
 *
 * Applies the same EXPENSIVE 1/1000 reject gate the bandit pickers
 * use before validation/scoring, so chain mid-step dispatches do not
 * win the K-candidate competition with an expensive syscall at a rate
 * the top-level pickers would never produce.
 */
static bool set_syscall_nr_edgepair_chain(struct syscallrecord *rec,
					  struct childdata *child)
{
	enum edgepair_score_mode mode;
	unsigned int nr_syscalls;
	unsigned int best_nr = 0;
	unsigned int best_score = 0;
	unsigned int sample;
	bool best_valid = false;
	bool do32;

	if (biarch) {
		do32 = choose_syscall_table(child, &nr_syscalls);
	} else {
		do32 = false;
		nr_syscalls = max_nr_syscalls;
	}

	if (no_syscalls_enabled() == true)
		return false;

	mode = RAND_BOOL() ? EDGEPAIR_SCORE_EXPLORATION
			   : EDGEPAIR_SCORE_EXPLOITATION;

	for (sample = 0; sample < EDGEPAIR_CHAIN_SAMPLE_K; sample++) {
		unsigned int idx = rnd_modulo_u32(nr_syscalls);
		int val = child->active_syscalls[idx];
		unsigned int candidate;
		unsigned int score;

		if (val == 0)
			continue;

		candidate = (unsigned int)(val - 1);

		if (syscall_is_expensive(candidate, do32) && !ONE_IN(1000))
			continue;

		if (validate_specific_syscall_silent(syscalls, (int)candidate) == false)
			continue;

		score = edgepair_score(child->last_syscall_nr, candidate, mode);

		/* > rather than >= so the first survivor wins ties.  Without
		 * the strict inequality the picker would silently prefer
		 * later samples on ties, which biases nothing useful and
		 * costs an extra store per equal-scoring candidate. */
		if (!best_valid || score > best_score) {
			best_nr = candidate;
			best_score = score;
			best_valid = true;
		}
	}

	if (!best_valid)
		return false;

	lock(&rec->lock);
	rec->do32bit = do32;
	rec->nr = best_nr;
	unlock(&rec->lock);

	__atomic_fetch_add(&shm->stats.edgepair_chain_picks, 1UL,
			   __ATOMIC_RELAXED);
	if (mode == EDGEPAIR_SCORE_EXPLORATION)
		__atomic_fetch_add(&shm->stats.edgepair_chain_pick_explore,
				   1UL, __ATOMIC_RELAXED);
	else
		__atomic_fetch_add(&shm->stats.edgepair_chain_pick_exploit,
				   1UL, __ATOMIC_RELAXED);

	return true;
}

/*
 * Dispatch syscall selection through the active strategy's picker.
 * Reads shm->current_strategy with relaxed atomic, then snapshots the
 * chosen arm into child->strategy_at_pick so the post-syscall reward
 * attribution sites credit the arm that actually picked the syscall --
 * not whichever arm happens to be current_strategy by the time the
 * syscall returns.  Without the stamp, a rotation that lands mid-call
 * (especially common on long or blocking syscalls) would misattribute
 * the reward and contaminate the bandit's learning signal.  Out-of-range
 * guard preserves correctness even if a wild write into shm corrupts
 * the strategy index.
 */
static bool set_syscall_nr(struct syscallrecord *rec, struct childdata *child)
{
	int strat;

	/* Explorer-pool children bypass the bandit's current pick and run
	 * STRATEGY_RANDOM unconditionally -- including when the bandit has
	 * picked STRATEGY_COVERAGE_FRONTIER.  The pool is the always-on
	 * uniform baseline that lets the bandit's reward signal stay honest
	 * even when its winning arm goes stale.  Skip the strategy_at_pick
	 * stamp too: explorer contributions are filtered out of the bandit's
	 * per-arm reward counters in the post-syscall path on is_explorer
	 * alone, and leaving the -1 sentinel here makes that intent explicit
	 * if a future reader forgets the is_explorer gate. */
	if (child->is_explorer) {
		__atomic_fetch_add(&shm->stats.strategy_explorer_picks, 1UL,
				   __ATOMIC_RELAXED);
		/* Explorer-pool exposure: explorers always run STRATEGY_RANDOM
		 * regardless of the bandit's pick.  Bump strategy_picks for
		 * RANDOM directly (strategy_at_pick stays at the -1 sentinel
		 * so the post-syscall PC/CMP reward attribution still skips
		 * explorers as before).  strategy_bandit_pool_ops is NOT
		 * bumped here -- it is a bandit-pool-only sub-counter so the
		 * operator can derive the explorer contribution per arm. */
		__atomic_fetch_add(&shm->strategy_picks[STRATEGY_RANDOM], 1UL,
				   __ATOMIC_RELAXED);
		return set_syscall_nr_random(rec, child);
	}

	/* Mid-chain edgepair-guided pick: when run_sequence_chain is mid-way
	 * through a fresh-generation chain (step i >= 1, not replaying) and
	 * the previous syscall is known, try to pick the next syscall by
	 * scoring outgoing edgepairs from child->last_syscall_nr.  On
	 * success the function commits rec and returns true here, skipping
	 * the strategy_picks[] / strategy_at_pick stamp below so the chain
	 * mid-step dispatch inherits step 0's bandit attribution -- the
	 * spec is deliberate about not double-counting picks that the
	 * bandit didn't actually drive.
	 *
	 * On failure (no candidate survived the K-sample budget) we bump
	 * the per-call fails counter and fall through to the normal bandit
	 * dispatch path, which stamps strategy_picks[] exactly once for
	 * this call. */
	if (child->in_chain_mid_step &&
	    child->last_syscall_nr != EDGEPAIR_NO_PREV &&
	    edgepair_is_enabled()) {
		if (set_syscall_nr_edgepair_chain(rec, child))
			return true;
		__atomic_fetch_add(&shm->stats.edgepair_chain_pick_fails, 1UL,
				   __ATOMIC_RELAXED);
		/* Fall through to bandit dispatch. */
	}

	/* ACQUIRE pairs with the RELEASE store on current_strategy in
	 * maybe_rotate_strategy below.  Without it, a child observing the
	 * new strategy id is not guaranteed to also see the companion
	 * fields (current_selection_reason, plateau_rescue_amplified_class,
	 * plateau_intervention_mode_current) the orchestrator published
	 * just before the rotation -- the gates downstream that consult
	 * those fields would mis-fire under weak memory. */
	strat = __atomic_load_n(&shm->current_strategy, __ATOMIC_ACQUIRE);

	if (strat < 0 || strat >= NR_STRATEGIES)
		strat = STRATEGY_HEURISTIC;

	/* Stamp the picked arm before dispatching so the post-syscall PC
	 * and CMP reward sites read a stable value even if shm->current_
	 * strategy rotates mid-call.  Written exactly once per pick on the
	 * bandit-pool path; explorers (handled above) leave the -1 sentinel
	 * from clean_childdata in place. */
	child->strategy_at_pick = strat;

	/* Bandit-pool exposure: bump both the wide picks counter and the
	 * bandit-pool-only sub-counter so post-run analysis can separate
	 * bandit dispatches from explorer dispatches per arm.  Bumped
	 * before the picker-specific set_syscall_nr_* call -- a FAIL from
	 * that path still counts as a pick attributed to this arm; the
	 * matching strategy_completed_calls bump in dispatch_step lets
	 * the operator read off the per-arm dispatch success rate. */
	__atomic_fetch_add(&shm->strategy_picks[strat], 1UL, __ATOMIC_RELAXED);
	__atomic_fetch_add(&shm->strategy_bandit_pool_ops[strat], 1UL,
			   __ATOMIC_RELAXED);

	switch (strat) {
	case STRATEGY_HEURISTIC:
		return set_syscall_nr_heuristic(rec, child);
	case STRATEGY_RANDOM:
		return set_syscall_nr_random(rec, child);
	case STRATEGY_COVERAGE_FRONTIER:
		return set_syscall_nr_coverage_frontier(rec, child);
	case STRATEGY_EDGEPAIR_FRONTIER:
		return set_syscall_nr_edgepair_frontier(rec, child);
	default:
		__builtin_unreachable();
	}
}

/*
 * Probability (in percent) that, when a substitute retval is offered by
 * the sequence-chain executor, one randomly-chosen arg slot is overwritten
 * with it.  Exposed here (rather than in sequence.c) because the substitution
 * itself happens between argument generation and dispatch, which lives in
 * this file.  Tunable independently of the chain length distribution.
 */
#define CHAIN_SUBST_PCT 30

/*
 * Substituting the previous syscall's return value (almost always a
 * small integer — fd, retval, error code) into a pointer-typed arg
 * slot produces a wild pointer.  The rendering path then SEGVs in
 * printf("%s", small_int) → strlen(0x402), or the kernel deref'es a
 * wild address, depending on which slot got stomped.  Restrict
 * substitution to slots whose argtype legitimately accepts a numeric
 * value.
 */
static bool argtype_accepts_numeric_substitute(enum argtype t)
{
	switch (t) {
	case ARG_UNDEFINED:
	case ARG_FD:
	case ARG_LEN:
	case ARG_MODE_T:
	case ARG_PID:
	case ARG_KEY_SERIAL:
	case ARG_TIMERID:
	case ARG_AIO_CTX:
	case ARG_SEM_ID:
	case ARG_MSG_ID:
	case ARG_SYSV_SHM:
	case ARG_RANGE:
	case ARG_OP:
	case ARG_LIST:
	case ARG_CPU:
	case ARG_NUMA_NODE:
	case ARG_IOVECLEN:
	case ARG_SOCKADDRLEN:
	case ARG_STRUCT_SIZE:
	case ARG_FD_BPF_BTF:
	case ARG_FD_BPF_LINK:
	case ARG_FD_BPF_MAP:
	case ARG_FD_BPF_PROG:
	case ARG_FD_EPOLL:
	case ARG_FD_EVENTFD:
	case ARG_FD_FANOTIFY:
	case ARG_FD_FS_CTX:
	case ARG_FD_INOTIFY:
	case ARG_FD_IO_URING:
	case ARG_FD_LANDLOCK:
	case ARG_FD_MEMFD:
	case ARG_FD_MOUNT:
	case ARG_FD_MQ:
	case ARG_FD_PERF:
	case ARG_FD_PIDFD:
	case ARG_FD_PIPE:
	case ARG_FD_SIGNALFD:
	case ARG_FD_SOCKET:
	case ARG_FD_TIMERFD:
		return true;
	case ARG_ADDRESS:
	case ARG_NON_NULL_ADDRESS:
	case ARG_PATHNAME:
	case ARG_IOVEC:
	case ARG_IOVEC_IN:
	case ARG_SOCKADDR:
	case ARG_MMAP:
	case ARG_SOCKETINFO:
	case ARG_STRUCT_PTR_IN:
	case ARG_STRUCT_PTR_OUT:
	case ARG_STRUCT_PTR_INOUT:
		return false;
	}
	return false;
}

/*
 * Build the numeric-substitute slot bitmap for entry's argtype[] table.
 * Called once per syscallentry at table-init time from
 * copy_syscall_table() in tables.c; the cached mask in
 * entry->numeric_substitute_mask then drives apply_chain_substitution()
 * below without re-walking argtype[] or re-running the 23-case
 * argtype_accepts_numeric_substitute() switch on every chain step.
 * Bit k (k=0..5) set means slot (k+1) accepts a numeric substitute.
 */
uint8_t compute_numeric_substitute_mask(const struct syscallentry *entry)
{
	uint8_t mask = 0;
	unsigned int i;

	if (entry == NULL)
		return 0;

	for (i = 0; i < entry->num_args && i < 6; i++) {
		if (argtype_accepts_numeric_substitute(entry->argtype[i]))
			mask |= (uint8_t)(1u << i);
	}
	return mask;
}

/*
 * Apply Phase 1 retval substitution to rec in place.  Used by both the
 * fresh-args path (random_syscall_step) and the corpus-replay path
 * (replay_syscall_step) so the chain semantics — substituted args reach
 * the kernel and show up in the trace — are identical regardless of
 * where the args came from.  No-op when no substitute is offered, the
 * dice roll comes up against, the syscall takes zero args, or no arg
 * slot has a numeric-substitute-compatible argtype.
 */
static void apply_chain_substitution(struct syscallrecord *rec,
				     struct syscallentry *entry,
				     bool have_substitute,
				     unsigned long substitute_retval)
{
	unsigned int nsafe, pick, slot, i;
	uint8_t mask;

	if (!have_substitute)
		return;
	if (entry == NULL || entry->num_args == 0)
		return;
	if (rnd_modulo_u32(100) >= CHAIN_SUBST_PCT)
		return;

	mask = entry->numeric_substitute_mask;
	if (mask == 0)
		return;
	if (substitute_retval == (unsigned long)mainpid) {
		for (i = 0; i < entry->num_args && i < 6; i++) {
			if (entry->argtype[i] == ARG_PID)
				mask &= (uint8_t)~(1u << i);
		}
		if (mask == 0)
			return;
	}

	/*
	 * Pick uniformly from the eligible-slot set: count the active
	 * bits in mask, draw a uniform index in [0, nsafe), then walk
	 * mask to find the index-th set bit.  Restores the uniformity of
	 * the original safe_slots[rand() % nsafe] dispatch (4ad1cc3f0628
	 * cached the mask but silently swapped the draw for a
	 * __builtin_ctz pick, which biases hard toward low-numbered slots
	 * -- bit 0 wins with p=0.5, bit 1 with p=0.25, and so on).
	 */
	nsafe = (unsigned int)__builtin_popcount(mask);
	pick = rnd_modulo_u32(nsafe);
	slot = 0;
	for (i = 0; i < 6; i++) {
		if ((mask & (1u << i)) == 0)
			continue;
		if (pick == 0) {
			slot = i + 1;
			break;
		}
		pick--;
	}

	switch (slot) {
	case 1: rec->a1 = substitute_retval; break;
	case 2: rec->a2 = substitute_retval; break;
	case 3: rec->a3 = substitute_retval; break;
	case 4: rec->a4 = substitute_retval; break;
	case 5: rec->a5 = substitute_retval; break;
	case 6: rec->a6 = substitute_retval; break;
	}
	if (minicorpus_shm != NULL)
		__atomic_fetch_add(&minicorpus_shm->chain_substitution_count,
				   1, __ATOMIC_RELAXED);
}

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
static void maybe_rotate_strategy(void)
{
	unsigned long now;
	unsigned long last;
	int prev, next;
	int prev_reason_raw;
	enum strategy_selection_reason prev_reason;
	enum strategy_selection_reason next_reason = SR_NORMAL_UCB;
	unsigned long calls_now, calls_in_window;
	unsigned long calls_dampened_q8_now, calls_dampened_q8_in_window;
	unsigned long edges_now, edges_in_window;
	unsigned long syscalls_in_window;
	unsigned long cmp_now, cmp_in_window;

	/* Read fleet op_count off the parent-published mirror page; the
	 * canonical aggregate is parent-private and not visible to children.
	 * The mirror is republished once per parent main_loop iteration so
	 * a stale read here only delays the rotation by drain cadence. */
	now = (shm_published != NULL)
	      ? __atomic_load_n(&shm_published->fleet_op_count, __ATOMIC_RELAXED)
	      : 0;
	last = __atomic_load_n(&shm->syscalls_at_last_switch, __ATOMIC_RELAXED);

	if (now - last < STRATEGY_WINDOW)
		return;

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

	calls_now = __atomic_load_n(&shm->pc_edge_calls_by_strategy[prev],
				    __ATOMIC_RELAXED);
	calls_in_window = calls_now -
		__atomic_load_n(&shm->pc_edge_calls_at_window_start,
				__ATOMIC_RELAXED);
	calls_dampened_q8_now = __atomic_load_n(
		&shm->pc_edge_calls_dampened_q8_by_strategy[prev],
		__ATOMIC_RELAXED);
	calls_dampened_q8_in_window = calls_dampened_q8_now -
		__atomic_load_n(&shm->pc_edge_calls_dampened_q8_at_window_start,
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
			   calls_dampened_q8_in_window,
			   edges_in_window, cmp_in_window);

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

	next = select_next_strategy(prev, &next_reason);
	if (next < 0 || next >= NR_STRATEGIES) {
		next = (prev + 1) % NR_STRATEGIES;
		next_reason = SR_ROUND_ROBIN;
	}

	__atomic_store_n(&shm->pc_edge_calls_at_window_start,
			 __atomic_load_n(&shm->pc_edge_calls_by_strategy[next],
					 __ATOMIC_RELAXED),
			 __ATOMIC_RELAXED);
	__atomic_store_n(&shm->pc_edge_calls_dampened_q8_at_window_start,
			 __atomic_load_n(
				 &shm->pc_edge_calls_dampened_q8_by_strategy[next],
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
}

/*
 * Dispatch a fully-prepared syscallrecord and run the per-call
 * post-dispatch bookkeeping: kcov collection / cmp-hint collection,
 * edge-pair recording, mutator-attribution commit, mini-corpus save,
 * trace output, fd-ring update, group/last_syscall_nr tracking.
 *
 * Caller has already populated rec->nr, rec->do32bit, rec->a1..a6, the
 * postbuffer is already cleared, and any chain substitution has been
 * applied.  The two callers (random_syscall_step and replay_syscall_step)
 * differ only in how they got the args into rec; everything from
 * output_syscall_prefix forward is shared.
 */
static bool dispatch_step(struct childdata *child, struct syscallentry *entry,
			  bool *found_new)
{
	struct syscallrecord *rec = &child->syscall;
	bool new_edges;
	unsigned long new_edge_count = 0;

	/* Stamp the resolved entry on the rec so .sanitise / .post handlers
	 * (and helpers like this_syscallname()) can reach it without
	 * re-running get_syscall_entry(nr, do32bit) on every probe. */
	rec->entry = entry;

	/* Clear the per-call validator-reject flag.  do_syscall() sets this
	 * when validate_arg_coupling() rejects the call before the kernel is
	 * entered; the kcov_collect() gate below reads it to skip the
	 * total_calls / per_syscall_calls[nr] bumps that would otherwise
	 * poison kcov_syscall_cold_skip_pct() for strict-validator syscalls. */
	rec->validator_rejected = false;

	output_syscall_prefix(rec, entry);

	/* PC mode: per-child kcov fd collects edge coverage, optionally
	 * via KCOV_REMOTE_ENABLE to also pick up softirq / threaded-irq /
	 * kthread coverage triggered by this syscall.  CMP mode: per-child
	 * cmp fd collects comparison-operand records that feed the
	 * cmp_hints pool.  Mode is fixed at child init; remote_mode is
	 * only meaningful in PC mode (KCOV_REMOTE_ENABLE applies to the PC
	 * fd, not the cmp fd).
	 *
	 * Sample rate is per-syscall: calls whose interesting kernel work
	 * is deferred to kthreads / workqueues / softirqs (netlink async
	 * delivery, io_uring workers, BPF attach, mount workqueues, cgroup
	 * migration, namespace setup) are flagged with KCOV_REMOTE_HEAVY
	 * and sampled at the heavier 1-in-KCOV_REMOTE_RATIO_HEAVY rate so
	 * those deferred-work edges don't get stuck cold; everything else
	 * uses the default 1-in-KCOV_REMOTE_RATIO trickle. */
	if (child->kcov.mode == KCOV_MODE_PC) {
		unsigned int remote_reciprocal =
			(entry->flags & KCOV_REMOTE_HEAVY) ?
				KCOV_REMOTE_RATIO_HEAVY : KCOV_REMOTE_RATIO;
		child->kcov.remote_mode = child->kcov.remote_capable &&
					  ONE_IN(remote_reciprocal);
	} else {
		child->kcov.remote_mode = false;
	}

	do_syscall(rec, entry, &child->kcov, child);

	/* kcov_collect() returns the real per-call bucket-edge count via the
	 * out-param alongside its bool found_new return.  Diff-ing the global
	 * kcov_shm->edges_found around the call would race other children's
	 * concurrent increments and over-attribute their edges to this
	 * syscall; the per-call count is the authoritative number.
	 *
	 * CMP-mode children contribute zero PC edges (their PC fd is never
	 * enabled), so new_edge_count stays 0 and the per-strategy edge
	 * attribution block below naturally skips on its `new_edge_count > 0`
	 * gate.  Frontier ring updates and bandit reward attribution also
	 * skip cleanly via `if (new_edges)` further down -- CMP-mode
	 * children deliberately don't contribute to those PC-edge concepts.
	 *
	 * CMP-source corpus saves are the exception: kcov_collect_cmp
	 * returns the per-call count of bloom-novel KCOV_CMP_CONST
	 * comparisons, captured here in new_cmp.  Under a PC-edge plateau
	 * (cmp_rising_pc_flat) that count is the only available novelty
	 * signal -- the save gate below widens to `new_edges || new_cmp
	 * > 0` so the corpus can still grow and mutator wins can still be
	 * credited, breaking the self-reinforcing
	 * PC-plateau->no-saves->no-mutator-wins loop.  See
	 * investigations/corpus-mutator-zero-wins-2026-05-20 for the full
	 * analysis. */
	unsigned long new_cmp = 0;

	/* Snapshot the rescue classifier's cold-skip-pct input BEFORE
	 * kcov_collect runs.  On a new edge kcov_collect bumps
	 * last_edge_at[rec->nr] to the current total_calls, after which
	 * kcov_syscall_cold_skip_pct(rec->nr) returns 0 -- the exact case
	 * classify_random_rescue exists to recognise as RRC_COLD_SKIP.
	 * Reading it here, at draw time, keeps the classifier's "would the
	 * picker have skipped this?" question pinned to the picker's actual
	 * pre-call state.  Only meaningful in PC mode; the CMP path never
	 * reaches the classifier (new_edges stays false there). */
	unsigned int rescue_cold_skip_pct_before = 0;

	if (child->kcov.mode == KCOV_MODE_PC) {
		rescue_cold_skip_pct_before =
			kcov_syscall_cold_skip_pct(rec->nr);
		/* Pre-validation reject in do_syscall() -- the kernel was never
		 * entered, so there is no coverage to collect and bumping
		 * total_calls / per_syscall_calls[nr] inside kcov_collect()
		 * would poison kcov_syscall_cold_skip_pct() on syscalls whose
		 * validators are strict.  last_edge_at[] only moves on the
		 * found_new branch and stays correctly frozen here. */
		if (rec->validator_rejected)
			new_edges = false;
		else
			new_edges = kcov_collect(&child->kcov, rec->nr,
						 &new_edge_count);
	} else {
		new_cmp = kcov_collect_cmp(&child->kcov, rec->nr,
					   rec->do32bit,
					   child->is_explorer,
					   child->strategy_at_pick);
		new_edges = false;
	}

	/* Per-syscall new-edge attribution split by strategy pool.  Skipped
	 * when the call produced no new edges (the dump only consumes the
	 * positive delta side) and when rec->nr falls outside the table.
	 * Biarch attribution follows the same raw-rec->nr indexing the
	 * existing kcov_shm->per_syscall_edges array uses; the dump iterates
	 * only the active 64-bit table when biarch, so 32-bit calls are
	 * effectively ignored there as they are everywhere else. */
	if (new_edge_count > 0 && rec->nr < MAX_NR_SYSCALL) {
		unsigned long *bucket = child->is_explorer
			? shm->stats.edges_per_syscall_explorer
			: shm->stats.edges_per_syscall_bandit;
		__atomic_fetch_add(&bucket[rec->nr], new_edge_count,
				   __ATOMIC_RELAXED);
	}

	/* Surface this step's new-coverage signal to the chain executor
	 * (when called via run_sequence_chain). */
	if (found_new != NULL)
		*found_new = new_edges;

	/* Snapshot the rescue classifier's pair-state inputs BEFORE
	 * edgepair_record() runs.  edgepair_record() queues a pair event
	 * on a per-child SPSC ring that the parent has not necessarily
	 * drained before classify_random_rescue() asks
	 * edgepair_get_stats() / edgepair_is_cold(); a live read in the
	 * classifier can therefore see either pre-call or post-call pair
	 * state depending on drain latency.  Pinning both answers at draw
	 * time keeps RRC_PAIR_UNSEEN / RRC_PAIR_COLD classification
	 * aligned with the state the picker actually saw, the same shape
	 * as rescue_cold_skip_pct_before above.  Both stay false when the
	 * child has no predecessor -- the classifier ignores the pair
	 * branches in that case. */
	bool rescue_pair_was_unseen = false;
	bool rescue_pair_was_cold = false;
	if (child->last_syscall_nr != EDGEPAIR_NO_PREV) {
		struct edgepair_stats ps_before =
			edgepair_get_stats(child->last_syscall_nr, rec->nr);
		rescue_pair_was_unseen =
			(ps_before.new_edges == 0 && ps_before.total == 0);
		rescue_pair_was_cold =
			edgepair_is_cold(child->last_syscall_nr, rec->nr);
	}

	/* Record the (prev, curr) syscall pair for sequence coverage.
	 * CMP-mode children collect comparison records, not PC edges,
	 * so new_edges is structurally false above; recording the pair
	 * would inflate total_pair_calls / total_count without ever
	 * being able to bump new_edge_count, polluting the productivity
	 * signal that edgepair_is_cold, the bandit reward dampener, and
	 * the frontier/chain pickers all consume.  Skip the write
	 * entirely on CMP children; the pre-snapshot reads above stay
	 * valid because they don't mutate state. */
	if (child->last_syscall_nr != EDGEPAIR_NO_PREV &&
	    child->kcov.mode != KCOV_MODE_CMP)
		edgepair_record(child, child->last_syscall_nr, rec->nr, new_edges);

	/* CMP-bloom novelty is an equivalent corpus-save / mutator-win
	 * signal alongside PC-edge novelty.  Under a PC-edge plateau the
	 * PC-only gate fires for ~0% of calls; the OR-with-CMP gate keeps
	 * the corpus growing on arg neighbourhoods that exercise new
	 * compile-time-constant comparisons (the cmp_rising_pc_flat
	 * frontier).  PC-edge-specific bookkeeping below (frontier ring,
	 * snapshot cadence, per-strategy edge attribution, explorer/bandit
	 * pool edge counters) STAYS gated on new_edges -- those are
	 * PC-edge concepts by definition and contaminating them with
	 * CMP-source events would silently bias the bandit reward and
	 * corrupt the plateau diagnostics. */
	bool found_something = new_edges || (new_cmp > 0);

	/* If the win signal came from CMP novelty rather than PC novelty,
	 * tag the pending mutator attribution.  Tag-before-commit + the
	 * unconditional clear inside commit() together mean a stale tag
	 * from a !found_something path never leaks into the next call. */
	if (new_cmp > 0)
		minicorpus_mut_attrib_set_cmp_source();

	/* Credit each mutator case picked during this call's arg
	 * generation, with wins iff this call produced ANY novelty
	 * signal (PC-edge OR CMP-bloom).  PC-only credit was the matching
	 * half of the PC-only save gate; expanding both together keeps
	 * mutator productivity stats and corpus growth in lockstep. */
	minicorpus_mut_attrib_commit(found_something);

	/* Save args that produced any novelty signal, but only for
	 * syscalls without sanitise (which may stash pointers).  Tag with
	 * the source so saves_by_reason[] separates PC-promoted from
	 * CMP-promoted entries; PC wins the tag on calls where both
	 * signals fire so the historical accounting is preserved. */
	if (unlikely(found_something)) {
		if (entry->sanitise == NULL)
			minicorpus_save_with_reason(rec,
				new_edges ? CORPUS_SAVE_REASON_PC
					  : CORPUS_SAVE_REASON_CMP);
	}

	/* PC-edge-only bookkeeping below.  Deliberately separate from the
	 * found_something save block above so CMP-source saves can't
	 * trigger snapshot cadence, per-strategy edge attribution, or
	 * pool edge counters -- see comment above on why those must
	 * stay PC-only. */
	if (unlikely(new_edges)) {
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
			__atomic_fetch_add(&shm->stats.explorer_pool_edges_discovered,
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

				/* Novelty-dampened call count.  Look up the
				 * historical (prev, curr) edgepair stats and
				 * scale the bump by the productivity ratio
				 * ratio = new_edges / (total + 1):
				 *   dampen     = 0.5 + 0.5 * ratio
				 *   dampen_q8  = 128 + (128 * new_edges) / (total + 1)
				 * Clamped to [128, 256] so a never-seen pair
				 * (no prev, or no edgepair record) gets the
				 * full 1.0 (256) credit and a fully-stale pair
				 * floors at 0.5x rather than zeroing -- the
				 * floor preserves a learning signal for rare
				 * novelty bursts from otherwise-saturated
				 * pairs while still discounting the bulk of
				 * the reward the bandit would otherwise bank
				 * from those pairs. */
				unsigned int dampen_q8 = 256U;
				if (child->last_syscall_nr != EDGEPAIR_NO_PREV) {
					struct edgepair_stats ps =
						edgepair_get_stats(
							child->last_syscall_nr,
							rec->nr);
					if (ps.total > 0) {
						unsigned long denom = ps.total + 1UL;
						dampen_q8 = 128U + (unsigned int)
							((128UL * ps.new_edges) / denom);
						if (dampen_q8 < 128U)
							dampen_q8 = 128U;
						if (dampen_q8 > 256U)
							dampen_q8 = 256U;
					}
				}
				__atomic_fetch_add(
					&shm->pc_edge_calls_dampened_q8_by_strategy[strat],
					dampen_q8, __ATOMIC_RELAXED);
				if (dampen_q8 < 256U) {
					__atomic_fetch_add(
						&shm->stats.bandit_dampened_bumps_count,
						1UL, __ATOMIC_RELAXED);
					__atomic_fetch_add(
						&shm->stats.bandit_dampened_q8_shortfall_sum,
						256UL - dampen_q8,
						__ATOMIC_RELAXED);
				}
			}
			__atomic_fetch_add(&shm->stats.bandit_pool_edges_discovered,
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
						rescue_cold_skip_pct_before,
						rescue_pair_was_unseen,
						rescue_pair_was_cold);
				if (rrc >= 0 && rrc < RRC_NR_CLASSES)
					__atomic_fetch_add(
						&shm->random_rescue_class_count[rrc],
						1UL, __ATOMIC_RELAXED);
			}
		}
	}

	output_syscall_postfix(rec);

	handle_syscall_ret(rec, entry);

	/* Snapshot the completed call into the per-child ring so the parent
	 * has a chronological window of recent activity if a kernel taint
	 * fires before the next syscall. */
	child_syscall_ring_push(&child->syscall_ring, rec);

	/* Also append a compact record to the per-child pre-crash ring,
	 * dumped on __BUG() to attribute the assertion to a specific
	 * recent syscall.  rec->tp was just refreshed in do_syscall(). */
	pre_crash_ring_record(child, rec, &rec->tp);

	/* Single combined enqueue: op_count + success/failure +
	 * syscall_category_count[] all ride on one STATS_FIELD_CALL_COMPLETE
	 * slot.  The drain expands it back into three logical bumps.
	 * Result class is derived post-handle_syscall_ret(), which has
	 * already coerced rec->retval for retfd_rejected and is the
	 * canonical settle point for rec->state. */
	{
		enum stats_result_class result;

		if (rec->state != AFTER)
			result = STATS_RESULT_INCOMPLETE;
		else if (rec->retval == (unsigned long)-1L)
			result = STATS_RESULT_FAILURE;
		else
			result = STATS_RESULT_SUCCESS;

		stats_ring_enqueue_call_complete(child->stats_ring,
						 (uint16_t)entry->syscall_category,
						 result);
	}

	/* FD leak tracking: count successful fd-creating and
	 * fd-closing syscalls per child for leak diagnosis. */
	if (rec->retval != -1UL) {
		if (entry->rettype == RET_FD) {
			child->fd_created++;
			if (entry->group < NR_GROUPS)
				child->fd_created_by_group[entry->group]++;
			/* Track returned fd for preferential reuse in arg generation. */
			if ((int)rec->retval > 2)
				child_fd_ring_push(&child->live_fds, (int)rec->retval);
		}
		if (entry->is_close_syscall)
			child->fd_closed++;
	}

	/* Track the group for biasing. */
	if (group_bias)
		child->last_group = entry->group;

	/* Mirror the just-completed syscall into child->last_syscall_nr,
	 * read by dispatch_step's edgepair_record() as the prev_nr of the
	 * next (prev, curr) pair-bump, and by set_syscall_nr_random's
	 * edgepair_is_cold check on the syscall-selection biasing path.
	 *
	 * Skip syscalls that returned -ENOSYS or -EOPNOTSUPP: the kernel
	 * dispatcher rejected the call before its body executed, so kernel
	 * state is unchanged from the previous syscall.  Crediting them as
	 * state-setting predecessors of a subsequent new-edge event would
	 * dilute attribution toward calls that did nothing — at top-N dump
	 * time these noise pairs crowd out genuinely interesting
	 * predecessor relationships. */
	if (rec->retval == -1UL &&
	    (rec->errno_post == ENOSYS || rec->errno_post == EOPNOTSUPP)) {
		/* nothing — keep the previous predecessor in place */
	} else {
		child->last_syscall_nr = rec->nr;
	}

	/* Per-arm completion exposure: bump the arm this call was attributed
	 * to.  Two distinct cases reach here with strategy_at_pick == -1:
	 *
	 *   - Explorer-pool children: set_syscall_nr() leaves the sentinel
	 *     in place and bumps strategy_picks[STRATEGY_RANDOM] directly.
	 *     The completion bump mirrors that pick by crediting RANDOM
	 *     here so picks and completions stay symmetric for the explorer
	 *     contribution.
	 *
	 *   - Replay steps from run_sequence_chain(): replay_syscall_step()
	 *     deliberately clears strategy_at_pick to -1 to avoid crediting
	 *     replay work to whichever arm started the chain.  Replays did
	 *     not bump strategy_picks[] either, so the completion bump must
	 *     skip them to keep picks and completions paired.
	 *
	 * Gate the fallback on child->is_explorer specifically rather than
	 * sap < 0 so the two cases stay separated.  Replay-step visibility
	 * lives in chain_corpus_shm->replay_steps_dispatched. */
	{
		int sap = child->strategy_at_pick;
		if (sap < 0 && child->is_explorer)
			sap = STRATEGY_RANDOM;
		if (sap >= 0 && sap < NR_STRATEGIES)
			__atomic_fetch_add(
				&shm->strategy_completed_calls[sap],
				1UL, __ATOMIC_RELAXED);
	}

	/* Cheap end-of-call check for the strategy rotation boundary.
	 * Two relaxed loads + a compare in the common case; the CAS only
	 * fires once per ~STRATEGY_WINDOW ops fleet-wide. */
	maybe_rotate_strategy();

	return true;
}

bool random_syscall_step(struct childdata *child,
			 bool have_substitute,
			 unsigned long substitute_retval,
			 bool *found_new)
{
	struct syscallrecord *rec = &child->syscall;
	struct syscallentry *entry;

	if (set_syscall_nr(rec, child) == FAIL)
		return FAIL;

	rec->postbuffer[0] = '\0';

	/* Generate arguments, print them out */
	generate_syscall_args(rec);

	/* Sequence-chain substitution.  When the previous step in the chain
	 * returned a usable value, with CHAIN_SUBST_PCT probability splice
	 * it into one randomly-chosen arg slot of this call, overwriting
	 * whatever the generator produced.  Done after generate_syscall_args
	 * so the substituted value is what the kernel actually sees, and
	 * before output_syscall_prefix so the trace reflects the real call. */
	entry = get_syscall_entry(rec->nr, rec->do32bit);
	apply_chain_substitution(rec, entry, have_substitute, substitute_retval);

	return dispatch_step(child, entry, found_new);
}

bool random_syscall(struct childdata *child)
{
	return random_syscall_step(child, false, 0, NULL);
}

/*
 * Replay a saved chain step: stage the saved (nr, do32bit, args) into
 * rec, run the saved args through the per-arg mutator chain, apply any
 * Phase 1 retval substitution from the prior step, and dispatch through
 * the same path random_syscall_step uses.  Returns FAIL when the saved
 * syscall is no longer callable in this run (deactivated, AVOID_SYSCALL,
 * needs root we don't have, or has a sanitise that would stash stale
 * pointers); the chain executor falls back to fresh args in that case.
 *
 * The mutator call goes to minicorpus_mutate_args, which is the same
 * splice + weighted-stack-mutate engine the per-syscall mini-corpus
 * replay uses.  Sharing the mutator means chain replay automatically
 * inherits productivity tuning from the existing weighted scheduler
 * rather than duplicating the mutation logic with its own counters.
 */
bool replay_syscall_step(struct childdata *child,
			 const struct chain_step *saved,
			 bool have_substitute,
			 unsigned long substitute_retval,
			 bool *found_new)
{
	struct syscallrecord *rec = &child->syscall;
	struct syscallentry *entry;
	unsigned long args[6];

	if (saved->nr >= MAX_NR_SYSCALL)
		return FAIL;

	entry = get_syscall_entry(saved->nr, saved->do32bit);
	if (entry == NULL)
		return FAIL;

	/* sanitise-bearing syscalls allocate and stash heap pointers into
	 * arg slots during generic_sanitise; replay would feed stale args
	 * to those slots.  Same gate the mini-corpus uses for the same
	 * reason. */
	if (entry->sanitise != NULL)
		return FAIL;

	/* The syscall may have been deactivated since the chain was saved
	 * (returned ENOSYS, hit AVOID_SYSCALL, lost a CAP_*).  Bail out
	 * rather than replay an inert call. */
	if (!validate_specific_syscall_silent(
			saved->do32bit ? syscalls_32bit :
			(biarch ? syscalls_64bit : syscalls),
			(int)saved->nr))
		return FAIL;

	memcpy(args, saved->args, sizeof(args));
	minicorpus_mutate_args(args, entry, saved->nr);

	/* Replay steps bypass set_syscall_nr() (which is where the bandit's
	 * per-arm pick stamp normally lands), so the child still holds the
	 * strategy_at_pick value from whichever fresh pick started the
	 * chain.  Letting that stale stamp ride through dispatch_step would
	 * credit replay-step PC/CMP novelty -- and the per-arm completion
	 * bump -- to an arm that did not actually pick the replayed syscall,
	 * contaminating the reward signal the bandit is meant to learn
	 * from.  Reset to the -1 sentinel so the existing strategy_at_pick
	 * gates at the consumer sites (kcov_collect_cmp / bandit_cmp_observe,
	 * the PC-edge per-strategy attribution in dispatch_step, the per-arm
	 * completion bump) all skip attribution for this step.
	 *
	 * The next fresh set_syscall_nr() overwrites strategy_at_pick
	 * unconditionally on the bandit-pool path, so leaving -1 here does
	 * not leak into subsequent non-replay calls. */
	child->strategy_at_pick = -1;

	if (chain_corpus_shm != NULL)
		__atomic_fetch_add(&chain_corpus_shm->replay_steps_dispatched,
				   1UL, __ATOMIC_RELAXED);

	/* Hold rec->lock across the (nr, do32bit) advance, the arg writes,
	 * the postbuffer reset, and the chain substitution.  An outside
	 * reader (watchdog thread, parent inspecting via shm, pre_crash_ring
	 * decode) that samples rec mid-step must not see the new (nr,
	 * do32bit) paired with the previous syscall's a1..a6 — that torn
	 * pairing miscredits args to the wrong syscall in divergence stats
	 * and crash-ring reconstruction.  apply_chain_substitution writes
	 * rec->aN, so the unlock has to come after it. */
	lock(&rec->lock);
	rec->do32bit = saved->do32bit;
	rec->nr = saved->nr;

	rec->a1 = args[0];
	rec->a2 = args[1];
	rec->a3 = args[2];
	rec->a4 = args[3];
	rec->a5 = args[4];
	rec->a6 = args[5];

	rec->postbuffer[0] = '\0';

	apply_chain_substitution(rec, entry, have_substitute, substitute_retval);
	unlock(&rec->lock);

	return dispatch_step(child, entry, found_new);
}
