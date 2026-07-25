/*
 * Picker arms and their helpers.  set_syscall_nr() is the top-level
 * dispatcher called from dispatch_step; it selects one of
 * set_syscall_nr_heuristic (STRATEGY_HEURISTIC), set_syscall_nr_random
 * (STRATEGY_RANDOM), or set_syscall_nr_coverage_frontier
 * (STRATEGY_COVERAGE_FRONTIER) based on the active strategy.  All
 * accept/retry budget logic lives here so future cooling/throttle work
 * edits one file.  set_syscall_nr and set_syscall_nr_random are
 * public via include/syscall.h; set_syscall_nr is cross-cluster
 * private and declared in include/random-syscall-internal.h.
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
#include "strategy.h"
#include "syscall.h"
#include "syscall_record.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

/*
 * Compression factor for the frontier-weighted acceptance denominator.
 * See the gate in set_syscall_nr_coverage_frontier() for the rationale.
 */
#define FRONTIER_SOFT_SCALE 16

/*
 * Pick the syscall to run under STRATEGY_COVERAGE_FRONTIER: uniform draw
 * from active_syscalls, then biased acceptance against the per-syscall
 * frontier-edge weight via rejection sampling.  Each candidate is
 * accepted with probability (frontier_recent_count(nr) + 1) /
 * (ilog2_ul(max_weight) * FRONTIER_SOFT_SCALE + 1); the softened
 * denominator stops a single very hot syscall from compressing every
 * cold-but-real candidate to near-zero acceptance and burning the retry
 * budget, while the +1 on both numerator and denominator keeps cold
 * syscalls from starving completely and lets the strategy still drive
 * forward when no syscall has produced a frontier edge in the last K
 * windows.
 *
 * max_weight is read once at the top of the function from the cached
 * shm->frontier_max_weight_cached so the bias mass stays stable across
 * the inner retry loop, and so concurrent kcov_collect-driven bumps to
 * frontier_history during the pick don't perturb the acceptance
 * probability mid-call.  The cache is a single RELAXED load,
 * recomputed authoritatively on each window rotation by
 * frontier_window_advance() and ratcheted upward on new-edge bumps
 * by frontier_record_new_edge().
 *
 * Plateau fallback (max_weight <= 2): the frontier ring decays to zero
 * everywhere at the plateau (a window with no new edges ages every slot
 * to 0 within FRONTIER_DECAY_WINDOWS rotations), which is exactly the
 * regime PIM_COVERAGE_FRONTIER pins ~25% of intervention windows on
 * FRONTIER for.  In that branch the fallback applies a cold/untried-
 * syscall bias keyed on per_syscall_edges/per_syscall_calls so the
 * picker still steers toward under-explored syscalls when the
 * recent-frontier signal is gone; a plain uniform draw here would
 * leave FRONTIER strictly worse than RANDOM (no anti-prior bias, no
 * explorer-pool backing, no near-coverage signal -- nothing to steer
 * on).
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
		nr_syscalls = load_active_syscall_count(
			&shm->nr_active_syscalls, "nr_active_syscalls");
	}
	/* See the matching guard in set_syscall_nr_heuristic above --
	 * corrupt shared count is already logged by the helper; bail
	 * before the rnd_modulo_u32 draw feeds an OOB index into
	 * child->active_syscalls[]. */
	if (nr_syscalls > MAX_NR_SYSCALL)
		return FAIL;

	max_weight = __atomic_load_n(&shm->frontier_max_weight_cached,
				     __ATOMIC_RELAXED);

retry:
	if (no_syscalls_enabled() == true) {
		/*
		 * Unbuffered stderr: the racing children about to
		 * spin-bail via _exit(shm->exit_reason) skip stdio flush,
		 * so a stdout output() here is lost.  outputerr() lands
		 * the trigger message before the exit_reason store races
		 * the child fleet into termination.
		 */
		outputerr("[%d] No more syscalls enabled. Exiting\n", mypid());
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

	/* EXPENSIVE early-out: expensive_accept() bitmap-tests before
	 * validate + entry fetch, so the reject path skips the
	 * syscallentry cache miss.  Helper consolidates the policy;
	 * default --expensive-adaptive=off applies the
	 * `syscall_is_expensive(...) && !ONE_IN(1000)` predicate. */
	if (!expensive_accept(syscallnr, do32))
		goto retry;

	if (validate_specific_syscall_silent(syscalls, syscallnr) == false) {
		note_validation_failure(syscallnr, do32);
		goto retry;
	}
	note_validation_success(syscallnr, do32);

	/* --cred-throttle gate.  Same contract as the matching call sites in
	 * set_syscall_nr_heuristic / set_syscall_nr_random above: returns
	 * false unconditionally when the flag is off so the frontier
	 * picker's distribution is byte-identical to today's default. */
	if (cred_throttle_should_reject(syscallnr, do32))
		goto retry;

	/* Frontier-weighted acceptance.  Two regimes share the same
	 * accept-probability shape ((w+1)/(denom+1)) so the inner-loop
	 * retry budget behaves identically across both:
	 *
	 *  - Live ring (max_weight > 2): weight = frontier_recent_count(nr),
	 *    the per-syscall sum across the K-window frontier ring.  Soften
	 *    the denominator via ilog2 so that a single very hot syscall
	 *    (max_weight in the 10k+ range) doesn't compress every cold-but-
	 *    real candidate to a near-zero acceptance probability and burn
	 *    the retry budget.  soft_max = ilog2(max) * SCALE keeps the
	 *    leader winning the majority of rolls while lifting a w=1
	 *    candidate from ~1/max to ~1/soft_max.  The +1 smoothing on w
	 *    is preserved as the uniform floor.
	 *
	 *  - Silent ring (max_weight <= 2): the frontier ring has aged out
	 *    everywhere, the defining state of a coverage plateau.  Without
	 *    a fallback the picker degenerates to a backing-less uniform
	 *    draw and ends up strictly worse than RANDOM (no anti-prior
	 *    bias, no explorer-pool backing, no near-coverage signal --
	 *    nothing to steer on) at exactly the windows the plateau
	 *    intervention pins it to.  Steer on lifetime cumulative ratios
	 *    instead: weight = INVERSE per-syscall productive-call ratio,
	 *    so the picker biases toward syscalls the fleet has under-
	 *    explored and away from the few syscalls that already produced
	 *    most of the saturated coverage. */
	if (max_weight > 2) {
		unsigned long w = frontier_recent_count(syscallnr);
		unsigned long soft_max = (unsigned long)ilog2_ul(max_weight) *
					 FRONTIER_SOFT_SCALE;
		unsigned long denom = soft_max + 1UL;
		unsigned long roll = (unsigned long)rnd_modulo_u32(denom);

		if (roll >= w + 1UL)
			goto retry;

		/* Blanket LIVE-regime probabilistic pick-reject.  Reclaims
		 * ~1 / FRONTIER_LIVE_DECAY_REJECT_DENOM of LIVE-ring picks
		 * unconditionally via the SAME goto-retry mechanism the
		 * frontier-weight roll above already uses, so the picker's
		 * inner retry budget absorbs the rejected pick the same way
		 * it absorbs a weight-loss reject and the counters past this
		 * point stay consistent.
		 *
		 * Placed AFTER the frontier-weight accept decision and
		 * BEFORE the frontier_live_picks bump so a rejected pick is
		 * counted only in frontier_live_decay_live_rejects, not in
		 * frontier_live_picks / frontier_live_picks_per_syscall.
		 * That keeps the documented (live_picks + silent_picks ~=
		 * frontier_picks_per_syscall) contract intact for the LIVE
		 * side: a rejected pick does not consume any per-syscall
		 * pick budget on either side of that identity.  The rejects
		 * counter sits next to frontier_live_picks in the stats
		 * dump for the projected reclaim fraction.
		 *
		 * Isolated from the F3 SHADOW cooldown signal
		 * (frontier_live_miss_streak_per_syscall[] +
		 * frontier_live_cooldown_candidates / _would_skip): this
		 * gate is unconditional, the cooldown signal is per-syscall.
		 * The targeted variant that gates the reject on the cooldown
		 * predicate is a SEPARATE later commit and explicitly does
		 * NOT try to reach the silent-decay path -- bootstrapping
		 * the two together would compound risk on the first ramp.
		 *
		 * Does NOT touch the cached frontier weight, the ring decay
		 * loop, or the per-syscall ring -- the smallest possible
		 * behaviour change that produces the desired reclaim. */
		if (rnd_modulo_u32(FRONTIER_LIVE_DECAY_REJECT_DENOM) == 0) {
			__atomic_fetch_add(
				&shm->stats.frontier.cooldown.live_decay_live_rejects,
				1UL, __ATOMIC_RELAXED);
			goto retry;
		}

		__atomic_fetch_add(&shm->stats.frontier.core.live_picks, 1UL,
				   __ATOMIC_RELAXED);

		/* Per-syscall split of the scalar bump above + per-call
		 * regime stamp consumed by the post-call attribution path in
		 * random_syscall_step.  ADDITIVE: the picker accept/retry math
		 * above is byte-identical to the pre-row baseline; the bump
		 * and stamp run strictly AFTER the accept decision and no
		 * live-path code reads either site.  Same MAX_NR_SYSCALL
		 * bound the sibling frontier_picks_per_syscall[] uses. */
		if (syscallnr < MAX_NR_SYSCALL)
			__atomic_fetch_add(
				&shm->stats.frontier.per_syscall.live_picks_per_syscall[syscallnr],
				1UL, __ATOMIC_RELAXED);
		child->frontier_pick_regime = FRONTIER_PICK_LIVE;
	} else {
		unsigned long w = frontier_cold_weight(syscallnr, child);
		unsigned long denom = (unsigned long)FRONTIER_COLD_SCALE + 1UL;
		unsigned long roll;
		enum cmp_frontier_mode cmpf_mode;

		/* CMP-weighted alternate picker arm (default off).  The
		 * mode load is the only work done under OFF -- the
		 * cmp_frontier_weight() call, the plateau-hint load, and
		 * the substitution itself are all skipped so a fixed-seed
		 * dry-run is byte-identical to a build before this row.
		 * The mode load consumes no RNG.
		 *
		 * SHADOW_ONLY computes the alternate weight, samples the
		 * plateau hint, and bumps the would-route counter on the
		 * plateau-hit subset; the returned w stays at the PC-led
		 * value so picks remain identical to OFF for a given seed.
		 *
		 * COMBINED replaces w with the alternate weight when the
		 * plateau classifier currently reads CMP_RISING_PC_FLAT
		 * -- the "rank the silent regime by CMP-derived signal
		 * instead" contract.  Off-plateau picks retain the PC-led
		 * weight; the arm only kicks in on the regime it was
		 * designed for.  A syscall with no CMP activity sees its
		 * weight drop to 0 under the swap, which the (w + 1) /
		 * (SCALE + 1) accept floor keeps reachable rather than
		 * unreachable.
		 *
		 * See include/cmp-frontier.h for the source-counter choice
		 * and the degrade-safe contract. */
		cmpf_mode = __atomic_load_n(&cmp_frontier_mode,
					    __ATOMIC_RELAXED);
		if (cmpf_mode != CMP_FRONTIER_OFF) {
			unsigned long cmp_w = cmp_frontier_weight(syscallnr);
			int plateau;

			__atomic_fetch_add(&shm->stats.cmp_frontier.samples,
					   1UL, __ATOMIC_RELAXED);
			plateau = __atomic_load_n(
					&shm->plateau_current_hypothesis,
					__ATOMIC_RELAXED);
			if (plateau == (int)PLATEAU_HYPOTHESIS_CMP_RISING_PC_FLAT) {
				__atomic_fetch_add(
					&shm->stats.cmp_frontier.would_route,
					1UL, __ATOMIC_RELAXED);
				if (cmpf_mode == CMP_FRONTIER_COMBINED) {
					__atomic_fetch_add(
						&shm->stats.cmp_frontier.live_routes,
						1UL, __ATOMIC_RELAXED);
					w = cmp_w;
				}
			}
		}

		roll = (unsigned long)rnd_modulo_u32(denom);

		if (roll >= w + 1UL)
			goto retry;

		__atomic_fetch_add(&shm->stats.frontier.core.silent_picks, 1UL,
				   __ATOMIC_RELAXED);

		/* Per-syscall split of the scalar bump above + per-call
		 * regime stamp consumed by the post-call attribution path in
		 * random_syscall_step.  ADDITIVE: the picker accept/retry math
		 * above is byte-identical to the pre-row baseline; the bump
		 * and stamp run strictly AFTER the accept decision and no
		 * live-path code reads either site.  Same MAX_NR_SYSCALL
		 * bound the sibling frontier_picks_per_syscall[] uses. */
		if (syscallnr < MAX_NR_SYSCALL)
			__atomic_fetch_add(
				&shm->stats.frontier.per_syscall.silent_picks_per_syscall[syscallnr],
				1UL, __ATOMIC_RELAXED);
		child->frontier_pick_regime = FRONTIER_PICK_SILENT;

		/* SHADOW-ONLY silent-streak accounting.  Mirrors the
		 * frontier_silent_picks bump above; counts CONSECUTIVE
		 * silent-regime accepts of this syscall since the last
		 * productive-edge event for it (reset to zero by
		 * frontier_record_new_edge() in strategy.c, the existing
		 * per-syscall new-edge hook in kcov_collect -- no new
		 * collection path is added).  When the post-increment value
		 * crosses FRONTIER_SHADOW_DECAY_STREAK the global
		 * frontier_shadow_decay_candidates counter bumps exactly
		 * once, the headline shadow stat that estimates how many
		 * decay-candidate syscalls a future LIVE silent-decay variant
		 * of this picker would have demoted, without changing any
		 * selection today.  Same MAX_NR_SYSCALL bound the
		 * frontier_picks_per_syscall[] bump below uses.
		 *
		 * Selection-byte-identical contract: the picker accept/retry
		 * math above this point is untouched; the bump runs strictly
		 * after the accept decision and writes only NEW counters
		 * that no live-path code reads.  Mirrors the same
		 * "observation-only, default off-by-construction" shape as
		 * the cred_throttle gate above so the frontier picker's
		 * distribution stays byte-identical to today. */
		if (syscallnr < MAX_NR_SYSCALL) {
			unsigned long streak = __atomic_add_fetch(
				&shm->stats.frontier.per_syscall.silent_streak_per_syscall[syscallnr],
				1UL, __ATOMIC_RELAXED);
			if (streak == FRONTIER_SHADOW_DECAY_STREAK)
				__atomic_fetch_add(
					&shm->stats.frontier.core.shadow_decay_candidates,
					1UL, __ATOMIC_RELAXED);

			/* SHADOW-ONLY tightened decay predicate.  Pairs with
			 * the looser frontier_shadow_decay_candidates bump
			 * above: the looser counter fires on N-silent alone
			 * (no PC novelty since reset, since the streak is
			 * reset by frontier_record_new_edge() / _transition_
			 * edge() on the PC-edge and transition productive
			 * paths).  The tighter predicate here additionally
			 * requires that NEITHER per-syscall CMP-pool inserts
			 * NOR the SUCCESS-bucket errno count has advanced
			 * since the streak's last reset -- the "no recent
			 * CMP novelty and no useful errno shift" UNLESS
			 * clause that distinguishes a genuinely-stuck
			 * candidate from one whose non-PC novelty stream is
			 * still moving.
			 *
			 * Baseline snapshots are refreshed at every streak
			 * reset (in strategy.c) so a current-vs-baseline
			 * equality test is sufficient -- no per-pick stash
			 * is needed.  Atomic loads under RELAXED ordering:
			 * shadow predicate, racing producer bumps are
			 * tolerated (worst case is a one-pick over/under-
			 * count of the shadow counters, never a perturbation
			 * of live selection).
			 *
			 *  frontier_decay_candidates
			 *      Edge bump: fires on the (streak ==
			 *      FRONTIER_SHADOW_DECAY_STREAK) crossing when
			 *      the UNLESS clause holds, the tighter sibling
			 *      of the frontier_shadow_decay_candidates bump
			 *      above.  Strictly <= the looser counter by
			 *      construction.
			 *  frontier_decay_would_skip
			 *      Cumulative bump on every silent-regime pick
			 *      where the streak is already past threshold
			 *      AND the UNLESS clause holds -- the projected
			 *      demote count a live silent-decay variant of
			 *      this picker would produce. */
			if (streak >= FRONTIER_SHADOW_DECAY_STREAK &&
			    kcov_shm != NULL) {
				unsigned long cmp_now, cmp_base;
				unsigned long errno_now, errno_base;

				cmp_now = __atomic_load_n(
					&kcov_shm->per_syscall_cmp.per_syscall_cmp_inserts[syscallnr],
					__ATOMIC_RELAXED);
				cmp_base = __atomic_load_n(
					&shm->stats.frontier.per_syscall.silent_cmp_baseline[syscallnr],
					__ATOMIC_RELAXED);
				errno_now = __atomic_load_n(
					&kcov_shm->errno_state.per_syscall_errno[syscallnr][ERRNO_BUCKET_SUCCESS],
					__ATOMIC_RELAXED);
				errno_base = __atomic_load_n(
					&shm->stats.frontier.per_syscall.silent_errno_success_baseline[syscallnr],
					__ATOMIC_RELAXED);

				if (cmp_now == cmp_base &&
				    errno_now == errno_base) {
					__atomic_fetch_add(
						&shm->stats.frontier.cooldown.decay_would_skip,
						1UL, __ATOMIC_RELAXED);
					if (streak == FRONTIER_SHADOW_DECAY_STREAK)
						__atomic_fetch_add(
							&shm->stats.frontier.cooldown.decay_candidates,
							1UL, __ATOMIC_RELAXED);

					/* Arm B live reject for the silent-streak
					 * decay.  FRONTIER_SILENT_DECAY_REJECT_DENOM-1
					 * / FRONTIER_SILENT_DECAY_REJECT_DENOM
					 * probabilistic demote so the syscall still
					 * samples at ~3% -- any of the four lanes the
					 * streak resets on (PC-edge, transition,
					 * CMP-insert, SUCCESS-bucket errno shift) will
					 * release the decay on the very next pick that
					 * observes the productive event.  Arm A leaves
					 * selection byte-identical to today; the shadow
					 * counters above bumped in lock-step so the
					 * would-be divergence stays observable across
					 * both cohorts.  parent context (child == NULL)
					 * falls through to no-reject to preserve
					 * baseline behaviour for any non-child caller,
					 * matching the frontier_blend / errno-plateau
					 * arm-b parent fallbacks.
					 *
					 * Coordination with the errno-plateau decay
					 * below: the goto retry here preempts the
					 * errno-plateau check that follows in this
					 * accept iteration, so a single pick can never
					 * be double-demoted within one iteration
					 * regardless of how the two arm-B stamps cross.
					 * Across picks, the joint (silent-decay arm B
					 * AND errno-plateau arm B) cohort sees
					 * compounded rejection (~99.9% combined) on a
					 * syscall both predicates classify as wasteful
					 * from orthogonal angles -- intentional: both
					 * gates target the same ~3% recoverable
					 * sampling rate, and compounding to a smaller
					 * effective rate on a doubly-classified-stuck
					 * syscall is strictly safer (any productive
					 * lane on either predicate still releases the
					 * decay on the next pick). */
					if (child != NULL &&
					    child->frontier_silent_decay_arm_b &&
					    rnd_modulo_u32(FRONTIER_SILENT_DECAY_REJECT_DENOM) != 0) {
						__atomic_fetch_add(
							&shm->stats.frontier.cooldown.silent_decay_live_rejects,
							1UL, __ATOMIC_RELAXED);
						goto retry;
					}
				}
			}
		}

		/*
		 * SHADOW-ONLY saturation cooldown predicate (gated by
		 * --frontier-saturation-cooldown != off).  Sibling of the
		 * silent-streak decay block above and the errno-plateau
		 * block below; targets the same wasteful-silent-pick shape
		 * but keys plateau on the windowed frontier-edge ring and
		 * spares the under-explored struct-arg backlog + the object-
		 * producer set via distinct-CMP / first-success-TRANSITION /
		 * precomputed producer-observer bitmap lanes.  See the full
		 * contract above frontier_satcool_spare() in
		 * strategy-frontier.c.
		 */
		frontier_satcool_spare(syscallnr, do32);

		/*
		 * SHADOW-ONLY floored-barren sub-floor demote predicate
		 * (gated by --frontier-barren-demote != off).  Sibling of
		 * the satcool spare above; targets the pure zero-arg
		 * getter set whose lifetime PC-edge yield has plateaued
		 * to a hard floor rather than the windowed-plateau of
		 * the saturated-productive set the satcool predicate
		 * owns.  Disjoint from satcool by construction (the
		 * barren predicate requires lifetime edges == 0 at the
		 * small FRONTIER_BARREN_C_MIN floor; satcool requires
		 * the FRONTIER_SATCOOL_CMIN 10000-call magnitude and
		 * keys plateau on the K-window ring going flat for a
		 * syscall that HAS produced).  See the full contract
		 * above frontier_barren_demote() in strategy-frontier.c.
		 */
		frontier_barren_demote(syscallnr, do32);

		/* Errno-plateau decay (SHADOW + per-child A/B).  See the
		 * FRONTIER_ERRNO_PLATEAU_* contract in include/strategy.h and the
		 * frontier_errno_plateau_should_decay() implementation in strategy.c.
		 *
		 * Composition with the sibling shadow decay above: that one keys on
		 * the CONSECUTIVE-silent-pick streak with a no-CMP-and-no-success-
		 * shift UNLESS clause; this one keys on a LIFETIME dominant-failure-
		 * errno + zero-edge shape.  The two predicates are orthogonal --
		 * a syscall returning EBADF every time will satisfy errno-plateau
		 * after the first FRONTIER_ERRNO_PLATEAU_MIN_CALLS calls regardless
		 * of streak length, and a syscall whose silent streak has crossed
		 * the threshold but whose errno mix is spread across buckets will
		 * satisfy silent-decay only.  The overlap_silent counter tallies
		 * picks where BOTH predicates fire so the operator can read the
		 * incremental coverage the errno-plateau predicate adds.
		 *
		 * The cred_throttle gate already rejected impossible credential
		 * picks above; frontier_errno_plateau_should_decay excludes the
		 * credential-class set explicitly so a credential syscall is
		 * never decayed by both gates. */
		if (frontier_errno_plateau_should_decay(syscallnr, do32)) {
			__atomic_fetch_add(
				&shm->stats.frontier.plateau.errno_decay_would_skip,
				1UL, __ATOMIC_RELAXED);
			if (syscallnr < MAX_NR_SYSCALL) {
				unsigned long s = __atomic_load_n(
					&shm->stats.frontier.per_syscall.silent_streak_per_syscall[syscallnr],
					__ATOMIC_RELAXED);
				if (s >= FRONTIER_SHADOW_DECAY_STREAK)
					__atomic_fetch_add(
						&shm->stats.frontier.plateau.errno_decay_overlap_silent,
						1UL, __ATOMIC_RELAXED);
			}
			/* Arm B live reject: REJECT_DENOM-1 / REJECT_DENOM
			 * probabilistic demote so the syscall still samples at
			 * ~3% -- any of the four novelty lanes the predicate
			 * checks will release the decay on the very next pick
			 * that observes the productive event.  Arm A leaves
			 * selection byte-identical to today; the shadow counters
			 * above bumped in lock-step so the would-be divergence
			 * stays observable across both cohorts.  parent context
			 * (child == NULL) falls through to no-reject to preserve
			 * baseline behaviour for any non-child caller, matching
			 * the frontier_blend arm-b parent fallback. */
			if (child != NULL && child->frontier_errno_decay_arm_b &&
			    rnd_modulo_u32(FRONTIER_ERRNO_PLATEAU_REJECT_DENOM) != 0) {
				__atomic_fetch_add(
					&shm->stats.frontier.plateau.errno_decay_live_rejects,
					1UL, __ATOMIC_RELAXED);
				goto retry;
			}
		}
	}

	srec_publish_begin(rec);
	rec->do32bit = do32;
	rec->nr = syscallnr;
	srec_publish_end(rec);

	/* Per-syscall accept distribution.  Bumped after both regimes converge
	 * on a successful pick so the array is regime-agnostic; the live/silent
	 * split lives in frontier_{live,silent}_picks.  Guarded on the same
	 * MAX_NR_SYSCALL bound the other per-syscall arrays use. */
	if (syscallnr < MAX_NR_SYSCALL)
		__atomic_fetch_add(
			&shm->stats.frontier.per_syscall.picks_per_syscall[syscallnr],
			1UL, __ATOMIC_RELAXED);

	__atomic_fetch_add(&shm->stats.frontier.core.strategy_picks, 1UL,
			   __ATOMIC_RELAXED);

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
bool set_syscall_nr(struct syscallrecord *rec, struct childdata *child)
{
	int strat;

	/* Clear the per-pick frontier accept-regime stamp before the
	 * strategy dispatcher fires.  The frontier picker re-stamps LIVE or
	 * SILENT at its accept sites; any other strategy leaves the slot at
	 * NONE so the post-call attribution path (random_syscall_step) does
	 * not credit a non-frontier pick to the per-syscall frontier yield
	 * arrays.  Mirrors the strategy_at_pick clear below; same owner-only
	 * write semantics. */
	child->frontier_pick_regime = FRONTIER_PICK_NONE;

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
		__atomic_fetch_add(&shm->stats.picker_bandit.strategy_explorer_picks, 1UL,
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
	default:
		__builtin_unreachable();
	}
}
