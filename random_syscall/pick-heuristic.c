/*
 * STRATEGY_HEURISTIC picker arm carved out of pickers.c.  The
 * heuristic picker is trinity's pre-rotation default: uniform draw
 * from active_syscalls, then layered biases (group affinity, kcov
 * cold-skip).  set_syscall_nr_heuristic is cross-cluster private
 * and declared in include/random-syscall-internal.h.
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
 * Pick the syscall to run under STRATEGY_HEURISTIC: uniform draw from
 * active_syscalls, then layered biases — group affinity (70% prefer last
 * group) and kcov cold-skip (probabilistic).  This is trinity's
 * pre-rotation default behaviour.
 */
bool set_syscall_nr_heuristic(struct syscallrecord *rec,
				     struct childdata *child)
{
	struct syscallentry *entry;
	unsigned int syscallnr;
	int val;
	bool do32;
	unsigned int group_attempts = 0;
	unsigned int kcov_attempts = 0;
	unsigned int outer_attempts = 0;
	unsigned int nr_syscalls;

	/* Pick the syscall table once per call: in uniarch the do32 result
	 * is a constant; in biarch the do32 dice rolls once per pick.  The
	 * nr_syscalls snapshot is the CURRENT active count
	 * (shm->nr_active_*) so the rnd_modulo_u32() draw indexes directly
	 * into the compact active_syscalls[0..nr_active) prefix and a
	 * restricted run never wastes the retry budget on the sparse-zero
	 * tail of the max table. */
	if (biarch) {
		do32 = choose_syscall_table(child, &nr_syscalls);
	} else {
		do32 = false;
		nr_syscalls = load_active_syscall_count(
			&shm->nr_active_syscalls, "nr_active_syscalls");
	}
	/* Corrupt shared count (either arch) -- the helper has already
	 * logged the self-corrupt marker; bail out on this pick so the
	 * rnd_modulo_u32(nr_syscalls) below cannot index child->
	 * active_syscalls[] past the mapped MAX_NR_SYSCALL bound. */
	if (nr_syscalls > MAX_NR_SYSCALL)
		return FAIL;

	/* Cost-pool selector SHADOW observer -- fires once per pick call
	 * (NOT per retry) so the analytical expected-expensive-fraction
	 * summand matches the flat picker's one-pick-per-call rhythm.
	 * OFF is a single RELAXED mode load + short-circuit; SHADOW_ONLY
	 * / COMBINED accumulates the section 4.1 closed-form summand
	 * with ZERO RNG draws so the live pick stream stays byte-
	 * identical to a pre-row build for a given seed.
	 *
	 * Shadow-vs-live accounting note: the SHADOW note above counts
	 * pick ATTEMPTS -- it is bumped once here, before the retry:
	 * loop.  cost_pool_selector_live_note() at the bottom counts
	 * FINALISES -- it fires once per pick that commits.  On a
	 * no_syscalls_enabled() early return or a 10k-retry-budget bail
	 * the pick attempt is charged to shadow but never reaches live,
	 * so shadow can exceed live_cheap + live_expensive.  Any
	 * shadow-vs-live expensive-fraction comparison should therefore
	 * expect a small attempt-vs-finalise gap and not treat it as a
	 * counting bug. */
	cost_pool_selector_shadow_note(do32);

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

	/* Bail if we have spent too many iterations failing to pick a
	 * usable syscall.  Even sampling the compact active prefix, a table
	 * dominated by EXPENSIVE syscalls (kept at 1-in-1000) can wedge
	 * the child in a tight retry loop. */
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
	 * EXPENSIVE early-out: expensive_accept() bitmap-tests before
	 * validate + entry fetch, so the reject path skips the
	 * syscallentry cache miss.  Helper consolidates the policy;
	 * under the default --expensive-adaptive=off it applies the
	 * `syscall_is_expensive(...) && !ONE_IN(1000)` predicate with
	 * the same control flow and RNG draw order.
	 */
	if (!expensive_accept(syscallnr, do32))
		goto retry;

	/* PRE-GATE cost-pool attribution: candidate has survived the
	 * uniform draw + expensive_accept throttle -- the exact population
	 * the shadow closed-form models.  Bumped here so a shadow-only
	 * validation run can compare predraw_expensive / (predraw_cheap +
	 * predraw_expensive) against shadow_expensive_ppm_sum /
	 * (shadow_picks * 1e6) without downstream gates (validate /
	 * anti_prior / cred-throttle) skewing the fraction.  OFF-mode
	 * short-circuits before any shm access, so this stays RNG- and
	 * byte-neutral for the default build. */
	cost_pool_selector_predraw_note(syscallnr, do32);

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

		/* F-RSEQ SHADOW group-pin damper predicate.  Evaluated
		 * BEFORE the dice roll so the candidate / would_skip
		 * accounting is regime-agnostic: the windowed pin barren
		 * test is a property of the pin, not of which dice arm
		 * the upcoming pick would have taken.  Gated on the mode
		 * outer guard so default OFF keeps this block byte-
		 * identical to a build before the F-RSEQ row: no per-
		 * child field is read, no atomic load fires, no shadow
		 * counter is touched, no extra RNG is consumed (the
		 * predicate is RNG-free by construction -- streak /
		 * watermark / fd-warm reads only).  See the enum
		 * frontier_group_antilock_mode comment in include/strategy.h
		 * for the predicate contract and the FRONTIER_FRSEQ_MIN_
		 * STREAK / FRONTIER_FRSEQ_COV_WINDOW comments for the
		 * threshold rationale.
		 *
		 * THIS COMMIT IS SHADOW-ONLY by construction: the block
		 * computes pin_stale && !pin_warm and bumps the
		 * frontier_frseq_* shadow counters but never alters the
		 * 70%-same-group dice arm below or any goto-retry path,
		 * so the picker's accept distribution stays byte-
		 * identical to the default-off baseline regardless of
		 * which non-OFF mode is selected.  Wiring the COMBINED
		 * live pin release is a deliberate follow-up after a
		 * SHADOW_ONLY run validates the demote mass concentrates
		 * on rseq_slice_yield / getpgrp / sched_yield and on
		 * GROUP_PROCESS, and is ~0 on socket / sendto / openat
		 * and on GROUP_NET / GROUP_VFS.
		 *
		 * Outer mode load is RELAXED -- the mode is parse-time
		 * configured and never mutated at runtime, so a one-pick
		 * tear is impossible.  Matches the satcool mode-load
		 * shape exactly (pickers.c silent-regime
		 * accept block). */
		{
			enum frontier_group_antilock_mode antilock_mode =
				__atomic_load_n(
					&frontier_group_antilock_mode,
					__ATOMIC_RELAXED);

			if (antilock_mode != FRONTIER_GROUP_ANTILOCK_MODE_OFF) {
				/* Both pin_stale clauses must hold.
				 * MIN_STREAK guards against the early-
				 * pin window where every cluster looks
				 * "barren" before it has had a chance
				 * to produce; COV_WINDOW is the sliding
				 * window inside the pin so a single
				 * incidental edge does not make a junk-
				 * drawer pin immortal (the whole-pin
				 * cov>0 version would have).  Unsigned
				 * subtraction guard: the streak_len >
				 * last_cov_at_streak invariant holds by
				 * construction because the bookkeeping
				 * helper advances last_cov_at_streak
				 * only to the CURRENT streak_len value
				 * AFTER the streak_len bump, so the
				 * subtraction never wraps.  We
				 * additionally guard >= just in case a
				 * future bookkeeping change loosens
				 * that invariant. */
				bool pin_stale = (child->group_streak_len >
						  FRONTIER_FRSEQ_MIN_STREAK) &&
						 (child->group_streak_len >=
						  child->last_cov_at_streak) &&
						 ((child->group_streak_len -
						   child->last_cov_at_streak) >
						  FRONTIER_FRSEQ_COV_WINDOW);
				/* pin_warm spare: a pin holding live state
				 * (warm setup chains that build objects
				 * before the rare trigger) is preserved
				 * even when coverage-barren.  Pure-getter
				 * pins never produce fds and so are not
				 * spared regardless of streak length --
				 * which is exactly the lock-in target
				 * this row reclaims. */
				bool pin_warm = (child->group_fd_created_in_streak > 0);
				bool pin_barren = pin_stale && !pin_warm;

				__atomic_fetch_add(
					&shm->stats.frontier.discriminator.frseq_candidates,
					1UL, __ATOMIC_RELAXED);

				if (pin_barren) {
					__atomic_fetch_add(
						&shm->stats.frontier.discriminator.frseq_would_skip,
						1UL, __ATOMIC_RELAXED);
					/* Per-syscall bucket keys on the
					 * candidate syscallnr being evaluated
					 * at the gate -- under live COMBINED
					 * the pin would release and the
					 * group_bias if-block would be
					 * skipped, so this syscall would be
					 * accepted regardless of group
					 * membership.  Dominated by the
					 * pure-getter / no-op yield set when
					 * the picker is in a junk-drawer pin
					 * (those are the most-drawn members
					 * because they are the only ones
					 * that pass every gate cheaply). */
					if (syscallnr < MAX_NR_SYSCALL) {
						__atomic_fetch_add(
							&shm->stats.frontier.discriminator.frseq_would_skip_per_syscall[syscallnr],
							1UL, __ATOMIC_RELAXED);
					}
					/* Per-group bucket keys on
					 * child->last_group (which pin is
					 * being released).  Dominated by
					 * GROUP_PROCESS (=5) when the
					 * pathology fires; should be ~0 on
					 * GROUP_NET / GROUP_VFS / GROUP_IO_
					 * URING / etc. -- the stateful-
					 * sequence groups whose locality
					 * the bias exists to protect.  The
					 * bound check is defensive; group
					 * is a u8 in syscallentry and the
					 * source values are <= GROUP_XATTR =
					 * 11 < NR_GROUPS = 12. */
					if (child->last_group < NR_GROUPS) {
						__atomic_fetch_add(
							&shm->stats.frontier.discriminator.frseq_would_skip_per_group[child->last_group],
							1UL, __ATOMIC_RELAXED);
					}
					/* COMBINED live pin release would
					 * sit here gated on antilock_mode ==
					 * COMBINED; intentionally NOT wired
					 * in this commit.  The block is
					 * observability-only regardless of
					 * mode so the SHADOW_ONLY counters
					 * can be validated against a real
					 * run before any live divergence is
					 * introduced. */
				}
			}
		}

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

	/* --cred-throttle gate.  Returns false unconditionally when the flag
	 * is off (single RELAXED bool load short-circuit, no per-class state
	 * touched) so the default picker distribution is byte-identical.
	 * Placed AFTER validate/EXPENSIVE/group/cold-skip so a rejected pick
	 * shares the existing outer_attempts budget instead of needing its
	 * own retry cap. */
	if (cred_throttle_should_reject(syscallnr, do32))
		goto retry;

	/* Wall-lever SHADOW gate: the candidate has cleared every
	 * live correctness + bias gate above, so this is the population a
	 * live wall-lever variant would have to act on.  Bump the eligible
	 * counter on every plateau-active pick (probe short-circuits to
	 * false outside the plateau, so the conditional is cheap) and bump
	 * the would_suppress family when the data-driven predicate fires.
	 * Live picker is byte-identical -- the lever does NOT reject here. */
	if (kcov_shm != NULL &&
	    __atomic_load_n(&kcov_shm->plateau.plateau_active, __ATOMIC_ACQUIRE)) {
		__atomic_fetch_add(&shm->stats.picker_bandit.wall_lever_eligible_total, 1UL,
				   __ATOMIC_RELAXED);
		if (wall_lever_should_suppress_shadow(syscallnr)) {
			__atomic_fetch_add(
				&shm->stats.picker_bandit.wall_lever_would_suppress_total,
				1UL, __ATOMIC_RELAXED);
			__atomic_fetch_add(
				&shm->stats.picker_bandit.wall_lever_would_suppress[syscallnr],
				1UL, __ATOMIC_RELAXED);
		}
	}

	/* Cost-pool selector LIVE-accept attribution -- placed at the
	 * pick-finalise site so a validate / cred-throttle / wall-lever
	 * reject earlier in the loop cannot double-count.  The bump
	 * fires regardless of cost_pool_selector_mode so the live-actual
	 * expensive fraction is always available for the section 4.1
	 * identity validation. */
	cost_pool_selector_live_note(syscallnr, do32);

	/* Path-A "regular_suppressed" context-axis SHADOW attribution --
	 * co-located with the cost-pool LIVE-note above so the two picker
	 * observers share the same pick-finalise cadence (the
	 * (context_regular_suppressed_would_skip /
	 * context_regular_suppressed_candidates) ratio reads directly off
	 * the same finalised-pick denominator without an attempt-vs-
	 * finalise skew).  Byte-identical OFF short-circuit: the helper's
	 * single RELAXED mode load returns before any kcov_shm access.
	 * SHADOW-ONLY -- never touches the accept distribution.  See the
	 * enum context_pool_mode comment in include/strategy.h for the
	 * mode contract. */
	context_regular_suppressed_shadow(syscallnr, do32);

	/* publish (nr, do32bit) as a coherent pair. */
	srec_publish_begin(rec);
	rec->do32bit = do32;
	rec->nr = syscallnr;
	srec_publish_end(rec);

	return true;
}
