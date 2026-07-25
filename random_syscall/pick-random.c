/*
 * STRATEGY_RANDOM picker arm carved out of pickers.c.  Uniform draw
 * from active_syscalls with no further biasing -- the "shake the
 * dust off" pass that exposes paths the heuristic biases
 * systematically suppress.  Anti-prior plateau intervention lives
 * here too.  set_syscall_nr_random is public via include/syscall.h.
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
	bool anti_prior_on;

	/* See the matching comment in set_syscall_nr_heuristic — the table
	 * pick is a per-call decision, not a per-retry one, and nr_syscalls
	 * is the active-prefix count rather than max_nr_*syscalls. */
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

	/* Latch the anti-prior mode once per pick so the per-retry inner
	 * loop reads a stable answer; a rotation that lands mid-pick is
	 * harmless either way (we either over-shoot one retry budget or
	 * under-shoot one) but caching avoids redoing the relaxed atomic
	 * load on every retry. */
	anti_prior_on = plateau_anti_prior_active();

	/* Cost-pool selector SHADOW observer -- same call-site contract
	 * as the matching helper call in set_syscall_nr_heuristic above:
	 * fires once per pick call (NOT per retry), consumes no RNG, and
	 * is short-circuit-OFF-fast so the RANDOM arm's default-off pick
	 * stream is byte-identical to a pre-row build for a given seed.
	 *
	 * Same shadow-vs-live accounting caveat as the HEURISTIC arm:
	 * SHADOW counts pick ATTEMPTS (bumped once, here, before the
	 * retry: loop) while cost_pool_selector_live_note() counts
	 * FINALISES (at pick commit).  A no_syscalls_enabled() early
	 * return or a 10k-retry-budget bail charges the attempt to
	 * shadow but never reaches live, so shadow can exceed
	 * live_cheap + live_expensive; a shadow-vs-live expensive-
	 * fraction comparison should expect that attempt-vs-finalise
	 * gap. */
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

	if (outer_attempts++ > 10000) {
		output(0, "[%d] set_syscall_nr_random exceeded retry budget\n", mypid());
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

	/* PRE-GATE cost-pool attribution.  See the matching call in
	 * set_syscall_nr_heuristic above -- this is the RANDOM-arm sibling.
	 * Fires after expensive_accept survives and before anti_prior /
	 * validate / cred-throttle can enrich the finalised stream, so
	 * (predraw_expensive / (predraw_cheap + predraw_expensive)) tracks
	 * the section 4.1 closed-form the shadow observer accumulates. */
	cost_pool_selector_predraw_note(syscallnr, do32);

	if (validate_specific_syscall_silent(syscalls, syscallnr) == false) {
		note_validation_failure(syscallnr, do32);
		goto retry;
	}
	note_validation_success(syscallnr, do32);

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

	/* --cred-throttle gate.  Same contract as the matching call site in
	 * set_syscall_nr_heuristic above: byte-identical default when the
	 * flag is off, and the outer_attempts budget absorbs the retries. */
	if (cred_throttle_should_reject(syscallnr, do32))
		goto retry;

	/* Wall-lever SHADOW gate.  Mirrors the call site in
	 * set_syscall_nr_heuristic above so plateau-active picks under both
	 * the bandit-heuristic and uniform-random arms feed the same shadow
	 * tally; the cold-skip-bypass logic that pulls the random arm into
	 * the plateau intervention windows is exactly where the
	 * dead-weight syscalls are most likely to be picked, so the random
	 * arm's contribution is the headline data point.  Live picker is
	 * byte-identical -- the lever does NOT reject here. */
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

	/* Cost-pool selector LIVE-accept attribution -- same call-site
	 * contract as the matching bump in set_syscall_nr_heuristic
	 * above: fires unconditionally at pick-finalise so the live-
	 * actual expensive fraction over the RANDOM arm is measurable
	 * on any run regardless of cost_pool_selector_mode. */
	cost_pool_selector_live_note(syscallnr, do32);

	/* Path-A "regular_suppressed" context-axis SHADOW attribution --
	 * same call-site contract as the matching bump in
	 * set_syscall_nr_heuristic above: fires at pick-finalise so both
	 * picker arms feed the same shadow denominator; byte-identical
	 * default when --context-pool=off. */
	context_regular_suppressed_shadow(syscallnr, do32);

	srec_publish_begin(rec);
	rec->do32bit = do32;
	rec->nr = syscallnr;
	srec_publish_end(rec);

	return true;
}
