/*
 * SHADOW typed-hypothesis store: inference + would-pick + LIVE inject.
 *
 * Layered on top of the raw cmp-hint pools as a PARALLEL table.  The raw
 * pools stay the canonical (cmp_ip, value, size) ledger; this cluster
 * builds typed inferences from those observations and drives the LIVE
 * inject arm that replaces a raw pool value with a hypothesis-derived one
 * on the callsites that opted in.  Every writer runs under the matching
 * durable cmp_hint_pool lock so hyp_pools[nr][do32] is serialised
 * per-(nr, do32) without a second lock of its own.
 */

#include <stdint.h>
#include <string.h>

#include "arch.h"
#include "cmp_hints.h"
#include "cmp_hints-internal.h"
#include "cmp_hints/hyp-internal.h"
#include "kcov.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "strategy.h"
#include "tables.h"
#include "utils.h"



/*
 * Inject rate for the LIVE typed-hypothesis arm under the
 * CMP_RISING_PC_FLAT plateau (channel A below).  Raised from the prior
 * conservative 1/32 to 1/4 (8x) for the conversion-measurement window:
 * at 1/32 a 2h run banks only ~10k typed firings, far short of the
 * ~75k needed to see even one PC win at the raw arm's ~1e-5 rate, so
 * the typed-vs-raw verdict could never resolve in a practical run.
 * 1/4 accumulates enough typed firings to measure the arm; it is
 * deliberately less conservative than the raw baseline (1/16) for that
 * measurement -- revisit (back toward 1/16-1/32) once the rate is known.
 */
#define CMP_HYP_LIVE_INJECT_DENOM	4U

/*
 * Bootstrap channel dice (channel B) for the LIVE typed-hypothesis arm.
 * Fires REGARDLESS of plateau so the inject pipeline can earn its first
 * PC wins on OBSERVED-state hypotheses before the plateau gate has ever
 * opened.  Sparse (~0.4 %) so it cannot drown the raw cmp-hint signal
 * even in the worst case; integrated over a multi-hour run this still
 * accumulates thousands of typed-arm firings, plenty to seed the
 * promotion ladder.  Resolves the circular dependency where
 * cmp_hyp_try_live_inject was gated on a plateau that only opens once
 * PROMOTED hypotheses exist, but PROMOTED hypotheses only appear after
 * cmp_hyp_try_live_inject has fired and earned wins.
 */
#define CMP_HYP_LIVE_INJECT_BOOTSTRAP_DENOM	256U

/*
 * PROMOTED-bypass channel dice (channel C) for the LIVE typed-hypothesis
 * arm.  Cheaper than the bootstrap dice (~1.6 %) because the state
 * machine (cmp_hyp_credit_outcome's DEMOTE / RETIRE on losses, PROMOTE
 * on wins) has already done the throttling work that the plateau gate
 * was approximating: a PROMOTED entry has demonstrably produced a
 * coverage win, so re-firing it cheaply is the warranted bias.  Only
 * applies when cmp_hyp_would_pick_locked returns a PROMOTED entry at
 * the served (cmp_ip, width) -- if the picker returns OBSERVED or NULL,
 * channel C is treated as if its dice had not been rolled (account via
 * NO_MATCH downstream when picker == NULL, otherwise bail).
 */
#define CMP_HYP_LIVE_INJECT_PROMOTED_DENOM	64U


/*
 * LIVE typed-hypothesis inject try.  Composes the conservative gate
 * (plateau == CMP_RISING_PC_FLAT AND ONE_IN(4)) with the shadow
 * resolver and the derive helper above.  On a fire the raw pool's
 * (cmp_ip, value, width) tuple the pick step computed is replaced by
 * (cmp_ip, derived, width) -- cmp_ip and width are unchanged because
 * the inject targets the SAME comparison site, just substituting a
 * typed-derived value for the raw replay.
 *
 * The caller (cmp_hints_try_get_ex) only invokes this on a typed-safe
 * argtype; gating that here would conflate the gate's "did not fire"
 * with the caller's "not eligible" cohort.
 *
 * Per-pull accounting is deferred to the caller's accept-gated commit
 * point so a hint the caller's accept range subsequently rejects does
 * not contaminate cmp_hyp_live_inject_gate_passed /
 * cmp_hyp_live_injected[/_by_kind].  This helper bumps nothing, and
 * signals back through two out-params:
 *
 *   *out_gate_fired -- the conservative gate passed (plateau + dice +
 *                      size + shm); the caller bumps gate_passed when
 *                      its accept gate also passes.  Preserves the
 *                      "gate fired but the typed store had nothing"
 *                      observability the gate_passed - live_injected
 *                      delta currently surfaces, just gated on the
 *                      value actually reaching the consumer.
 *   *out_kind       -- picked->kind, valid iff the function returns
 *                      true (i.e. picked != NULL AND derive
 *                      succeeded).  The caller bumps live_injected /
 *                      live_injected_by_kind[*out_kind] under the
 *                      same accept-gate.
 *
 * Both out-params are written on every entry: out_gate_fired starts
 * at false and only flips true once the gate passes, out_kind is left
 * at 0 unless the function returns true.  Callers can therefore key
 * their accounting off the bool return alone for live_injected and off
 * *out_gate_fired for gate_passed without re-checking helper inputs.
 */
bool cmp_hyp_try_live_inject(unsigned int nr, bool do32,
			     unsigned long cmp_ip, unsigned int size,
			     unsigned int arg_idx __attribute__((unused)),
			     enum cmp_hint_callsite callsite,
			     unsigned long *out,
			     uint8_t *out_kind,
			     bool *out_gate_fired)
{
	struct cmp_hyp_pool *pool;
	struct cmp_hypothesis *picked;
	bool present[CMP_HYP_KIND_NR];
	uint8_t width;
	unsigned long derived;
	bool plateau_on;
	bool channel_a_fired;
	bool channel_b_fired = false;
	bool channel_c_dice_won = false;
	uint8_t picked_state;

	*out_gate_fired = false;
	*out_kind = 0;

	if (cmp_hints_shm == NULL || nr >= MAX_NR_SYSCALL)
		return false;
	if (size != 1 && size != 2 && size != 4 && size != 8)
		return false;
	if (shm == NULL)
		return false;

	/*
	 * Three independent channels can open this gate:
	 *
	 *   A  plateau == CMP_RISING_PC_FLAT  AND  ONE_IN(LIVE_INJECT_DENOM)
	 *   B  ONE_IN(BOOTSTRAP_DENOM)                          (always-on)
	 *   C  ONE_IN(PROMOTED_DENOM)  AND  picker returns PROMOTED
	 *
	 * A is the historical plateau-amplified path; the bootstrap (B) and
	 * promoted-bypass (C) channels exist so PC wins can accumulate even
	 * when the plateau gate has never opened.  C's "picker returns
	 * PROMOTED" half is verified AFTER the pool walk further down -- we
	 * roll the dice here and consult the picker once, deferring channel
	 * attribution until we know whether C qualifies.
	 *
	 * Dice are rolled even when an earlier channel has already fired so
	 * the random stream stays callsite-deterministic across plateau
	 * transitions -- without this, flipping the plateau on / off would
	 * shift every downstream rnd_*() consumer's value.  Cost is two
	 * rnd_modulo_u32 calls in the rejected case, both off the hot raw
	 * cmp-hint path.
	 */
	plateau_on = (__atomic_load_n(&shm->plateau_current_hypothesis,
				      __ATOMIC_RELAXED) ==
		      (int)PLATEAU_HYPOTHESIS_CMP_RISING_PC_FLAT);
	channel_a_fired = plateau_on && ONE_IN(CMP_HYP_LIVE_INJECT_DENOM);
	if (ONE_IN(CMP_HYP_LIVE_INJECT_BOOTSTRAP_DENOM))
		channel_b_fired = true;
	if (ONE_IN(CMP_HYP_LIVE_INJECT_PROMOTED_DENOM))
		channel_c_dice_won = true;

	if (!channel_a_fired && !channel_b_fired && !channel_c_dice_won) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(
				&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_live_inject_reason[plateau_on
					? CMP_HYP_LIVE_INJECT_REASON_DICE_MISS
					: CMP_HYP_LIVE_INJECT_REASON_NOT_PLATEAU],
				1UL, __ATOMIC_RELAXED);
		return false;
	}

	*out_gate_fired = true;

	width = (uint8_t)size;
	pool = &cmp_hints_shm->hyp_pools[nr][do32 ? 1 : 0];

	picked = cmp_hyp_would_pick_locked(pool, cmp_ip, width, present);
	if (picked == NULL) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(
				&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_live_inject_reason[CMP_HYP_LIVE_INJECT_REASON_NO_MATCH],
				1UL, __ATOMIC_RELAXED);
		return false;
	}

	/*
	 * Channel attribution.  Priority C > B > A: PROMOTED_BYPASS is the
	 * most informative signal (state machine validated the hyp), so when
	 * channels overlap we credit the most specific one.  Channel A has
	 * no specific reason counter -- its firings are visible as
	 * cmp_hyp_live_inject_gate_passed minus the sum of the BOOTSTRAP and
	 * PROMOTED_BYPASS reason counters.
	 *
	 * The "channel C dice won but picked is not PROMOTED, and A/B both
	 * lost" branch bails via NO_MATCH: structurally there IS a
	 * hypothesis at the site (picker returned non-NULL), but no channel
	 * actually qualified to drive an inject -- C requires PROMOTED, B/A
	 * didn't roll.  Treating it as NO_MATCH keeps the per-reason
	 * partition closed (sum of head + downstream reasons + injected ==
	 * total entries past the size-class guard) without adding a third
	 * new enum value just for this one corner.
	 */
	picked_state = __atomic_load_n(&picked->state, __ATOMIC_RELAXED);
	if (channel_c_dice_won && picked_state == CMP_HYP_STATE_PROMOTED) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(
				&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_live_inject_reason[CMP_HYP_LIVE_INJECT_REASON_PROMOTED_BYPASS],
				1UL, __ATOMIC_RELAXED);
	} else if (channel_b_fired) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(
				&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_live_inject_reason[CMP_HYP_LIVE_INJECT_REASON_BOOTSTRAP],
				1UL, __ATOMIC_RELAXED);
	} else if (!channel_a_fired) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(
				&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_live_inject_reason[CMP_HYP_LIVE_INJECT_REASON_NO_MATCH],
				1UL, __ATOMIC_RELAXED);
		return false;
	}

	if (!cmp_hyp_derive_value(picked, callsite, &derived)) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(
				&kcov_shm->cmp_hyp_lifecycle.cmp_hyp_live_inject_reason[CMP_HYP_LIVE_INJECT_REASON_DERIVE_FAIL],
				1UL, __ATOMIC_RELAXED);
		return false;
	}

	*out = derived;
	*out_kind = picked->kind;
	return true;
}
