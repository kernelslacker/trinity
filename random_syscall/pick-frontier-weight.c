/*
 * Per-syscall weight helpers for the STRATEGY_COVERAGE_FRONTIER
 * silent-regime accept gate, carved out of pickers.c.
 *
 * frontier_cold_weight is the plateau-fallback weight when the
 * frontier ring goes silent (max_weight <= 2); cmp_frontier_weight
 * is the CMP-weighted alternate weight consulted under
 * cmp_frontier_mode != CMP_FRONTIER_OFF.  Both cap output at
 * FRONTIER_COLD_SCALE and are declared in
 * include/random-syscall-internal.h.
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
 * Cold-syscall weight for the frontier picker's plateau fallback path.
 * Returns a value in [0, FRONTIER_COLD_SCALE] that the accept gate in
 * set_syscall_nr_coverage_frontier() consumes as the bias toward this
 * syscall when the frontier ring has gone silent.  Higher = more biased
 * toward picking this syscall.
 *
 * Three regimes, deliberately distinguished:
 *
 *   calls == 0 (never invoked)
 *     -- return FRONTIER_COLD_SCALE.  Maximum bias.  These are
 *        genuinely under-explored slots the picker should be steering
 *        to.
 *
 *   calls > 0 && edges == 0 (invoked, never productive)
 *     -- return 0.  Minimum bias.  The syscall has had its shot and
 *        failed to produce any new coverage; biasing toward it pulls
 *        the picker into a bug-graveyard where it spends the plateau
 *        re-running calls that already established themselves as
 *        unproductive.  The +1 smoothing on w in the caller's accept
 *        gate keeps these syscalls reachable at the uniform floor
 *        ((0+1)/(SCALE+1)) rather than starving entirely.
 *
 *   calls > 0 && edges > 0 (invoked, some productivity)
 *     -- return SCALE - floor(SCALE * edges / calls).  Linear inverse
 *        productivity, same shape as before but at the new SCALE
 *        resolution: a perfectly productive syscall (edges == calls)
 *        lands at 0, a syscall that has produced a small fraction of
 *        new edges across many calls keeps a near-full weight.
 *        edges <= calls by construction so the subtraction can't
 *        underflow.
 *
 * The previous shape conflated the first two regimes: both never-tried
 * and tried-but-broken returned SCALE, so the plateau-fallback picker
 * weighted the bug-graveyard identically to the genuinely under-explored
 * frontier and burned its picks re-running known dead-ends.  Splitting
 * the two regimes is the headline fix; the SCALE bump (16 -> 256, see
 * the FRONTIER_COLD_SCALE macro comment) is what lets the third regime's
 * integer divide actually distinguish productivity below ~6% from MAX
 * instead of flooring everything in that range to the ceiling.
 *
 * Semantics note: per_syscall_edges has "bumps by 1 per call that
 * discovered >=1 new edge" semantics (see include/kcov.h), not raw
 * bucket-edge counts, so edges <= calls by construction.  Reads are
 * RELAXED -- a stale snapshot is harmless; a racing kcov_collect bump
 * that lands mid-pick only shifts the weight by one step, well inside
 * the slack the outer accept/retry loop already tolerates.
 *
 * Returns the uniform-floor (FRONTIER_COLD_SCALE) when kcov_shm is
 * unavailable so the caller's accept gate degrades to plain uniform
 * pick rather than wedging on a NULL deref -- matches the kcov-less
 * fallback the rest of the codebase already takes (see
 * kcov_syscall_cold_skip_pct in kcov.c for the sibling pattern).
 */
unsigned long frontier_cold_weight(unsigned int nr,
					  struct childdata *child)
{
	unsigned long edges, calls;
	unsigned long bucket_bits, distinct_pcs;
	unsigned long transition_edges_real_local;
	unsigned long old_weight, blend_weight;
	unsigned long blend_productivity;
	unsigned long picked_weight;
	enum kcov_transition_reward_mode trew_mode;
	enum reach_band_mode rb_mode;

	if (kcov_shm == NULL || nr >= MAX_NR_SYSCALL)
		return FRONTIER_COLD_SCALE;

	calls = per_syscall_calls_total(nr);

	/* Never invoked: MAX bias, genuinely under-explored.  Bypass the
	 * shadow A/B math entirely -- both formulas agree on
	 * FRONTIER_COLD_SCALE in this case and the early return keeps the
	 * cold-path overhead untouched for syscalls that have never seen
	 * a single call. */
	if (calls == 0)
		return FRONTIER_COLD_SCALE;

	edges = per_syscall_edges_total(nr);

	/* OLD weight (call-count only): the live-path productivity signal
	 * this function has always returned.  Logic preserved verbatim from
	 * the pre-blend implementation.  Computed unconditionally so the
	 * SHADOW blend below can compare against it, then returned at the
	 * tail so the picker's per-syscall distribution stays byte-
	 * identical to today.
	 *
	 *  edges == 0 -- invoked but never productive (bug-graveyard);
	 *  edges >= calls -- RELAXED-load inversion against the steady-
	 *                    state edges <= calls invariant, treat as
	 *                    fully productive (would otherwise underflow
	 *                    the unsigned subtract).
	 *
	 * The caller's (w+1)/(SCALE+1) accept floor keeps a w == 0
	 * syscall reachable in both regimes. */
	if (edges == 0)
		old_weight = 0;
	else if (edges >= calls)
		old_weight = 0;
	else
		old_weight = FRONTIER_COLD_SCALE -
			     (edges * FRONTIER_COLD_SCALE) / calls;

	/* BLENDED weight (mode-gated): treat
	 * per_syscall_edges (call-count of productive calls) as the stable
	 * backbone and ADD logarithmic credit for three disjoint per-call
	 * yield signals:
	 *
	 *   bucket_bits_real
	 *       PC bit transitions across the AFL-style hit-count buckets
	 *       (per_syscall_diag[].bucket_bits_real).  Fires when a known
	 *       edge moves into a never-seen hit-count bucket -- "new
	 *       behaviour on known code".  Weight 1x.
	 *
	 *   distinct_pcs
	 *       First-sight PC events (per_syscall_diag[].distinct_pcs):
	 *       dedup_inc first-sightings of a PC the global bitmap had
	 *       not seen.  Unambiguous new coverage; weighted 2x to
	 *       reflect higher signal-to-noise than the bucket-bit term.
	 *
	 *   transition_edges_real_local  (THIS COMMIT)
	 *       New transition slots flipped (per_syscall_transition_edges_
	 *       real_local): a 0 -> 1 in the (prev_canon_pc, cur_canon_pc)
	 *       hash, restricted to local-mode traces.  Fires when a new
	 *       ORDERING between two PCs is observed -- can happen on
	 *       warm-known code (a new route through already-mapped
	 *       blocks).  Weight 1x: symmetric to bucket_bits in that a
	 *       transition can fire on already-known edges, so the
	 *       higher-confidence 2x slot stays reserved for distinct_pcs.
	 *
	 * The three terms are STRICTLY DISJOINT discovery signals: a
	 * single PC-edge discovery bumps {edges, bucket_bits_real,
	 * distinct_pcs}; a single transition discovery bumps
	 * {transition_edges_real_local} and (via kcov_collect's separate
	 * branch) {per_syscall_transition_edges_real}.  A call that
	 * discovers both kinds of novelty correctly contributes to both
	 * terms because two distinct novelty events happened -- there is
	 * no double-counting.  Composition with the PC-edge backbone
	 * is coordinated with 434ca4fc8c96 ("random-syscall: shadow-score
	 * blended frontier cold weight"), which introduced the bucket-bits
	 * and distinct-pcs terms; the disjoint transition term layered on
	 * top is what makes blend_weight differ from old_weight under
	 * COMBINED mode.
	 *
	 * Diag counters are split by [nr][do32]; sum both arch slots so
	 * the blend's productivity numerator pairs against the unsplit
	 * per_syscall_calls denominator above -- matches the unsplit
	 * per_syscall_edges shape the old branch uses.  Transitions are
	 * unsplit by [do32] (the per_syscall_transition_edges family
	 * never grew the arch split), so a single load suffices for the
	 * transition term.
	 *
	 * ilog2() is the per-call contribution clamp on each term: a
	 * syscall whose single huge trace dumped a million transition
	 * slots contributes ~20 to the score, not a million, so one
	 * productive call cannot monopolize the frontier window.
	 *
	 * blend_productivity is capped at calls so the SCALE subtraction
	 * cannot underflow -- same invariant the OLD branch above relies
	 * on for the productive range.
	 *
	 * The transition term is folded only when kcov_transition_reward_
	 * mode != OFF.  Under SHADOW_ONLY the term IS folded into
	 * blend_weight (so the A/B counters below measure the divergence
	 * the COMBINED switch would activate); the function still returns
	 * old_weight, so live selection stays byte-identical.  Under OFF
	 * the term is zeroed so blend_weight reproduces the legacy formula
	 * exactly, keeping the A/B counters comparable to baseline runs. */
	trew_mode = __atomic_load_n(&kcov_transition_reward_mode,
				    __ATOMIC_RELAXED);

	bucket_bits = __atomic_load_n(
			&kcov_shm->per_syscall_cmp.per_syscall_diag[nr][0].bucket_bits_real,
			__ATOMIC_RELAXED) +
		      __atomic_load_n(
			&kcov_shm->per_syscall_cmp.per_syscall_diag[nr][1].bucket_bits_real,
			__ATOMIC_RELAXED);
	distinct_pcs = __atomic_load_n(
			&kcov_shm->per_syscall_cmp.per_syscall_diag[nr][0].distinct_pcs,
			__ATOMIC_RELAXED) +
		       __atomic_load_n(
			&kcov_shm->per_syscall_cmp.per_syscall_diag[nr][1].distinct_pcs,
			__ATOMIC_RELAXED);
	transition_edges_real_local =
		(trew_mode == KCOV_TRANSITION_REWARD_OFF) ? 0UL :
		__atomic_load_n(
			&kcov_shm->transitions.per_syscall_transition_edges_real_local[nr],
			__ATOMIC_RELAXED);

	blend_productivity = edges +
			     (unsigned long)ilog2_ul(bucket_bits + 1UL) +
			     2UL * (unsigned long)ilog2_ul(distinct_pcs + 1UL) +
			     (unsigned long)ilog2_ul(transition_edges_real_local + 1UL);
	if (blend_productivity >= calls)
		blend_weight = 0;
	else
		blend_weight = FRONTIER_COLD_SCALE -
			       (blend_productivity * FRONTIER_COLD_SCALE) /
			       calls;

	/* A/B counters.  Bumped once per call so the operator can read
	 * the run-wide divergence pattern between the OLD (call-count
	 * only) and BLENDED (call-count + ilog2(bucket_bits) +
	 * 2*ilog2(distinct_pcs) + ilog2(transition_edges_real_local))
	 * productivity scores.  Counter names predate the transition
	 * term but the semantics ("how often the blend would steer
	 * differently") are unchanged.  The counters fire from both
	 * arms in lock-step so the would-be divergence stays observable
	 * regardless of which arm the calling child is stamped under;
	 * the LIVE behaviour delta from Arm B's blend_weight promotion
	 * shows up downstream in frontier_silent_picks / per-syscall
	 * pick rates rather than in these sums. */
	__atomic_fetch_add(&shm->stats.frontier.plateau.blend_samples, 1UL,
			   __ATOMIC_RELAXED);
	__atomic_fetch_add(&shm->stats.frontier.plateau.blend_old_weight_sum,
			   old_weight, __ATOMIC_RELAXED);
	__atomic_fetch_add(&shm->stats.frontier.plateau.blend_new_weight_sum,
			   blend_weight, __ATOMIC_RELAXED);
	if (blend_weight < old_weight)
		__atomic_fetch_add(&shm->stats.frontier.plateau.blend_new_lower,
				   1UL, __ATOMIC_RELAXED);
	else if (blend_weight > old_weight)
		__atomic_fetch_add(&shm->stats.frontier.plateau.blend_new_higher,
				   1UL, __ATOMIC_RELAXED);
	else
		__atomic_fetch_add(&shm->stats.frontier.plateau.blend_new_equal,
				   1UL, __ATOMIC_RELAXED);

	/* Per-child A/B arm promotes the blend (now including the
	 * transition term) to the live picker for half the children
	 * (Arm B); the other half (Arm A) returns the historical OLD
	 * weight so the picker's per-syscall distribution stays byte-
	 * identical to the pre-blend baseline for that cohort.  The
	 * frontier_blend_* shm counters above record the would-be
	 * divergence for both arms in lock-step, so the operator can
	 * read the live promotion delta off a single run instead of
	 * gating it on a fleet-wide mode flip.  child==NULL (parent
	 * context, should not reach here under the FRONTIER picker)
	 * falls back to the OLD weight to preserve baseline behaviour. */
	if (child != NULL && child->frontier_blend_arm_b)
		picked_weight = blend_weight;
	else
		picked_weight = old_weight;

	/* Reach-band picker weighting (default off).  Bands the syscall
	 * by edges_total (per_syscall_edges + warm-loaded _prior) and
	 * adjusts the silent-regime weight returned above so the MID
	 * band's stale slot is demoted harder than the cold curve alone
	 * gives it, while the HIGH band's productive slot earns a
	 * protection bump that the inverse-productivity old/blend weight
	 * formula otherwise sinks toward zero.  See include/reach-band.h
	 * for the OFF / SHADOW_ONLY / COMBINED contract and the band-
	 * boundary / multiplier rationale.
	 *
	 * OFF early-out: the mode load is the only work done under
	 * default; the band classification, edges_prior / total_calls /
	 * last_edge_at loads, and the demote/boost arithmetic are all
	 * skipped, so a fixed-seed dry-run is byte-identical to a build
	 * before this row.  The mode load consumes no RNG, matching the
	 * mode-load shape kcov_transition_reward_mode and frontier_group_
	 * antilock_mode use at their own hook sites.
	 *
	 * RELAXED-load guard: edges, kcov_shm->per_syscall.per_syscall_edges_prior,
	 * total_calls, and last_edge_at[nr] are separate atomic loads
	 * that can sample inconsistent snapshots; the (total > last) +
	 * (total - last) > KCOV_COLD_THRESHOLD pair is the same shape
	 * the cold-skip helper in kcov.c uses to keep the unsigned
	 * subtract from wrapping when last momentarily reads larger
	 * than total under a concurrent kcov_collect update.  Match
	 * that idiom -- treat the inverted sample as "no stale gap"
	 * rather than wrapping. */
	rb_mode = __atomic_load_n(&reach_band_mode, __ATOMIC_RELAXED);
	if (rb_mode != REACH_BAND_OFF) {
		unsigned long reach;
		unsigned long total, last;
		unsigned long band_weight = picked_weight;
		bool stale = false;

		reach = edges + per_syscall_edges_prior_total(nr);

		total = __atomic_load_n(&kcov_shm->coverage.total_calls,
					__ATOMIC_RELAXED);
		last = __atomic_load_n(&kcov_shm->per_syscall.last_edge_at[nr],
				       __ATOMIC_RELAXED);
		if (total > last && (total - last) > KCOV_COLD_THRESHOLD)
			stale = true;

		if (reach >= REACH_BAND_HIGH_THRESHOLD) {
			/* HIGH band, fresh edges: lift the silent-regime
			 * weight back up by a fraction of the FRONTIER_
			 * COLD_SCALE headroom so the long-tail deep-reach
			 * discoverer is not starved by the inverse-
			 * productivity transform.  A stale HIGH-reach slot
			 * keeps its base weight -- the cold-skip path is
			 * the right place to handle staleness on a slot
			 * that has already earned its productivity. */
			__atomic_fetch_add(
				&shm->stats.picker_bandit.reach_band_picks_per_band[REACH_BAND_IDX_HIGH],
				1UL, __ATOMIC_RELAXED);
			if (!stale) {
				unsigned long headroom =
					(unsigned long)FRONTIER_COLD_SCALE -
					picked_weight;

				__atomic_fetch_add(
					&shm->stats.picker_bandit.reach_band_would_boost_high,
					1UL, __ATOMIC_RELAXED);
				band_weight = picked_weight +
					      headroom /
					      REACH_BAND_HIGH_FRESH_BOOST_DEN;
				if (band_weight >
				    (unsigned long)FRONTIER_COLD_SCALE)
					band_weight =
						(unsigned long)FRONTIER_COLD_SCALE;
			}
		} else if (reach >= REACH_BAND_MID_THRESHOLD) {
			/* MID band, stale gap: halve the silent-regime
			 * weight on top of whatever the cold-skip path
			 * has already imposed at the heuristic gate.  A
			 * MID-reach slot that has gone cold is the
			 * primary call-budget consumer this row reclaims
			 * -- a band_weight of 0 cleanly falls through to
			 * the (w + 1)/(SCALE + 1) accept floor so the
			 * slot is reachable, not unreachable. */
			__atomic_fetch_add(
				&shm->stats.picker_bandit.reach_band_picks_per_band[REACH_BAND_IDX_MID],
				1UL, __ATOMIC_RELAXED);
			if (stale) {
				__atomic_fetch_add(
					&shm->stats.picker_bandit.reach_band_would_demote_mid,
					1UL, __ATOMIC_RELAXED);
				band_weight = picked_weight /
					      REACH_BAND_MID_STALE_DEMOTE_DEN;
			}
		} else {
			/* LOW band: no band action.  The graduated cold-skip
			 * path already filters these via its KCOV_COLD_
			 * THRESHOLD gap window; layering an extra demote on
			 * a reach < 10 slot would push barely-tried syscalls
			 * below the live picker's accept floor before they
			 * have had a chance to produce.  The pick is still
			 * tallied so the per-band split sums to the gate's
			 * non-OFF entry count. */
			__atomic_fetch_add(
				&shm->stats.picker_bandit.reach_band_picks_per_band[REACH_BAND_IDX_LOW],
				1UL, __ATOMIC_RELAXED);
		}

		if (rb_mode == REACH_BAND_COMBINED)
			picked_weight = band_weight;
		/* SHADOW_ONLY: band_weight computed but discarded; the
		 * per-band picks + would_demote_mid + would_boost_high
		 * counters above record the COMBINED-mode decisions for
		 * before-after measurement without perturbing the live
		 * weight (which still returns the OLD/blend value). */
	}

	return picked_weight;
}
/*
 * CMP-weighted alternate weight for the silent-regime accept gate in
 * set_syscall_nr_coverage_frontier() below.  See the enum comment in
 * include/cmp-frontier.h for the OFF / SHADOW_ONLY / COMBINED contract
 * and the source-counter rationale.
 *
 * Returns a weight in [0, FRONTIER_COLD_SCALE].  Sources are the two
 * per-syscall CMP-insert counters the dump_stats() "Top syscalls by
 * CMP unique inserts" block already consumes -- per_syscall_cmp_inserts
 * (durable pool) and childop_cmp_pool_inserts (childop pool) -- so
 * no parallel sampler is added.  ilog2 clamps each per-counter
 * contribution so a single very-active syscall cannot monopolise the
 * weight; the SIGNAL_SCALE multiplier maps the typical 0..20 sum onto
 * most of [0, FRONTIER_COLD_SCALE] and the result is saturated at
 * FRONTIER_COLD_SCALE.  kcov_shm == NULL / nr out of range short-
 * circuits to 0 -- the silent gate's (w + 1) / (SCALE + 1) accept
 * floor keeps a zero-weight syscall reachable, matching the cold-
 * weight degrade-safe contract.
 *
 * Conversion accounting layers a third term on top of the two
 * inserts proxies: per-syscall cmp-hint injections and their PC-edge
 * plus transition wins are read from cmp_hint_ps and folded into a
 * bounded conv_bonus (see the sample-size floor and scaling
 * rationale on the block below) so proven converters are lifted
 * above flat peers in the same insert-volume tier.
 */
/*
 * Sample-size floor for the conversion-rate bonus.  Below this many
 * cmp-hint injections we ignore the conversion ratio entirely -- a
 * 1/1 = 100% noise spike must not dominate ranking against syscalls
 * with thousands of injections.  Sized at the same order as the
 * typical per-window inject volume for an active syscall. */
#define CMP_FRONTIER_MIN_INJECTED	32UL

/*
 * Conversion-rate boost magnitude.  rate_milli is wins-per-1000-
 * injections (0..1000); ilog2_ul(1 + rate_milli * SCALE / 1000) caps
 * the bonus at roughly ilog2(257) = 8 for a 100%-converting syscall,
 * which roughly doubles the typical 8-12 base signal -- lifts proven
 * converters above flat peers in the same volume tier without
 * letting them monopolise the weight. */
#define CMP_FRONTIER_CONVERSION_SCALE	256UL

unsigned long cmp_frontier_weight(unsigned int nr)
{
	unsigned long cmp_inserts, childop_inserts;
	unsigned long injected, pc_wins, tr_wins, wins;
	unsigned long base, conv_bonus = 0, signal, weight;

	if (kcov_shm == NULL || nr >= MAX_NR_SYSCALL)
		return 0;

	cmp_inserts = __atomic_load_n(&kcov_shm->per_syscall_cmp.per_syscall_cmp_inserts[nr],
				      __ATOMIC_RELAXED);
	childop_inserts = __atomic_load_n(
			&kcov_shm->childop_cmp.childop_cmp_pool_inserts[nr],
			__ATOMIC_RELAXED);

	/*
	 * Conversion-rate bonus.  per_syscall_cmp_injected /
	 * per_syscall_cmp_hint_pc_wins are the raw cmp-hint pipeline's
	 * per-syscall PC-edge attribution that has existed for a while;
	 * per_syscall_cmp_hint_transition_wins is the typed-hyp side
	 * channel wired in earlier in this stack.  Sum PC + transition
	 * wins for the conversion numerator -- both are real
	 * attributable yields of an injected hint, and treating them
	 * separately would let a transition-rich syscall rank as flat
	 * just because PC edges have plateaued.
	 *
	 * Gated on a sample-size floor (CMP_FRONTIER_MIN_INJECTED) so
	 * a 1/1 = 100% conversion noise spike does not dominate the
	 * weight; ilog2 of the scaled rate caps the bonus to the same
	 * magnitude band as the base inserts signal so a proven
	 * converter is lifted out of its insert-volume tier without
	 * monopolising the frontier.  A syscall with 0% conversion
	 * gets conv_bonus = 0 and ranks on inserts alone (the
	 * historical behaviour) -- degrade-safe.
	 */
	injected = __atomic_load_n(&kcov_shm->cmp_hint_ps.per_syscall_cmp_injected[nr],
				   __ATOMIC_RELAXED);
	pc_wins = __atomic_load_n(&kcov_shm->cmp_hint_ps.per_syscall_cmp_hint_pc_wins[nr],
				  __ATOMIC_RELAXED);
	tr_wins = __atomic_load_n(
			&kcov_shm->cmp_hint_ps.per_syscall_cmp_hint_transition_wins[nr],
			__ATOMIC_RELAXED);
	wins = pc_wins + tr_wins;
	if (injected >= CMP_FRONTIER_MIN_INJECTED && wins > 0UL) {
		unsigned long rate_milli = (wins * 1000UL) / injected;
		unsigned long scaled = 1UL + (rate_milli *
					      CMP_FRONTIER_CONVERSION_SCALE) /
					      1000UL;

		conv_bonus = (unsigned long)ilog2_ul(scaled);
	}

	base = (unsigned long)ilog2_ul(cmp_inserts + 1UL) +
	       (unsigned long)ilog2_ul(childop_inserts + 1UL);
	signal = base + conv_bonus;
	weight = signal * CMP_FRONTIER_SIGNAL_SCALE;
	if (weight > (unsigned long)FRONTIER_COLD_SCALE)
		weight = (unsigned long)FRONTIER_COLD_SCALE;
	return weight;
}
