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
static unsigned long frontier_cold_weight(unsigned int nr,
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
	 * is coordinated with 86ee2986cec8 ("random-syscall: shadow-score
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
 * Conversion accounting (CMP inserts that translate into NEW PC edges)
 * is not yet a per-syscall counter in kcov_shm; ranking on the two
 * inserts proxies alone is the deliberate first cut here.  A follow-up
 * that adds per-syscall conversion accounting can layer a third term
 * into this helper without changing the call site.
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

static unsigned long cmp_frontier_weight(unsigned int nr)
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
