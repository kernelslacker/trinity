/*
 * SHADOW typed-hypothesis derive lane.
 *
 * Split out of hyp.c: the per-kind derive ladder
 * (cmp_hyp_derive_value) plus the two SHADOW shadow-only probe
 * classes (pow2 / alignment, bitmask FULL_OR / ANDNOT_TOGGLE) it
 * fans out to on emission.
 *
 * cmp_hyp_derive_value drops static because the live inject arm in
 * hyp-live.c consumes it; declaration lives in
 * cmp_hints/hyp-internal.h.  The shadow probes stay static -- they
 * are only called from cmp_hyp_derive_value at the shared out_bump
 * label.
 */

#include <stdint.h>

#include "arch.h"
#include "cmp_hints.h"
#include "cmp_hints-internal.h"
#include "cmp_hints/hyp-internal.h"
#include "kcov.h"
#include "rnd.h"

/*
 * Bit-pattern test for the SHADOW pow2 / alignment derive class: true
 * when C is at or within +/-1 of a power of two.  A strict popcount==1
 * test would miss the common off-by-one boundary constants
 * (511 vs 512, 4095 vs 4096) that the pow2 lane's would-emit ladder
 * targets, so the neighbourhood is folded into the eligibility gate
 * itself.  C == 0 is treated as ineligible (round-to-N variants would
 * all collapse to zero and the >>1 / <<1 arms carry no information),
 * matching the empty-mask fallback shape the BITMASK derive uses.
 */
static bool cmp_hyp_is_near_pow2(uint64_t c)
{
	if (c == 0)
		return false;
	if ((c & (c - 1)) == 0)
		return true;
	if (((c + 1) & c) == 0)
		return true;
	if (c >= 1 && ((c - 1) & (c - 2)) == 0 && (c - 1) != 0)
		return true;
	return false;
}

/*
 * SHADOW pow2 / alignment derive-class measurement.  Runs on every
 * derive whose callsite is a size / offset-class argtype
 * (ARG_RANGE / ARG_STRUCT_SIZE) AND whose picked exemplar is at or
 * near a power of two.  Bumps cmp_hyp_pow2_derive_would_fire on
 * eligibility, and cmp_hyp_pow2_derive_would_win when at least one
 * candidate from the {C>>1, C, C<<1, round-to-512, round-to-4096,
 * round-to-page-size} ladder differs from live_out (the value the
 * live derive lane just wrote to *out).  Does NOT touch *out and does
 * NOT emit into the live candidate stream -- pure observation.
 *
 * Argtype gate rationale: flag / enum callsites overlap the existing
 * EXACT / ENUM_FAMILY lanes, so a pow2 lane firing there is wasted
 * pick budget with no coverage headroom.  Size / offset callsites
 * (length caps, struct-size fields, offset arguments) are where
 * powers of two carry real meaning (page-boundary, cache-line,
 * allocator bucket) and where the existing lanes' exemplar / lo /
 * hi / mask candidates do NOT construct the neighbourhood the class
 * targets.
 *
 * Bug-pattern guards: page_size is read via a plain load and clamped
 * to a well-defined power of two before the round-up computation
 * (a torn read of a zero page_size would divide-by-zero the naive
 * form).  The shift arms mask to 64 bits so an out-of-range shift
 * (C == 0 already gated above, C == 2^63 for <<1) does not surface
 * as UB.  The round-up computations use the standard
 * (v + align - 1) & ~(align - 1) form after verifying v + align does
 * not overflow; on overflow the arm is skipped rather than emitting
 * a wrapped value.
 */
static void cmp_hyp_pow2_shadow_probe(const struct cmp_hypothesis *picked,
				      enum cmp_hint_callsite callsite,
				      unsigned long live_out)
{
	uint64_t c, cand;
	uint64_t page_align;
	uint64_t live_val;
	bool differs;

	if (kcov_shm == NULL || picked == NULL)
		return;
	if (callsite != CMP_HINT_CALLSITE_ARG_RANGE &&
	    callsite != CMP_HINT_CALLSITE_ARG_STRUCT_SIZE)
		return;

	c = picked->exemplar;
	if (!cmp_hyp_is_near_pow2(c))
		return;

	__atomic_fetch_add(&kcov_shm->cmp_hyp_shadow.cmp_hyp_pow2_derive_would_fire, 1UL,
			   __ATOMIC_RELAXED);

	live_val = (uint64_t)live_out;
	differs = false;

	/* C>>1 arm: informationless when C == 0 (gated above) or C == 1
	 * (right-shift yields 0, indistinguishable from the empty-mask
	 * fallback). */
	if (c >= 2) {
		cand = c >> 1;
		if (cand != live_val)
			differs = true;
	}

	/* C arm: the exemplar itself.  Existing lanes may already emit it
	 * (EXACT exemplar, ENUM_FAMILY exemplar), which is precisely why
	 * this candidate is expected to MATCH live_val on the equality-
	 * dominated path -- the would_win partition surfaces the rest. */
	if (c != live_val)
		differs = true;

	/* C<<1 arm: gated against high-bit wrap.  c & (1ULL<<63) != 0
	 * would shift the sign bit out; skip cleanly (the round-to-N
	 * arms below still contribute a candidate). */
	if ((c & (1ULL << 63)) == 0) {
		cand = c << 1;
		if (cand != live_val)
			differs = true;
	}

	/* Round-to-512 / 4096: standard (v + align - 1) & ~(align - 1),
	 * skipped when the add would wrap (v > UINT64_MAX - (align - 1)).
	 * The round-DOWN arm collapses to c & ~(align - 1) and is always
	 * well-defined for non-zero c, but a v < align input rounds down
	 * to zero, so the more useful signal is round-UP. */
	if (c <= (uint64_t)~0ULL - 511UL) {
		cand = (c + 511UL) & ~(uint64_t)511UL;
		if (cand != live_val)
			differs = true;
	}
	if (c <= (uint64_t)~0ULL - 4095UL) {
		cand = (c + 4095UL) & ~(uint64_t)4095UL;
		if (cand != live_val)
			differs = true;
	}

	/* Round-to-page-size: page_size is a runtime global, clamp to a
	 * safe power of two (4096) if a torn / zero read would break the
	 * mask math.  __builtin_popcount check gates the clamp to a
	 * non-pow2 page_size (e.g. a mid-init garbage read), so the align
	 * math stays valid. */
	page_align = (uint64_t)page_size;
	if (page_align == 0 || __builtin_popcountll(page_align) != 1)
		page_align = 4096UL;
	if (c <= (uint64_t)~0ULL - (page_align - 1UL)) {
		cand = (c + page_align - 1UL) & ~(page_align - 1UL);
		if (cand != live_val)
			differs = true;
	}

	if (differs)
		__atomic_fetch_add(&kcov_shm->cmp_hyp_shadow.cmp_hyp_pow2_derive_would_win,
				   1UL, __ATOMIC_RELAXED);
}

/*
 * SHADOW BITMASK combination derive-class measurement.  The live
 * BITMASK lane in cmp_hyp_derive_value() emits a SINGLE bit chosen
 * uniformly from picked->mask (the accumulated OR of every single-bit
 * constant observed at (nr, cmp_ip, width) by cmp_hyp_observe -- the
 * per-hypothesis short-window "pair tracker" this class needs is
 * already materialised in picked->mask because observations at the
 * same (nr, cmp_ip, width) fold into the SAME BITMASK entry).  Two
 * combination probes carry information the single-bit lane cannot:
 *
 *  FULL_OR (would-fire on popcount(mask) >= 2, would-win when the OR
 *  differs from the single bit the live lane just emitted): the OR
 *  of all observed single-bit constants.  Reaches predicates of the
 *  form `(flags & A) && (flags & B)` -- both arms need both bits set
 *  simultaneously, and a lane that only ever fires ONE bit at a time
 *  hits AT MOST one arm per probe.
 *
 *  ANDNOT_TOGGLE (would-fire on popcount(~mask & width_mask) in
 *  [1, 8], would-win when at least one toggled candidate differs
 *  from the live-emitted single bit): treat the observed single-bit
 *  set as the "allowed" bit mask of an `x & ~c` predicate.  The
 *  complement within the operand width is the disallowed-bit mask
 *  c -- toggling each set bit in c one at a time surfaces WHICH
 *  disallowed bit trips the gate.  The 1..8 popcount gate keeps the
 *  candidate set small (a 64-bit width with no observations would
 *  otherwise produce 64 candidates and swamp the measurement) and
 *  restricts the class to sites where the "few disallowed bits"
 *  shape is plausible -- if the complement is dense, the site is
 *  more likely EXACT / ENUM_FAMILY-shaped and the existing lanes
 *  already cover it.
 *
 * Termination stop-condition prose (baked into the shadow gate
 * intentionally): FULL_OR is kept shadow-only in this change even
 * on a large would-win ratio because a lane that always emits the
 * SAME picked->mask on every fire at a given site would only
 * reproduce already-seen edges once the combo gate behind the mask
 * has converted, so a live promotion needs a follow-up feedback-
 * loop input (per-hypothesis pc_win credit on the OR probe) to
 * confirm the combo gate exists at all before it can be judged.
 * ANDNOT_TOGGLE is kept shadow-only for the mirror reason: without
 * per-bit credit attribution the toggle sweep would fire the same
 * candidate ladder every time regardless of which disallowed bit
 * was actually the tripping one.  These counters size the coverage
 * headroom of both classes; the live promotion decision is a
 * follow-up.
 *
 * Bug-pattern guards:
 *   * width_mask computed via the same >=8 short-circuit the
 *     BOUNDARY arm uses (a picked->width of 8 covers the full
 *     uint64, so the (1<<64) shift is skipped -- would be UB).
 *   * disallowed-bit iteration walks bits 0..63 with an explicit
 *     mask test rather than shifting a running bit until wrap; on a
 *     torn read of picked->width, a 0 width_mask yields disallowed
 *     == 0 and the loop simply does not fire the would-win path
 *     (the would-fire gate above already needs popcount >= 1).
 *   * a would-fire that finds no differing toggle candidate does
 *     NOT bump would-win, so the live-lane single-bit picks that
 *     the toggle set happens to hit (e.g. mask == 0x01 and picked
 *     bit == 0x01, toggle over disallowed bit 1 yields 0x03 which
 *     obviously differs) are not double-counted -- the FIRST
 *     differing candidate is enough evidence.
 */
static void cmp_hyp_bitmask_shadow_probe(const struct cmp_hypothesis *picked,
					 unsigned long live_out)
{
	uint64_t mask, width_mask, disallowed, cand;
	uint64_t live_val;
	unsigned int mask_pop, disallowed_pop;
	unsigned int bit_idx;
	bool andnot_differs;

	if (kcov_shm == NULL || picked == NULL)
		return;
	if (picked->kind != CMP_HYP_BITMASK)
		return;

	mask = picked->mask;
	if (mask == 0)
		return;

	mask_pop = (unsigned int)__builtin_popcountll(mask);
	live_val = (uint64_t)live_out;

	/* FULL_OR: needs at least two distinct observed bits, else the
	 * OR degenerates to the same single bit the live lane emits. */
	if (mask_pop >= 2) {
		__atomic_fetch_add(
			&kcov_shm->cmp_hyp_shadow.cmp_hyp_bitmask_full_or_would_fire,
			1UL, __ATOMIC_RELAXED);
		if (mask != live_val)
			__atomic_fetch_add(
				&kcov_shm->cmp_hyp_shadow.cmp_hyp_bitmask_full_or_would_win,
				1UL, __ATOMIC_RELAXED);
	}

	/* ANDNOT_TOGGLE: width_mask via the same >=8 short-circuit the
	 * BOUNDARY arm uses so a picked->width of 8 does not shift by
	 * 64 (UB). */
	width_mask = (picked->width >= 8)
		? ~(uint64_t)0
		: ((uint64_t)1 << (picked->width * 8)) - 1;
	disallowed = (~mask) & width_mask;
	disallowed_pop = (unsigned int)__builtin_popcountll(disallowed);
	if (disallowed_pop < 1 || disallowed_pop > 8)
		return;

	__atomic_fetch_add(
		&kcov_shm->cmp_hyp_shadow.cmp_hyp_bitmask_andnot_toggle_would_fire,
		1UL, __ATOMIC_RELAXED);

	andnot_differs = false;
	for (bit_idx = 0; bit_idx < 64; bit_idx++) {
		uint64_t bit = (uint64_t)1 << bit_idx;

		if ((disallowed & bit) == 0)
			continue;
		cand = mask | bit;
		if (cand != live_val) {
			andnot_differs = true;
			break;
		}
	}
	if (andnot_differs)
		__atomic_fetch_add(
			&kcov_shm->cmp_hyp_shadow.cmp_hyp_bitmask_andnot_toggle_would_win,
			1UL, __ATOMIC_RELAXED);
}

/*
 * Derive ONE candidate value from PICKED via the spec's ladder.  Every
 * derived value is constructed so cmp_hyp_find_for_credit() will
 * re-resolve back to a hypothesis at the same (cmp_ip, width) at
 * credit time -- either the SAME hypothesis (EXACT.exemplar matches
 * EXACT; ENUM_FAMILY exemplar / lo / hi all lie in [lo, hi]; BITMASK
 * single set-bit is single-bit AND set in mask; RANGE lo / hi /
 * midpoint all lie in [lo, hi]) or, for the EXACT +/-1 arms, the
 * co-populated BOUNDARY hypothesis at the same (cmp_ip, width) via
 * its +/-2 credit window.  For RANGE, boundary probes (lo-1, hi+1)
 * are deliberately NOT emitted -- they fall outside [lo, hi] and so
 * are unreachable by the value-keyed credit walk, which would
 * silently drop their attribution; that neighbourhood is instead the
 * BOUNDARY arm's job.  The EXACT arm's +/-1 rotation is safe because
 * BOUNDARY co-registers on every observation and its credit window
 * (CMP_HYP_BOUNDARY_CREDIT_WINDOW == 2) is wide enough to cover the
 * shifted values.
 *
 * Bug-pattern rules applied:
 *   * midpoint computed as lo + ((hi - lo) >> 1) so (lo + hi) cannot
 *     overflow.
 *   * RANGE rejects hi < lo (a torn read of an in-flight RANGE entry
 *     would otherwise underflow).
 *   * BITMASK with mask == 0 falls back to exemplar so the
 *     popcount-walk loop is never entered with an empty mask.
 *   * popcount-walk bounds via __builtin_popcountll so the bit-pick
 *     index is in [0, popcount); the for-loop's bit shift terminates
 *     on the uint64_t high-bit wrap and the seen counter exits
 *     deterministically.
 */
bool cmp_hyp_derive_value(const struct cmp_hypothesis *picked,
			  enum cmp_hint_callsite callsite,
			  unsigned long *out)
{
	uint64_t lo, hi, mask;
	unsigned int popcount, pick, seen;
	uint64_t bit;
	enum cmp_hyp_probe_class cls;

	if (picked == NULL || out == NULL)
		return false;
	switch (picked->kind) {
	case CMP_HYP_EXACT: {
		/*
		 * Rotate uniformly among {N-1, N, N+1}, mirroring
		 * cmp_hint_apply_transform's CMP_HINT_BOUNDARY case.
		 * Before this rotation the derive always returned the
		 * exemplar unchanged -- the compile-time const the kernel
		 * had already observed -- so every LIVE typed EXACT inject
		 * re-fed the site the byte-identical value that got recorded
		 * there in the first place: the equality gate the const
		 * originally passed still passed, but strict-inequality
		 * gates ("x < N", "x > N", the pattern documented in the
		 * CMP_HYP_BOUNDARY block below and in include/kcov.h's
		 * cmp_hyp_boundary_* commentary) stayed unsatisfied and
		 * pc_wins was structurally starved on this arm.  The raw
		 * cmp-hint arm applies this same +/-1 rotation at the same
		 * callsites via cmp_hint_apply_transform's CMP_HINT_BOUNDARY
		 * case, so pre-rotation the LIVE typed EXACT arm was a
		 * strict downgrade of the raw arm's conversion (the raw
		 * arm's own comment at the transform notes "the equality
		 * slot -- C unchanged -- is retained in the rotation, so
		 * the worst case is a 3x slowdown on a purely
		 * equality-dominated callsite, while
		 * length-/cap-/extent-dominated syscalls ... get the
		 * boundary edges they were missing").  The rotation restores
		 * parity with the raw arm and lets the strict-inequality
		 * boundary gates convert on the typed arm too.
		 *
		 * Credit attribution: EXACT's find_for_credit arm demands
		 * exemplar == value, so the +/-1 probes do NOT re-resolve
		 * back to this EXACT hypothesis at credit time -- they fall
		 * through to the BOUNDARY arm's +/-2 credit window
		 * (CMP_HYP_BOUNDARY_CREDIT_WINDOW == 2) and get attributed
		 * to whichever BOUNDARY entry the observe path registered
		 * at the same (cmp_ip, width).  Both EXACT and BOUNDARY
		 * co-populate on every observation (see cmp_hyp_observe),
		 * so a fired shifted probe has a home; if the BOUNDARY
		 * slot was reclaimed, per-hypothesis credit misses but the
		 * pc_win itself is still counted in the flat kcov_shm
		 * rollup.  The exemplar arm still re-resolves to this
		 * EXACT hypothesis exactly as before.
		 *
		 * Unsigned wrap at the extremes (N == 0 -> N-1 ==
		 * ULONG_MAX; N == ULONG_MAX -> N+1 == 0) is intentional
		 * and unclamped, matching the raw transform's rationale:
		 * both wrapped values are themselves useful probes
		 * (underflow exercises length-cap validators; overflow
		 * exercises zero-length rejection paths), and the
		 * downstream accept-range gate in cmp_hints_try_get_ex
		 * rejects any that overshoot the caller's bounds and
		 * counts them under
		 * CMP_HYP_LIVE_INJECT_REASON_ACCEPT_REJECT.
		 *
		 * Probe-class histogram: the +/-1 arms bump the shared
		 * CMP_HYP_PROBE_CLASS_BOUNDARY_MINUS1 / _PLUS1 buckets by
		 * *probe shape* rather than by originating hypothesis --
		 * a "constant nudged down/up by 1" probe reached the
		 * kernel, which is what a downstream reader wants to
		 * measure.  Splitting these into dedicated
		 * EXACT_MINUS1 / _PLUS1 buckets would need an
		 * include/kcov.h enum extension deferred to a follow-up if
		 * the shared bucket becomes ambiguous in practice.
		 */
		uint64_t n = picked->exemplar;

		switch (rnd_modulo_u32(3)) {
		case 0:
			*out = (unsigned long)(n - 1);
			cls = CMP_HYP_PROBE_CLASS_BOUNDARY_MINUS1;
			goto out_bump;
		case 2:
			*out = (unsigned long)(n + 1);
			cls = CMP_HYP_PROBE_CLASS_BOUNDARY_PLUS1;
			goto out_bump;
		/* case 1 (and default): N unchanged.  Retains the exact
		 * equality-gate probe so equality-dominated callsites
		 * (cmd codes, enum selectors, version magics) keep
		 * converting on the typed arm. */
		default:
			*out = (unsigned long)n;
			cls = CMP_HYP_PROBE_CLASS_EXACT_EXEMPLAR;
			goto out_bump;
		}
	}
	case CMP_HYP_ENUM_FAMILY:
		switch (rnd_modulo_u32(3)) {
		case 0:
			*out = (unsigned long)picked->exemplar;
			cls = CMP_HYP_PROBE_CLASS_ENUM_EXEMPLAR;
			goto out_bump;
		case 1:
			*out = (unsigned long)picked->lo;
			cls = CMP_HYP_PROBE_CLASS_ENUM_LO;
			goto out_bump;
		default:
			*out = (unsigned long)picked->hi;
			cls = CMP_HYP_PROBE_CLASS_ENUM_HI;
			goto out_bump;
		}
	case CMP_HYP_BITMASK:
		mask = picked->mask;
		if (mask == 0) {
			*out = (unsigned long)picked->exemplar;
			cls = CMP_HYP_PROBE_CLASS_EXEMPLAR_FALLBACK;
			goto out_bump;
		}
		popcount = (unsigned int)__builtin_popcountll(mask);
		pick = rnd_modulo_u32(popcount);
		seen = 0;
		for (bit = 1; bit != 0; bit <<= 1) {
			if ((mask & bit) == 0)
				continue;
			if (seen == pick) {
				*out = (unsigned long)bit;
				cls = CMP_HYP_PROBE_CLASS_BITMASK_SINGLE_BIT;
				goto out_bump;
			}
			seen++;
		}
		/* Unreachable: popcount of a non-zero mask is in
		 * [1, 64], and pick < popcount.  Fall back to exemplar so
		 * a future bit-shape change cannot strand the inject. */
		*out = (unsigned long)picked->exemplar;
		cls = CMP_HYP_PROBE_CLASS_EXEMPLAR_FALLBACK;
		goto out_bump;
	case CMP_HYP_RANGE:
		lo = picked->lo;
		hi = picked->hi;
		if (hi < lo)
			return false;
		switch (rnd_modulo_u32(3)) {
		case 0:
			*out = (unsigned long)lo;
			cls = CMP_HYP_PROBE_CLASS_RANGE_LO;
			goto out_bump;
		case 1:
			*out = (unsigned long)hi;
			cls = CMP_HYP_PROBE_CLASS_RANGE_HI;
			goto out_bump;
		default:
			*out = (unsigned long)(lo + ((hi - lo) >> 1));
			cls = CMP_HYP_PROBE_CLASS_RANGE_MIDPOINT;
			goto out_bump;
		}
	case CMP_HYP_BOUNDARY: {
		/*
		 * Neighbourhood ladder around the exemplar N: the strict-
		 * inequality boundary EXACT cannot pass (the passing value
		 * for `x < N` is N-1, for `x > N` is N+1) and RANGE refuses
		 * to emit (the comment at RANGE bans lo-1 / hi+1 because the
		 * value-keyed credit walk cannot re-resolve them; the lane
		 * here owns that emission and the BOUNDARY arm of
		 * cmp_hyp_find_for_credit() owns the matching credit walk).
		 *
		 * Bug-pattern guards from the audit batch:
		 *   * unsigned underflow: emit N-1 / N-2 only when N >= 1
		 *     / N >= 2; arg1 is u64, N=0 - 1 would otherwise land at
		 *     ULONG_MAX.
		 *   * width overflow: skip the + arms when N is at the
		 *     width's max (1 << (width*8) - 1) so a u8/u16 boundary
		 *     does not wrap to 0 (or, worse, leak high-bit garbage
		 *     past the operand width that the accept gate would then
		 *     reject anyway).
		 *   * mask the derived value to the operand width so an u8
		 *     boundary at value 255 with the +1 arm gated off still
		 *     yields a well-formed 8-bit value when the sweep arm
		 *     touches it.
		 * The accept-range gate in cmp_hints_try_get_ex (and the
		 * caller's own range check) is the second line of defence:
		 * a derived neighbour past the caller's bounds is rejected
		 * cleanly and counted under
		 * CMP_HYP_LIVE_INJECT_REASON_ACCEPT_REJECT.
		 */
		uint64_t n = picked->exemplar;
		uint64_t width_mask = (picked->width >= 8)
			? ~(uint64_t)0
			: ((uint64_t)1 << (picked->width * 8)) - 1;
		uint64_t width_max = width_mask;
		uint64_t cand;
		bool have_cand = false;

		switch (rnd_modulo_u32(4)) {
		case 0:
			if (n >= 1) {
				cand = n - 1;
				cls = CMP_HYP_PROBE_CLASS_BOUNDARY_MINUS1;
				have_cand = true;
				break;
			}
			/* N=0: N-1 would underflow.  Fall through to the +1
			 * arm which is well-defined for N=0 at any width. */
			/* fallthrough */
		case 1:
			if (n < width_max) {
				cand = n + 1;
				cls = CMP_HYP_PROBE_CLASS_BOUNDARY_PLUS1;
				have_cand = true;
				break;
			}
			/* N == width_max: N+1 would overflow the operand
			 * width.  Fall through to the exemplar arm, which
			 * always fits. */
			/* fallthrough */
		case 2:
			cand = n;
			cls = CMP_HYP_PROBE_CLASS_BOUNDARY_EXACT;
			have_cand = true;
			break;
		default:
			/* Widen-by-one sweep for off-by-one chains.  Random
			 * direction; the same underflow / overflow guards as
			 * the +/-1 arms apply at the wider step. */
			if (rnd_modulo_u32(2) == 0) {
				if (n >= 2) {
					cand = n - 2;
					cls = CMP_HYP_PROBE_CLASS_BOUNDARY_SWEEP;
					have_cand = true;
					break;
				}
			} else {
				if (n + 2 > n && n + 2 <= width_max) {
					cand = n + 2;
					cls = CMP_HYP_PROBE_CLASS_BOUNDARY_SWEEP;
					have_cand = true;
					break;
				}
			}
			/* Both sweep directions strand the value at this
			 * width.  Fall back to the exemplar so the lane never
			 * emits "no value" -- the find_for_credit BOUNDARY
			 * window covers exemplar matches too. */
			cand = n;
			cls = CMP_HYP_PROBE_CLASS_BOUNDARY_EXACT;
			have_cand = true;
			break;
		}
		if (!have_cand)
			return false;
		*out = (unsigned long)(cand & width_mask);
		goto out_bump;
	}
	default:
		return false;
	}

out_bump:
	/* SHADOW: census which probe class the derivation just emitted.
	 * Pure observation -- *out is unchanged from the pre-census ladder,
	 * the live inject arm receives the same byte-identical value. */
	if (kcov_shm != NULL)
		__atomic_fetch_add(&kcov_shm->cmp_hyp_results.cmp_hyp_probe_class_hist[cls],
				   1UL, __ATOMIC_RELAXED);

	/* SHADOW: pow2 / alignment probe-class would-fire / would-win
	 * measurement.  Gated on a size / offset-class callsite and a
	 * near-pow2 exemplar; compares the value the live derive just
	 * wrote to *out against the pow2 / align candidate set without
	 * mutating it.  The live derive path (and every downstream
	 * caller of cmp_hyp_derive_value) is byte-for-byte unchanged. */
	cmp_hyp_pow2_shadow_probe(picked, callsite, *out);

	/* SHADOW: bitmask FULL_OR / ANDNOT_TOGGLE would-fire / would-win
	 * measurement.  Gated on picked->kind == CMP_HYP_BITMASK inside
	 * the helper; picked->mask carries the per-(nr, cmp_ip, width)
	 * accumulated OR of all single-bit constants observed at this
	 * site, so no extra pair state is needed.  Nothing else is
	 * touched -- *out and the probe-class histogram bump above are
	 * unchanged. */
	cmp_hyp_bitmask_shadow_probe(picked, *out);
	return true;
}
