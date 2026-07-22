/*
 * Per-syscall cmp-hint consumer.
 *
 * cmp_hints_try_get() / try_get_ex() is the entry point every
 * generate-args.c consumer routes through.  This cluster owns the
 * two-tier picker (recent ring first during a rising-PC-flat plateau,
 * durable per-syscall pool otherwise), the per-child A/B stamp that
 * gates the uniform-versus-weighted draw, and the weighted draw itself.
 * The typed-hypothesis inject arm and the SHADOW would-pick resolver
 * are pulled in through include/cmp_hints-internal.h from
 * cmp_hints/hyp.c.
 */

#include <stdint.h>

#include "cmp_hints.h"
#include "cmp_hints-internal.h"
#include "child-api.h"
#include "kcov.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "stats_ring.h"
#include "strategy.h"
#include "tables.h"


/*
 * Per-child A/B stamp + weighted draw for the cmp-hints live-pick
 * policy -- the header-anticipated follow-up to the SHADOW per-entry
 * feedback loop ("weighted live-pick policy" in include/cmp_hints.h).
 *
 * Arm A (false) keeps the historical uniform draw at the two pick
 * sites below; arm B (true) routes the same pick through
 * cmp_hint_weighted_pick(), weighting each entry by
 *
 *      weight = CMP_HINT_LIVEPICK_FLOOR + wins * 4 - misses
 *
 * clamped to >= CMP_HINT_LIVEPICK_FLOOR so a single bad miss cannot
 * extinguish a slot's exploration budget.  The SHADOW recording path
 * (stash + dispatch-tail credit + per-entry .wins/.misses bumps + the
 * flat cmp_hint_wins/cmp_hint_misses counters) is unmodified and
 * fires identically from both arms: arm A is the control whose pick
 * distribution stays uniform; arm B consumes the same fresh score
 * snapshot the SHADOW recorder is producing.
 *
 * Stamp discipline: lazy-stamped on first read inside the child via
 * ONE_IN(2).  The file-static lives in COW'd post-fork memory, so
 * each forked child sees its own copy and the stamp persists for the
 * life of that child process.  Parent context never reaches the pick
 * path (this_child() == NULL on the parent side), so no parent-side
 * stamp ever leaks into a freshly-forked child via COW.  Independent
 * of the other A/B axes (cmp_hint_inject_arm_b / boring_filter_arm_b
 * / frontier_blend_arm_b / ...) so the cohort comparison stays
 * un-confounded.
 *
 * Race tolerance on the weight read: .wins / .misses are RELAXED
 * uint16_t writes from the SHADOW credit drain; the weighted draw
 * loads them with __atomic_load_n RELAXED.  A torn view (a sibling's
 * mid-bump being half-visible) at worst nudges the draw by one weight
 * unit -- the same tolerance the uniform draw already extends to a
 * concurrent eviction of the picked triplet.  Hints are advisory; the
 * next pull resamples.
 */
#define CMP_HINT_LIVEPICK_FLOOR	1U

static bool cmp_hint_livepick_arm_stamped;
static bool cmp_hint_livepick_arm_b;

bool cmp_hint_livepick_arm_b_active(void)
{
	if (!cmp_hint_livepick_arm_stamped) {
		cmp_hint_livepick_arm_b = ONE_IN(2);
		cmp_hint_livepick_arm_stamped = true;
	}
	return cmp_hint_livepick_arm_b;
}

unsigned int cmp_hint_weighted_pick(struct cmp_hint_entry *entries,
					   unsigned int count)
{
	uint32_t weights[CMP_HINTS_PER_SYSCALL];
	uint64_t total = 0;
	uint64_t acc = 0;
	uint32_t draw;
	unsigned int i;

	/* Defensive clamp against a torn count snapshot reaching the
	 * helper: the caller already passes a cmp_hints_pool_corrupted-
	 * gated count, but bounding entries[] access here keeps the
	 * weighted path self-contained against a future caller that
	 * forgets the gate. */
	if (count > CMP_HINTS_PER_SYSCALL)
		count = CMP_HINTS_PER_SYSCALL;

	for (i = 0; i < count; i++) {
		uint16_t w_wins =
			__atomic_load_n(&entries[i].wins, __ATOMIC_RELAXED);
		uint16_t w_misses =
			__atomic_load_n(&entries[i].misses, __ATOMIC_RELAXED);
		int32_t w = (int32_t)CMP_HINT_LIVEPICK_FLOOR
			  + (int32_t)w_wins * 4
			  - (int32_t)w_misses;

		if (w < (int32_t)CMP_HINT_LIVEPICK_FLOOR)
			w = (int32_t)CMP_HINT_LIVEPICK_FLOOR;
		weights[i] = (uint32_t)w;
		total += weights[i];
	}

	/* total >= count * FLOOR > 0 for count > 0; bounded by
	 * CMP_HINTS_PER_SYSCALL * (FLOOR + UINT16_MAX * 4) well under
	 * 2^32 so the rnd_modulo_u32 cast is safe. */
	draw = rnd_modulo_u32((uint32_t)total);

	for (i = 0; i < count; i++) {
		acc += weights[i];
		if ((uint64_t)draw < acc)
			return i;
	}
	/* Unreachable: draw < total and acc accumulates to total above.
	 * Fall back to the last in-bounds slot if a future change drifts
	 * the invariant rather than silently indexing off the array. */
	return count - 1;
}

static bool cmp_try_get_durable_tier(unsigned int nr, bool do32,
				     enum cmp_hint_use use, unsigned long old,
				     bool allow_hyp_inject,
				     const struct cmp_accept_range *accept,
				     unsigned int arg_idx,
				     enum cmp_hint_callsite callsite,
				     unsigned long *out,
				     unsigned int *out_size)
{
	struct cmp_hint_pool *pool = &cmp_hints_shm->pools[nr][do32 ? 1 : 0];
	struct cmp_hint_entry *picked;
	unsigned int count;
	unsigned long picked_value;
	unsigned long picked_cmp_ip;
	uint32_t picked_size;

	/*
	 * Lockless read.  Multiple children fuzzing the same syscall would
	 * otherwise serialize on pool->lock just to grab one hint.
	 *
	 * Tolerated race: a stale count snapshot still indexes a populated
	 * slot — count is monotonic up to the CMP_HINTS_PER_SYSCALL cap, and
	 * once full it stops moving (full-pool eviction overwrites in place).
	 * The per-entry .value field is a naturally-aligned unsigned long, so
	 * a concurrent eviction yields either the pre- or post-overwrite
	 * value at the hardware level; both are valid hints that lived in
	 * the pool.
	 *
	 * For fuzzer hints this is benign — values are direct unsigned longs
	 * substituted as syscall args, never dereferenced.  We do not refresh
	 * the entry's last_used field on lookup: the LRU stamp tracks
	 * insertion freshness from cmp_hints_collect(), which is what the
	 * dedup-vs-eviction policy is built around.
	 */
	count = __atomic_load_n(&pool->count, __ATOMIC_ACQUIRE);
	if (count == 0) {
		/* SHADOW warm-start eligibility probe.  The per-nr durable
		 * pool is COLD on this (nr, do32) slot -- the recent-tier
		 * pre-pass in the caller already returned MISS, and this
		 * empty-pool return is the try_get miss the caller sees.
		 * Fire the shared cmp_ip tier probe to observe whether a
		 * fleet-wide warm-start seed would have been available; the
		 * probe is value-neutral (does NOT read a tier value, does
		 * NOT consume RNG, does NOT change what we return) so live
		 * pick stays byte-for-byte identical under OFF and SHADOW
		 * alike.  Fires unconditionally on the cold-miss branch so
		 * cmp_shared_tier_shadow_warmstart_eligible remains the
		 * complete opportunity denominator regardless of whether
		 * the COMBINED-mode serve below actually returns a
		 * value. */
		cmp_shared_tier_shadow_probe_cold_miss();
		/* COMBINED-mode QUARANTINED live serve.  Fires strictly
		 * lower priority than every native tier: the recent-tier
		 * pre-pass in cmp_try_get_recent_tier returned MISS above
		 * and the per-nr durable pool is empty here, so no native
		 * warm hit was available to prefer.  Under
		 * CMP_SHARED_TIER_MODE_COMBINED the helper elects an
		 * occupied non-entry-path bucket at random, budget-gated
		 * by ONE_IN(CMP_SHARED_TIER_SERVE_DICE), and stashes the
		 * result with served_from_shared=1 so the credit drain
		 * routes the PC outcome to the shared-tier lane ONLY --
		 * a shared-served value NEVER becomes native pool
		 * evidence under this path.  Under SHADOW_ONLY / OFF the
		 * helper short-circuits to false and this branch is
		 * byte-identical to the pre-serve cold-miss return. */
		if (cmp_shared_tier_try_serve_cold_miss(nr, do32, use, old,
							accept, callsite,
							out, out_size))
			return true;
		return false;
	}
	/* Lockless gate: a kernel-side wild write through a syscall arg
	 * pointer can stomp pool->count, and rnd_modulo_u32(garbage) would
	 * then index off the 1.1 MB SHM into an unmapped page.  Hints are
	 * advisory -- skip is the safe response. */
	if (cmp_hints_pool_corrupted(pool, count))
		return false;

	/* A/B-gated live-pick policy.  Arm A (control) keeps the
	 * historical uniform draw; arm B routes the pick through the
	 * weighted draw on the per-entry .wins/.misses score the SHADOW
	 * credit drain maintains.  The stash + credit path below is
	 * unchanged and fires identically from both arms, so the SHADOW
	 * win/miss counters keep flowing as the cohort-rollup signal the
	 * weighted draw is measured against. */
	if (cmp_hint_livepick_arm_b_active())
		picked = &pool->entries[
			cmp_hint_weighted_pick(pool->entries, count)];
	else
		picked = &pool->entries[rnd_modulo_u32(count)];
	/* Snapshot the entry triplet BEFORE the transform so the stash
	 * carries the raw pool-entry identity (cmp_ip, value, size) -- the
	 * tuple the credit drain uses to re-find the same entry.  Reading
	 * each field once locally also avoids reading a torn (cmp_ip, value,
	 * size) triplet on a concurrent eviction: even if a sibling overwrites
	 * the slot between our load of value and load of cmp_ip, the credit
	 * drain just fails to re-find a matching entry and the per-entry score
	 * for that pull is lost (the flat counter still bumps). */
	picked_value = picked->value;
	picked_cmp_ip = picked->cmp_ip;
	picked_size = picked->size;
	/* Staleness sample for the freshness observability counters.
	 * Lock-free reads on the two stamp fields: a torn read (a sibling
	 * insert advancing pool->last_used_stamp between our two loads, or
	 * a concurrent eviction overwriting picked->last_used with a fresh
	 * stamp) at worst misbuckets a single sample, which is acceptable
	 * shadow accounting -- the next pull resamples.  Guard the
	 * unsigned subtraction against a torn read that would make the
	 * entry stamp appear larger than the pool stamp; clamp to 0 per
	 * the codified rule "ensure b <= a at the point of a - b". */
	{
		uint64_t cur_stamp = __atomic_load_n(&pool->last_used_stamp,
						     __ATOMIC_RELAXED);
		uint64_t entry_stamp = __atomic_load_n(&picked->last_used,
						       __ATOMIC_RELAXED);
		uint64_t age = (cur_stamp >= entry_stamp) ?
				(cur_stamp - entry_stamp) : 0;
		uint8_t bucket = cmp_hint_age_bucket(age);
		unsigned long stash_value = picked_value;
		bool hyp_injected = false;
		bool inject_gate_fired = false;
		uint8_t inject_kind = 0;

		/* LIVE typed-hypothesis inject arm.  Runs only for callers
		 * that opted in (the typed-safe argtype set).  When the
		 * conservative gate fires AND the typed store has a
		 * hypothesis at the same (cmp_ip, width) the raw pick just
		 * served, the raw value is replaced by a value derived from
		 * that hypothesis.  Bypasses cmp_hint_apply_transform so the
		 * derived constant reaches the kernel verbatim -- a +/-1
		 * BOUNDARY shift on top of the derived value would dodge the
		 * value-keyed credit re-resolution path in
		 * cmp_hyp_find_for_credit, silently dropping the conversion
		 * attribution this arm exists to measure.  Raw pool stays
		 * the fallback on any gate miss / empty resolver / derive
		 * bail.
		 *
		 * Per-pull inject counters (gate_passed, live_injected,
		 * live_injected_by_kind) are NOT bumped inside the helper:
		 * deferring them to the accept-gated commit point below
		 * keeps a hint the caller's accept range subsequently
		 * rejects from contaminating the denominator. */
		if (allow_hyp_inject) {
			unsigned long derived;

			if (cmp_hyp_try_live_inject(nr, do32, picked_cmp_ip,
						    picked_size, arg_idx,
						    callsite,
						    &derived,
						    &inject_kind,
						    &inject_gate_fired)) {
				*out = derived;
				stash_value = derived;
				hyp_injected = true;
			}
		}
		if (!hyp_injected)
			*out = cmp_hint_apply_transform(picked_value, use, old);

		/* Caller accept-range gate.  Miss-exit: NO consume-age
		 * bump, NO returned counters, NO gate_passed /
		 * live_injected denominator, NO stash, NO would_pick --
		 * the value never reached the consumer.  Without this gate
		 * a derived value the caller subsequently rejects (today
		 * ARG_RANGE; same shape for any future typed-safe consumer
		 * with a hard bound) was credited and counted as
		 * cmp_hyp_live_injected (+ stash-eligible for
		 * cmp_hyp_pc_wins) even though it never reached the
		 * kernel, biasing both arm-verdict numerator and
		 * denominator. */
		if (accept != NULL &&
		    (*out < accept->lo || *out > accept->hi)) {
			/* Additive reason-counter for the LIVE inject path:
			 * only bump when the rejected value came from the
			 * typed hypothesis (hyp_injected), so the per-reason
			 * partition matches the existing accept-gated denom
			 * (a raw-pool value getting accept-rejected belongs
			 * to a different cohort and is not counted here). */
			if (hyp_injected && kcov_shm != NULL)
				__atomic_fetch_add(
					&kcov_shm->cmp_hyp_live_inject_reason[CMP_HYP_LIVE_INJECT_REASON_ACCEPT_REJECT],
					1UL, __ATOMIC_RELAXED);
			return false;
		}

		if (kcov_shm != NULL) {
			__atomic_fetch_add(&kcov_shm->cmp_hint_durable_consumed_age[bucket],
					   1UL, __ATOMIC_RELAXED);

			/* Inject-arm denominator + per-kind partition,
			 * deferred from cmp_hyp_try_live_inject() to here so
			 * an accept-rejected derived value does not
			 * contaminate the counters.  gate_passed counts
			 * "dice gate fired AND value reached the consumer";
			 * live_injected counts "gate fired AND derive
			 * succeeded AND value reached the consumer".  The
			 * gate_passed - live_injected delta keeps the
			 * "gate fired but the typed store had nothing"
			 * observability the kcov_shm doc describes. */
			if (inject_gate_fired)
				__atomic_fetch_add(&kcov_shm->cmp_hyp_live_inject_gate_passed,
						   1UL, __ATOMIC_RELAXED);
			if (hyp_injected) {
				__atomic_fetch_add(&kcov_shm->cmp_hyp_live_injected,
						   1UL, __ATOMIC_RELAXED);
				__atomic_fetch_add(
					&kcov_shm->cmp_hyp_live_injected_by_kind[inject_kind],
					1UL, __ATOMIC_RELAXED);
				/* Placement-proof fill-slot counter.
				 * Sibling of reexec_attribution_slot_hist
				 * (which reports the arg slot the kernel
				 * CMP fired ON); this reports the arg slot
				 * the typed inject actually LANDED IN.
				 * arg_idx is 1-based (argnum); convert to
				 * the 0-based histogram index and gate on
				 * the bound so a non-typed caller
				 * (arg_idx == 0) or a stray out-of-range
				 * value is harmlessly dropped without
				 * indexing off the array.  Sits inside
				 * the accept-gated commit block so an
				 * accept-rejected derived value cannot
				 * contaminate the fill distribution. */
				if (arg_idx >= 1 &&
				    arg_idx <= CMP_REDQUEEN_SLOT_HIST_NR)
					__atomic_fetch_add(
						&kcov_shm->reexec_pending_hist.typed_inject_fill_slot_hist[arg_idx - 1],
						1UL, __ATOMIC_RELAXED);
			}

			/* Mirror of the attempts ring path above: both the
			 * scalar and per-nr returned counters drain into
			 * parent_stats via the per-child stats_ring. */
			{
				struct childdata *return_child = this_child();

				if (return_child != NULL) {
					(void) stats_ring_enqueue(return_child->stats_ring,
								  STATS_FIELD_CMP_HINTS_TRY_GET_RETURNED,
								  0, 1);
					/* per-nr partition of the producer-side
					 * pool-hit counter.  Same in-bounds guard
					 * reasoning as the attempts bump above. */
					(void) stats_ring_enqueue(return_child->stats_ring,
								  STATS_FIELD_PER_SYSCALL_CMP_RETURNED,
								  (uint16_t)nr, 1);
					/* Typed-inject partition of the per-nr
					 * pool-hit counter above: only bumped when
					 * the raw pool value was replaced by a
					 * typed hypothesis-store derive.  Same
					 * accept-gated commit point as the scalar
					 * cmp_hyp_live_injected bump; nr is already
					 * pinned < MAX_NR_SYSCALL by
					 * cmp_hints_try_get_ex_common.  Lets a
					 * coverage consumer isolate raw vs typed
					 * arm yield per syscall, which
					 * per_syscall_cmp_returned (raw + typed
					 * conflated) cannot answer. */
					if (hyp_injected)
						(void) stats_ring_enqueue(return_child->stats_ring,
									  STATS_FIELD_PER_SYSCALL_CMP_HYP_LIVE_INJECTED,
									  (uint16_t)nr, 1);
				}
			}
		}

		/* arg_idx is carried on the stash but unread by the per-
		 * syscall pool credit path (which keys on cmp_ip/value/size);
		 * only the field-scoped credit lane consumes it, so a per-
		 * syscall stash entry passing arg_idx == 0 is fine. */
		cmp_hints_stash_consumed(nr, do32, CMP_HINT_POOL_PER_SYSCALL,
					 callsite,
					 picked_cmp_ip, stash_value, picked_size, use,
					 arg_idx, 0, NULL,
					 false, bucket, hyp_injected, false);
	}
	cmp_hyp_would_pick(nr, do32, picked_cmp_ip, picked_size, picked_value);
	if (out_size != NULL)
		*out_size = picked_size;
	return true;
}

/* enum cmp_tier_result moved to include/cmp_hints-internal.h. */

static enum cmp_tier_result cmp_try_get_recent_tier(unsigned int nr, bool do32,
						    enum cmp_hint_use use,
						    unsigned long old,
						    bool allow_hyp_inject,
						    const struct cmp_accept_range *accept,
						    unsigned int arg_idx,
						    enum cmp_hint_callsite callsite,
						    unsigned long *out,
						    unsigned int *out_size)
{
	/*
	 * Recent-pool sampling tier.
	 *
	 * The recent ring carries fresh constants the durable pool's
	 * saturated LRU floor would have dropped.  During a
	 * CMP_RISING_PC_FLAT plateau -- when the
	 * cmp_hints_save_reject_cap dominance signal says the durable
	 * pool is the bottleneck -- sample the recent ring first; this
	 * gives the consumer a window onto the late-run constant
	 * stream without competing with the durable pool's selection
	 * on the off-plateau steady state.  Typed-inject callsites are
	 * exempted (allow_hyp_inject) so they reach the inject arm on
	 * the durable path instead.
	 *
	 * cmp_recent_would_pick / cmp_recent_would_miss continue to
	 * bump on every plateau call so the recent-tier opportunity
	 * rate stays observable alongside the served rate.
	 * cmp_recent_live_picks bumps on a return actually served from
	 * the recent ring.
	 *
	 * Lockless reads with ACQUIRE on count + RELAXED on entries[]
	 * mirror the durable pool's lockless reader contract: torn
	 * cross-field reads are tolerated (hints are advisory), and a
	 * concurrent ring writer can only ever produce the pre- or
	 * post-overwrite triplet -- both lived in the ring.
	 */
	if (shm != NULL &&
	    __atomic_load_n(&shm->plateau_current_hypothesis,
			    __ATOMIC_RELAXED) ==
	    (int)PLATEAU_HYPOTHESIS_CMP_RISING_PC_FLAT) {
		struct cmp_recent_pool *rp =
			&cmp_hints_shm->recent_pools[nr][do32 ? 1 : 0];
		unsigned int rcount =
			__atomic_load_n(&rp->count, __ATOMIC_ACQUIRE);

		if (rcount > 0 && rcount <= CMP_RECENT_PER_SYSCALL) {
			if (kcov_shm != NULL)
				__atomic_fetch_add(&kcov_shm->cmp_recent_would_pick,
						   1UL, __ATOMIC_RELAXED);
			/* Typed-inject callsites must reach the inject arm on
			 * the durable path, not be shadowed by the recent-first
			 * early-return.
			 */
			if (!allow_hyp_inject) {
				struct cmp_recent_entry *re =
					&rp->entries[rnd_modulo_u32(rcount)];
				unsigned long re_value = re->value;
				unsigned long re_cmp_ip = re->cmp_ip;
				uint32_t re_size = re->size;

				*out = cmp_hint_apply_transform(re_value,
								use, old);

				/* Caller accept-range gate.  Miss-exit:
				 * NO live_picks bump, NO stash, NO
				 * would_pick -- the value never reached
				 * the consumer so it must not show up
				 * in any per-pull counter or in the
				 * SHADOW would-pick resolver, which
				 * would otherwise re-credit a value the
				 * caller threw away. */
				if (accept != NULL &&
				    (*out < accept->lo ||
				     *out > accept->hi))
					return CMP_TIER_REJECTED;

				if (kcov_shm != NULL)
					__atomic_fetch_add(&kcov_shm->cmp_recent_live_picks,
							   1UL, __ATOMIC_RELAXED);

				/* Stash the recent-served pull under the
				 * per-syscall pool-kind: the feedback drain's
				 * per-entry credit path re-finds by (cmp_ip,
				 * value, size) in the durable pool and will
				 * harmlessly fail to find the recent-only
				 * tuple, while the flat cmp_hint_wins /
				 * cmp_hint_misses counters still bump -- the
				 * follow-up commit wires the recent-pool
				 * conversion credit + promotion.
				 *
				 * served_from_recent=1, age_bucket=0: the
				 * recent ring has no per-entry LRU stamp; its
				 * freshness story IS the tier itself.  The
				 * credit drain partitions PC-wins by tier so a
				 * recent-served stash entry rolls up under
				 * cmp_hint_tier_recent_wins / _misses; the
				 * age-bucketed durable counters skip it. */
				cmp_hints_stash_consumed(nr, do32,
							 CMP_HINT_POOL_PER_SYSCALL,
							 callsite,
							 re_cmp_ip, re_value,
							 re_size, use,
							 arg_idx, 0, NULL,
							 true, 0, false, false);
				cmp_hyp_would_pick(nr, do32, re_cmp_ip,
						   re_size, re_value);
				if (out_size != NULL)
					*out_size = re_size;
				return CMP_TIER_SERVED;
			}
		} else if (kcov_shm != NULL) {
			__atomic_fetch_add(&kcov_shm->cmp_recent_would_miss,
					   1UL, __ATOMIC_RELAXED);
		}
	}

	return CMP_TIER_MISS;
}

/*
 * Common entrypoint that both cmp_hints_try_get_ex() (public width-
 * discarding surface) and cmp_hints_try_get_sized() (width-preserving
 * surface for consumers that need to splat at the recorded operand
 * width) route through.  out_size == NULL matches the historical
 * behaviour: the recorded operand width is discarded on the served
 * path; callers that pass a non-NULL out_size receive the pool
 * entry's uint32_t size (1, 2, 4, or 8) on a true return.  The
 * chaos-suppressed / accept-rejected / empty-pool fall-through paths
 * never touch out_size, so a caller can leave its pre-call scratch
 * uninitialised and only trust *out_size on a true return.
 */
static bool cmp_hints_try_get_ex_common(unsigned int nr, bool do32,
					enum cmp_hint_use use,
					unsigned long old,
					bool allow_hyp_inject,
					const struct cmp_accept_range *accept,
					unsigned int arg_idx,
					enum cmp_hint_callsite callsite,
					unsigned long *out,
					unsigned int *out_size)
{
	if (cmp_hints_shm == NULL || nr >= MAX_NR_SYSCALL)
		return false;

	if (kcov_shm != NULL) {
		/* Scalar attempts counter now lives in parent_stats and is
		 * fed via the per-child stats_ring -- the kernel cannot
		 * scribble it through any fuzzed syscall arg because the
		 * authoritative copy is in MAP_PRIVATE parent memory.
		 * Direct +1 enqueue (no local staging like the kcov
		 * batched counters): cmp_hints_try_get fires at consumer
		 * cadence, well below the SPSC budget.  Ring-full drops
		 * fold into ring_overflow_total. */
		struct childdata *attempt_child = this_child();

		if (attempt_child != NULL) {
			(void) stats_ring_enqueue(attempt_child->stats_ring,
						  STATS_FIELD_CMP_HINTS_TRY_GET_ATTEMPTS,
						  0, 1);
			/* per-nr partition of the consumer-demand counter,
			 * drained into parent_stats.per_syscall_cmp_attempts[].
			 * The shm/nr guard above already pinned nr <
			 * MAX_NR_SYSCALL so aux is in-bounds at the drain. */
			(void) stats_ring_enqueue(attempt_child->stats_ring,
						  STATS_FIELD_PER_SYSCALL_CMP_ATTEMPTS,
						  (uint16_t)nr, 1);
		}
	}

	/* Chaos-mode gate.  Placed after the attempts bump so the consumer
	 * demand series stays comparable across chaos and non-chaos
	 * windows -- suppressed pulls remain visible as the
	 * attempts/returned gap, with cmp_hints_chaos_suppressed
	 * accounting for the difference.  Before the pool snapshot so the
	 * suppressed path skips the lockless load entirely. */
	if (kcov_shm != NULL &&
	    __atomic_load_n(&kcov_shm->hints_flat.cmp_hints_chaos_active,
			    __ATOMIC_RELAXED)) {
		__atomic_fetch_add(&kcov_shm->hints_flat.cmp_hints_chaos_suppressed,
				   1UL, __ATOMIC_RELAXED);
		return false;
	}

	switch (cmp_try_get_recent_tier(nr, do32, use, old,
					allow_hyp_inject, accept,
					arg_idx, callsite, out,
					out_size)) {
	case CMP_TIER_SERVED:
		return true;
	case CMP_TIER_REJECTED:
		return false;
	case CMP_TIER_MISS:
		break;
	}

	return cmp_try_get_durable_tier(nr, do32, use, old,
				       allow_hyp_inject, accept,
				       arg_idx, callsite, out,
				       out_size);
}

bool cmp_hints_try_get_ex(unsigned int nr, bool do32, enum cmp_hint_use use,
			  unsigned long old, bool allow_hyp_inject,
			  const struct cmp_accept_range *accept,
			  unsigned int arg_idx,
			  enum cmp_hint_callsite callsite,
			  unsigned long *out)
{
	return cmp_hints_try_get_ex_common(nr, do32, use, old,
					   allow_hyp_inject, accept,
					   arg_idx, callsite, out,
					   NULL);
}

bool cmp_hints_try_get(unsigned int nr, bool do32,
		       enum cmp_hint_callsite callsite,
		       unsigned long *out)
{
	/* arg_idx == 0: back-compat wrapper keeps allow_hyp_inject == false,
	 * so hyp_injected can never fire and the fill-slot counter is never
	 * bumped from this path.  Passing 0 is safe by construction. */
	return cmp_hints_try_get_ex(nr, do32, CMP_HINT_BOUNDARY, 0, false,
				    NULL, 0, callsite, out);
}

/*
 * Width-preserving pull.  Same policy as cmp_hints_try_get() (BOUNDARY
 * rotation, no typed-hypothesis inject, no accept range) but on a
 * successful return also writes the pool entry's recorded operand
 * width to *out_size in {1, 2, 4, 8}.  The blob mutator's CMPDICT
 * learned arm splats the returned constant at exactly that width so
 * an on-disk / on-wire byte sequence learned at a 2-byte cmp is not
 * blindly re-emitted as an 8-byte splat that surrounds the constant
 * with 6 bytes of garbage the kernel's downstream compare then
 * rejects.  On a false return *out_size is untouched.
 */
bool cmp_hints_try_get_sized(unsigned int nr, bool do32,
			     enum cmp_hint_callsite callsite,
			     unsigned long *out, unsigned int *out_size)
{
	/* arg_idx == 0: sized wrapper is a non-typed CMPDICT byte-splat
	 * consumer (no argnum context, no typed inject); same safe-by-
	 * construction reasoning as the cmp_hints_try_get() wrapper. */
	return cmp_hints_try_get_ex_common(nr, do32, CMP_HINT_BOUNDARY, 0,
					   false, NULL, 0, callsite,
					   out, out_size);
}
