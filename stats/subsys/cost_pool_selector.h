#ifndef _TRINITY_STATS_SUBSYS_COST_POOL_SELECTOR_H
#define _TRINITY_STATS_SUBSYS_COST_POOL_SELECTOR_H

/*
 * Cost-pool one-shot selector observer counters (gated by
 * cost_pool_selector_mode != OFF for the shadow_ pair; the live_
 * pair bumps unconditionally so the analytical vs actual comparison
 * is available on every run).  See enum cost_pool_selector_mode in
 * include/strategy.h for the shadow/live contract and the cost-pool-
 * oneshot-selector spec section 4.1 for the closed-form identity the
 * shadow rows accumulate.
 *
 *  shadow_picks               : one bump per HEURISTIC / RANDOM arm
 *    entry into set_syscall_nr_* under SHADOW_ONLY/COMBINED, after
 *    arch table chosen and before retry-loop's rnd_modulo_u32 draw.
 *    Bumps exactly once per pick call regardless of retries.
 *  shadow_expensive_ppm_sum   : cumulative sum of per-pick analytical
 *    expected expensive-pool fraction, scaled to parts-per-million.
 *    Per-pick summand = 1e6 * n_exp / (n_cheap * R + n_exp) with
 *    R = EXPENSIVE_ADAPTIVE_FLOOR = 1000.  Analytical fraction over
 *    any window = ppm_sum / (shadow_picks * 1e6); by 4.1 identity
 *    should match live_expensive_picks / (live_* sum).
 *  live_cheap_picks           : bump per successful pick whose
 *    finalised syscall is CHEAP.  Placed pre-srec_publish_begin so
 *    downstream reject gates don't double-count.
 *  live_expensive_picks       : EXPENSIVE sibling of live_cheap_picks.
 *  predraw_cheap_picks        : one bump per HEURISTIC/RANDOM draw
 *    whose candidate PASSED expensive_accept but not yet validate /
 *    anti_prior / cred-throttle -- the exact population the shadow
 *    closed-form models.
 *  predraw_expensive_picks    : EXPENSIVE sibling.
 *
 * Section 4.1 identity: shadow_expensive_ppm_sum / (shadow_picks * 1e6)
 * should match predraw_expensive / (predraw_expensive + predraw_cheap)
 * within Monte-Carlo noise.  The live_ pair remains "what actually
 * executes" (post all gates); typically diverges from shadow because
 * anti_prior selectively enriches rare/expensive syscalls.
 *
 * Observability only: the shadow observer never returns a value,
 * never gates any accept, never consumes any RNG.  cost_pool_
 * selector_mode == COMBINED in this build behaves identically to
 * SHADOW_ONLY -- the COMBINED coin-then-draw wire-up lands in a
 * follow-up commit.
 *
 * The surrounding struct stats_s composes an instance of struct
 * cost_pool_selector_stats as its "cost_pool_selector" member.
 */
struct cost_pool_selector_stats {
	unsigned long shadow_picks;
	unsigned long shadow_expensive_ppm_sum;
	unsigned long live_cheap_picks;
	unsigned long live_expensive_picks;
	unsigned long predraw_cheap_picks;
	unsigned long predraw_expensive_picks;
};

#endif	/* _TRINITY_STATS_SUBSYS_COST_POOL_SELECTOR_H */
