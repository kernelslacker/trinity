#ifndef _TRINITY_STATS_SUBSYS_ARG_H
#define _TRINITY_STATS_SUBSYS_ARG_H

/*
 * arg-generation observability -- per-arg ownership metadata census +
 * object-size-relative ARG_LEN draw accounting.
 *
 * Bespoke (non-category) RAW group.  All bumps RELAXED on shm->stats;
 * diagnostic-only, no live decision consumes any of these counters.
 * The surrounding struct stats_s composes an instance of struct
 * arg_stats as its "arg" member.
 */
struct arg_stats {
	/* SHADOW per-arg ownership-metadata sidecar census, bumped from
	 * arg_meta_init() once per dispatch over the address-family slots
	 * (ARG_ADDRESS / ARG_NON_NULL_ADDRESS / ARG_RANGE) the seed pass
	 * touches.  Telemetry only: the sidecar is written + counted here
	 * but no live decision (inject, schedule, sanitise, scrub) reads
	 * dir/owner/flags.
	 *
	 *  meta_addr_with_meta
	 *      Address-family slot whose seeded sidecar carries a non-default
	 *      classification after the per-argtype seed pass (dir != NONE,
	 *      owner != NONE, or any flag bit set).  Seeded purely from
	 *      argtype today, so the baseline for bare ARG_ADDRESS is zero
	 *      until per-generator coverage starts populating dir/owner.
	 *  meta_addr_without_meta
	 *      Address-family slot still at the zero-init sidecar state
	 *      after the seed pass.  The shadow proof for this row: an
	 *      ARG_ADDRESS slot has no per-slot ownership metadata today.
	 *  meta_argtype_stale
	 *      Bumped when arg_meta_init() observes a slot's stored
	 *      generation that does not match the dispatch sequence the
	 *      previous init stamped (a stale sidecar from a missed reset
	 *      path, or a wholesale stomp of the rec).  Foundation for the
	 *      future recorded-vs-actual mismatch counter once a real
	 *      consumer compares the sidecar to live state.
	 *
	 * RELAXED add-fetch -- diagnostic, not an event log. */
	unsigned long meta_addr_with_meta;
	unsigned long meta_addr_without_meta;
	unsigned long meta_argtype_stale;

	/* SHADOW contradiction census between blanket_address_scrub()'s
	 * coverage (entry->address_scrub_mask) and the per-slot sidecar
	 * direction seeded by arg_meta_init().  Walked once per dispatch
	 * from the tail of blanket_address_scrub() over the
	 * entry->num_args slots; the live scrub walk above is byte-
	 * unchanged.
	 *
	 *  meta_scrub_would_destroy_in
	 *      Slot bit set in entry->address_scrub_mask (the blanket
	 *      walked and overwrote it via avoid_shared_buffer_out) AND
	 *      sidecar dir is ARG_DIR_IN or ARG_DIR_INOUT.  Each bump is
	 *      one curated input slot a metadata-aware scrub would have
	 *      to skip to avoid clobbering it.  Zero today because the
	 *      address-family argtypes in the scrub mask all seed dir =
	 *      NONE; bumps appear as per-generator coverage starts
	 *      classifying those slots.
	 *  meta_scrub_would_preserve_out
	 *      Slot bit clear in entry->address_scrub_mask (the blanket
	 *      skipped it) AND sidecar dir is ARG_DIR_OUT.  Each bump is
	 *      one OUT slot the blanket leaves untouched today because
	 *      the argtype sits outside the default_address_scrub domain.
	 *
	 * RELAXED add-fetch -- diagnostic, not an event log. */
	unsigned long meta_scrub_would_destroy_in;
	unsigned long meta_scrub_would_preserve_out;

	/* Object-size-relative ARG_LEN draw observability.  All counters
	 * stay at zero while --arg-len-semantics is off (the default): the
	 * OFF arm in gen_arg_len() exits before any bump runs.  Under ON the
	 * counters expose how often the new arm fires vs falls back, and
	 * which boundary class the relative draw picks.
	 *
	 * Aggregates:
	 *
	 *  len_semantics_draws
	 *      Total ARG_LEN draws that entered the semantics path
	 *      (mode != OFF).  Denominator for the other rates.
	 *
	 *  len_objrelative_used
	 *      Subset of _draws where get_len_relative() returned an
	 *      object-relative boundary value (one of the per-class
	 *      arms below fired).
	 *
	 *  len_objrelative_nosize
	 *      Subset of _draws where gen_arg_len() fell back to the
	 *      legacy size-blind get_len() path -- no immediately
	 *      preceding ARG_ADDRESS / ARG_NON_NULL_ADDRESS slot, the
	 *      address was NULL, or the address resolved to no tracked
	 *      writable region.  High share here means the adjacency rule
	 *      is rejecting most candidate sites for this workload.
	 *
	 *  len_objrel_blend_getlen
	 *      Subset of get_len_relative() calls that took the half-
	 *      time RAND_BOOL blend arm and deferred to get_len() (clamped
	 *      to objsize).  Identity:
	 *        arg_len_objrelative_used + arg_len_objrel_blend_getlen
	 *        == calls to get_len_relative()
	 *        == arg_len_semantics_draws - arg_len_objrelative_nosize
	 *
	 * Per-class breakdown of the eight object-relative arms drawn by
	 * get_len_relative().  Sum equals arg_len_objrelative_used.  The
	 * pagesize_* arms collapse to objsize when the writable region is
	 * smaller than the page-size-derived value; the collapsed draws
	 * still bump the pagesize_* counter for the arm that was rolled
	 * (the per-class counters track the RNG arm, not the final value
	 * after clamping). */
	unsigned long len_semantics_draws;
	unsigned long len_objrelative_used;
	unsigned long len_objrelative_nosize;
	unsigned long len_objrel_blend_getlen;
	unsigned long len_objrel_zero;
	unsigned long len_objrel_one;
	unsigned long len_objrel_objsize;
	unsigned long len_objrel_objsize_minus_1;
	unsigned long len_objrel_objsize_half;
	unsigned long len_objrel_pagesize;
	unsigned long len_objrel_pagesize_plus_1;
	unsigned long len_objrel_pagesize_minus_1;
};

#endif	/* _TRINITY_STATS_SUBSYS_ARG_H */
