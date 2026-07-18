#ifndef _TRINITY_STATS_SUBSYS_MAPS_H
#define _TRINITY_STATS_SUBSYS_MAPS_H

/*
 * mmap-pool pick/reject accounting -- get_map_handle() /
 * get_map_with_prot() / common_set_mmap_ptr_len() observability.
 *
 * Bespoke (non-category) RAW group.  All bumps RELAXED on shm->stats
 * from mm/maps.c (same writer set, same atomic convention, same
 * shm->stats home), so no new hot cross-child synchronisation class is
 * introduced.  The surrounding struct stats_s composes an instance of
 * struct maps_stats as its "maps" member.
 */
struct maps_stats {
	/* Bumped by get_map_handle() in mm/maps.c when the 1000-iteration
	 * random-pool draw loop exhausts its retry budget without finding a
	 * usable map handle.  Most commonly fires because OBJ_LOCAL OBJ_MMAP_*
	 * pools are sparse or empty (TESTFILE in particular has no producer in
	 * tree).  Not a corruption signal -- post-Stage-5 the OBJ_LOCAL pools
	 * live in private heap with no concurrent destroyer, so there is no
	 * UAF window for the retry loop to defend against. */
	unsigned long pool_draw_exhausted;

	/* Per-rejection-reason sub-attributions of maps_pool_draw_exhausted.
	 * The 1000-iteration draw loop in get_map_handle() has five distinct
	 * `continue;` paths; each of the five counters below is bumped once
	 * per iteration that exits via the corresponding clause.  Summed,
	 * they bound 1000 * maps_pool_draw_exhausted + 999 * successful
	 * get_map_handle() calls.  Pure attribution -- no behaviour change. */

	/* get_random_object() returned NULL.  Predicted dominant reason
	 * because type is picked uniformly from {ANON, FILE, TESTFILE} but
	 * only ANON has a well-populated OBJ_LOCAL pool post-fork, so ~2/3
	 * of draws hit a guaranteed-empty or near-empty pool. */
	unsigned long reject_pool_empty;

	/* obj pointer fell outside the heap band [0x10000, 0x800000000000).
	 * A non-zero rate-of-change here is a real corruption signal
	 * (stale or stomped slot pointer leaking out of the OBJ_MMAP pool). */
	unsigned long reject_bogus_obj_ptr;

	/* scope == OBJ_LOCAL and alloc_track_lookup(obj) miss.  Bumped on
	 * the validator-LRU false-positive class: alloc_track[] is a 256-
	 * slot LRU; OBJ_MMAP_ANON pool entries can rotate out under fd-
	 * pressure cascades, causing legitimate live entries to be
	 * false-rejected.  See [[stomped-slot-regression-bisect-20260529]]. */
	unsigned long reject_alloc_track_miss;

	/* obj->map.size == 0.  Benign noise from pre-clamp mmap_fd pool
	 * entries left over from earlier startups; expected low and
	 * monotonic. */
	unsigned long reject_size_zero;

	/* obj->map.size > GB(4UL).  Like maps_reject_bogus_obj_ptr, a
	 * non-zero rate-of-change is a real corruption signal (the map
	 * struct itself was stomped after the obj pointer survived the
	 * heap-band guard). */
	unsigned long reject_size_too_large;

	/* Per-pool-type sub-attributions of [[maps_reject_alloc_track_miss]].
	 * The aggregate above is bumped per false-reject regardless of which
	 * OBJ_MMAP_* pool the iteration sampled, so a 153M-class miss tally
	 * cannot be attributed to one pool vs. another -- a 256-slot LRU
	 * rotating out OBJ_MMAP_ANON entries under fd-pressure cascades looks
	 * identical at the aggregate to a TESTFILE-only seeding bug.  These
	 * three counters split the same reject by the pool the draw landed on
	 * this iteration (the `type` local at the bump site is the only
	 * contextual axis available there without new plumbing; `scope` is
	 * gated to OBJ_LOCAL by the surrounding if-condition so splitting on
	 * it would be inert).  Summed, they equal maps_reject_alloc_track_miss
	 * minus any iteration where `type` is somehow neither ANON nor FILE
	 * nor TESTFILE (defensively bounded; should be zero in practice).
	 * Pure attribution -- no behaviour change. */
	unsigned long reject_alloc_track_miss_anon;
	unsigned long reject_alloc_track_miss_file;
	unsigned long reject_alloc_track_miss_testfile;

	/* Map subsystem scan-cost / health observability.
	 * Pure attribution; no behaviour change.  All bumps RELAXED on
	 * shm->stats from get_map_handle / get_map_with_prot /
	 * common_set_mmap_ptr_len (mm/maps.c) — mirrors the existing
	 * maps_reject_* class above (same writer set, same atomic
	 * convention, same shm->stats home), so no new hot cross-child
	 * synchronisation class is introduced.
	 *
	 * The planned side-index rows (O(1) map-region resolution, a
	 * per-prot map index) should only be built once the rate-of-
	 * change these counters surface in periodic_counter_rates_dump
	 * proves the cost is real -- do NOT build the side indexes until
	 * the map-type-resolution scan-length / get_map_with_prot
	 * prot-reject rates here prove the linear scan actually costs. */

	/* Per-type sub-attribution of get_map_handle()'s pool pick.
	 * Bumped once per successful pick at the &obj->map publish
	 * site, indexed by the OBJ_MMAP_* type selected for the
	 * winning iteration.  Sum across the three equals
	 * maps_pick_successes below.  The dispatch mix lets
	 * pool-popmask balance be cross-checked against
	 * post-pop-mask pool occupancy. */
	unsigned long pool_chosen_anon;
	unsigned long pool_chosen_file;
	unsigned long pool_chosen_testfile;

	/* Per-type sub-attribution of [[maps_reject_pool_empty]]:
	 * the aggregate above is bumped per get_random_object()==NULL
	 * iteration without recording which OBJ_MMAP_* pool returned
	 * NULL.  These three split the same reject by the `type`
	 * local at the bump site.  Summed they equal
	 * maps_reject_pool_empty.  The MMAP_TESTFILE share is the
	 * specific signal of interest (only ANON has a
	 * well-populated OBJ_LOCAL pool post-fork). */
	unsigned long reject_pool_empty_anon;
	unsigned long reject_pool_empty_file;
	unsigned long reject_pool_empty_testfile;

	/* Per-required-prot-mask sub-attribution of
	 * get_map_with_prot() retries.  Indexed by required_prot &
	 * 0x7 (PROT_READ|WRITE|EXEC bits — PROT_NONE collapses to
	 * index 0, PROT_SEM is out of the low-three-bit window and
	 * folded into its RWX overlap).  Bumped once per
	 * (m->prot & required_prot) != required_prot iteration.
	 * The hottest bucket identifies the prot combination paying
	 * the highest rejection-sample cost — the input a
	 * per-prot map index would optimise. */
	unsigned long prot_reject_by_mask[8];

	/* get_map_handle() pick-cost accounting.  Bumped once per
	 * successful pick, with `attempts_sum` carrying the
	 * 1-indexed loop iteration that landed the pick.  The
	 * ratio maps_pick_attempts_sum / maps_pick_successes is
	 * the realised average attempts-per-successful-pick the
	 * 1000-iter budget exists to amortise — a value
	 * approaching the budget says the loop is dominated by
	 * the reject path and the side-index work is justified. */
	unsigned long pick_attempts_sum;
	unsigned long pick_successes;
	/* Same pair for the get_map_with_prot() outer retry loop,
	 * which wraps get_map_handle() with its own up-to-1000-
	 * iter prot-filter retry.  Tracked separately because the
	 * prot filter compounds with the inner pool-pick reject
	 * to multiply iteration cost; the with_prot ratio is the
	 * one a per-prot map index would directly improve. */
	unsigned long pick_with_prot_attempts_sum;
	unsigned long pick_with_prot_successes;

	/* SAMPLED shadow telemetry over get_map_handle()'s
	 * pool-pick reject loop.  A per-child call counter
	 * (see mm/maps.c) gates 1-in-N calls to bracket the
	 * for-loop body with rdtsc; on sampled calls the
	 * total cycles across pick_mmap_pool_type +
	 * get_random_object + obj_ptr_in_user_va_band +
	 * obj_alloc_track_check + map_size_in_range reject
	 * chain are added to _sum and _count is bumped once.
	 * cycles_sampled_sum / cycles_sampled_count is the
	 * mean cost of one pick call; multiplied by the
	 * attempts/success ratio it yields cycles-per-
	 * successful-pick -- the direct input a per-pool
	 * side-index gate would trade off against.  Pure
	 * additive: the gate never consumes RNG and never
	 * influences arg generation, so the emitted syscall
	 * arg stream is byte-identical to the untelemetered
	 * build. */
	unsigned long pick_cycles_sampled_sum;
	unsigned long pick_cycles_sampled_count;

	/* Log2 histogram of the loop index i at exit from
	 * get_map_handle()'s pool-pick retry loop.  Bumped on
	 * both the success path (i == the 0-indexed iteration
	 * that landed the pick) and the exhaustion path (i ==
	 * final loop counter after all_empty break or the
	 * full 1000-iter budget).  Shape mirrors
	 * fd_live_remove_scan_histogram exactly: log2 bucket
	 * with a match-on-first-slot floor and a saturating
	 * tail slot, RELAXED per-call adds.  The bucket
	 * distribution answers "how deep does the reject
	 * chain typically run before yielding a hit" -- a
	 * distribution biased toward the tail slot is the
	 * signal a per-pool side-index would eliminate. */
	unsigned long pick_scan_histogram[8];

	/* common_set_mmap_ptr_len() type-resolution scan accounting.
	 * The function walks the three OBJ_LOCAL OBJ_MMAP_* pools
	 * end-to-end looking for the pointer-identity match for
	 * the caller-supplied `map`; each pool walks all of
	 * head->array.  Bumped per call into the resolution arm
	 * (out_type != NULL): `calls` is the denominator,
	 * `scan_length_sum` is the cumulative objects visited
	 * across all three pools, `hits` is the subset where the
	 * walk resolved (out_type != OBJ_NONE).  scan_length_sum /
	 * calls = avg objects walked per resolution — the direct
	 * measurement the O(1) map-region resolution is gated on. */
	unsigned long type_resolution_calls;
	unsigned long type_resolution_scan_length_sum;
	unsigned long type_resolution_hits;
};

#endif	/* _TRINITY_STATS_SUBSYS_MAPS_H */
