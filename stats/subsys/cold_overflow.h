#ifndef _TRINITY_STATS_SUBSYS_COLD_OVERFLOW_H
#define _TRINITY_STATS_SUBSYS_COLD_OVERFLOW_H

/* Shadow cold-overflow would-save accounting (measurement only --
 * no fuzzer behaviour change).  Hypothesis: under a CMP_RISING_
 * PC_FLAT plateau the per-syscall minicorpus has collapsed to a
 * small fraction of the active syscall set (~51/383 in the
 * baseline run), so the cold-but-CMP-active tail produces a long
 * trickle of would-save events that the single durable lane has no
 * room to admit.  This block counts the demand for a future
 * "overflow" lane keyed on (cold-or-corpus-absent AND nonzero
 * CMP signal) BEFORE any second save target is wired up.  No
 * selection / admission / scoring / corpus path consumes any
 * field here -- the only effect of these writes is the counter
 * values rendered by the shutdown stats dump.  The existing live save
 * call at the producer site (minicorpus_save_with_reason in
 * random-syscall.c) is untouched: its arguments and branch shape are
 * byte-identical to the pre-row baseline, and the shadow block
 * fires strictly AFTER it on the same gated arm.
 *
 * Predicate composition at the bump site, all evaluated AFTER the
 * existing found_something / entry->sanitise == NULL save gate so
 * the population is the same population that already passes
 * through minicorpus_save_with_reason:
 *   plateau == CMP_RISING_PC_FLAT
 *     (RELAXED load of shm->plateau_current_hypothesis, the
 *     same key the cmp-recent-first arm and the live-inject path
 *     in cmp_hints.c use)
 *   new_cmp > 0
 *     (nonzero CMP-bloom novelty -- the "transition" signal in
 *     the row description; CMP-mode children never set
 *     new_edges so the new_edges-only sub-population never bumps
 *     either subset, by construction)
 *   cold OR corpus-absent
 *     cold     := kcov_syscall_cold_skip_pct(nr) > 0
 *                 (the existing cold-skip classifier; > 0 iff
 *                 the syscall has not earned a new edge within
 *                 KCOV_COLD_THRESHOLD calls)
 *     absent   := minicorpus_shm->rings[nr].count == 0
 *                 (ACQUIRE-paired with the publishing release
 *                 inside minicorpus_save_with_reason; absent
 *                 means no entry has ever been admitted for nr)
 *
 * Counter shape (mirrors the errno_gradient sibling -- a gate
 * scalar plus two non-disjoint subset scalars; a single bump may
 * bump BOTH subsets when the syscall is both cold and corpus-
 * absent, which is the common case at fleet start-of-day).
 *
 * Both subsets are RELAXED add-fetches and may race with the peer
 * publishing into the same per-nr ring (corpus-absent flips false
 * the instant another child wins a save), so a one-pick over- or
 * under-count of the subsets is tolerated by design.  Live
 * selection is not a consumer.
 *
 * All three counters start at zero on parent boot; warm-start
 * does not persist stats counters. */
struct cold_overflow_stats {
	/* would_save
	 *      Aggregate scalar -- total would-save events that satisfy
	 *      the cold-OR-absent disjunction.  Doubles as the
	 *      STAT_CATEGORY gate so a run that never observed a
	 *      qualifying event emits nothing in the text dump. */
	unsigned long would_save;

	/* would_save_cold
	 *      Subset of would_save: the would-save event satisfied the
	 *      cold side of the disjunction (the syscall had not earned
	 *      a new edge within the cold-skip threshold window at the
	 *      moment the save fired). */
	unsigned long would_save_cold;

	/* would_save_absent
	 *      Subset of would_save: the would-save event satisfied the
	 *      corpus-absent side of the disjunction (the syscall's
	 *      per-nr ring held no admitted entries at the moment the
	 *      save fired).  This is the headline "the single durable
	 *      lane has not yet admitted this syscall at all, yet it is
	 *      producing CMP novelty" signal. */
	unsigned long would_save_absent;
};

#endif /* _TRINITY_STATS_SUBSYS_COLD_OVERFLOW_H */
