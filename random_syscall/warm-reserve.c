/*
 * SHADOW warm-reserve / cold-overflow probes ridden on the same
 * post-collect seam in dispatch_step: account_warm_reserve fires on
 * novelty-quiet PC-mode calls that ran a deep-but-warm trace, and
 * account_cold_overflow_would_save shadows the CMP-triggered cold /
 * corpus-absent tail that a STAGE B overflow save lane would admit.
 *
 * Carved out of strategy-accounting.c; the sibling seams (rotation,
 * remote-adaptive decide, per-syscall edge accounting, fd+group
 * accounting) live in their own TUs under random_syscall/.
 *
 * account_warm_reserve and account_cold_overflow_would_save are
 * cross-cluster private and declared in
 * random_syscall/strategy-accounting-internal.h.
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
#include "strategy-accounting-internal.h"
#include "strategy.h"
#include "syscall.h"
#include "syscall_record.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

/*
 * SHADOW deep-but-warm candidate predicate tunables -- consumed by the
 * post-collect bookkeeping in dispatch_step() that bumps shm->stats.
 * warm_reserve_candidates*.  Static defaults; no runtime knob exists
 * yet because the live STAGE B reserve+replay consumer is not built.
 *
 * DEEP_WARM_PCS_MIN_CALLS
 *     Warmup floor on the running-mean clause: a syscall whose lifetime
 *     invocation count is below this threshold cannot trip the
 *     "per-call PCs >= MULT * mean" check.  Keeps the first handful of
 *     calls on a syscall from all qualifying against their own zero or
 *     near-zero baseline mean.  Sized to the same order of magnitude as
 *     the bandit / remote-adaptive sample floors elsewhere; large
 *     enough to filter cold-start noise, small enough that any syscall
 *     that gets routine traffic clears it inside a single periodic
 *     dump window.
 * DEEP_WARM_PCS_MEAN_MULT
 *     High-side multiplier on the running mean for the per-call PC-
 *     density clause: a call's local_distinct_pcs must reach at least
 *     MULT * mean to qualify.  2 is the "noticeably deeper than this
 *     syscall's own typical trace" cutoff -- aggressive enough to
 *     catch the long-tail expensive calls without flagging every call
 *     that randomly lands above the mean.  Picked over a true quartile
 *     mechanism so the predicate stays cheap (one integer cross-
 *     product, no per-syscall sorted-sample buffer) -- noted as the
 *     STAGE A default in the dispatchable plan.
 * DEEP_WARM_TRACE_NUM / DEEP_WARM_TRACE_DEN
 *     Threshold on the per-call PC trace length as a fraction of the
 *     KCOV_TRACE_SIZE buffer cap: a call's trace_size must reach at
 *     least NUM/DEN of the buffer to qualify under the near-truncation
 *     clause.  9/10 matches the dispatchable plan's 0.9 default; the
 *     ratio is applied as a cross-product to avoid the runtime divide.
 */
#define DEEP_WARM_PCS_MIN_CALLS 16UL
#define DEEP_WARM_PCS_MEAN_MULT 2UL
#define DEEP_WARM_TRACE_NUM 9UL
#define DEEP_WARM_TRACE_DEN 10UL

/* SHADOW "deep but warm" candidate accounting.  Fires only when
 * the call produced no PC-edge novelty AND no CMP-bloom novelty
 * (the union of corpus-save reasons above), yet still executed
 * either:
 *   - a per-call PC walk meaningfully deeper than this syscall's
 *     own lifetime mean local_distinct_pcs (warmup-gated so the
 *     first few calls on a syscall do not compare against their
 *     own zero mean), OR
 *   - a trace that approached the KCOV_TRACE_SIZE buffer cap,
 *     i.e. the kernel ran enough code that the tail of the trace
 *     was at risk of truncation.
 * Gated to the PC-mode path: CMP-mode children do not populate
 * pcres, do not return a local_distinct_pcs / trace_size, and
 * their new_cmp branch already carries its own novelty
 * accounting.  Validator-rejected calls also short-circuit
 * (pcres stays zero, kcov never ran) so the predicate naturally
 * does not fire on them.
 *
 * Both stores are RELAXED -- cumulative diagnostic, no event-
 * ordering consumer.  No live-path code reads either counter; the
 * picker, the per-strategy attribution and the frontier-blend
 * shadow path are byte-identical to the pre-row baseline.  See the
 * warm_reserve_candidates* comment in include/stats.h for the
 * predicate rationale. */
void account_warm_reserve(struct childdata *child,
				 struct syscallrecord *rec,
				 bool new_edges, unsigned long new_cmp,
				 const struct kcov_pc_result *pcres)
{
	bool deep_pcs = false;
	bool near_truncation = false;

	if (child->kcov.mode != KCOV_MODE_PC || new_edges || new_cmp != 0 ||
	    rec->nr >= MAX_NR_SYSCALL || kcov_shm == NULL)
		return;

	/* Per-call PC count vs the syscall's lifetime running mean.
	 * distinct_sum is the cross-arch sum of per_syscall_diag[].
	 * distinct_pcs (the lifetime sum of per-call dedup-inc
	 * first-sightings); calls is the lifetime invocation count.
	 * mean = distinct_sum / calls; guard against zero-divide and
	 * apply DEEP_WARM_PCS_MIN_CALLS as a warmup floor so a
	 * syscall whose first few calls all happen to be its own
	 * deepest does not flood the counter.  The compare is
	 * pcs * DEN >= mean_unrolled (pcs >= mean * MULT) folded into
	 * an integer cross-product so no division per call. */
	if (pcres->local_distinct_pcs > 0) {
		unsigned long calls = per_syscall_calls_total(rec->nr);
		if (calls >= DEEP_WARM_PCS_MIN_CALLS) {
			unsigned long distinct_sum =
				__atomic_load_n(&kcov_shm->per_syscall_cmp.per_syscall_diag[rec->nr][0].distinct_pcs,
					__ATOMIC_RELAXED) +
				__atomic_load_n(&kcov_shm->per_syscall_cmp.per_syscall_diag[rec->nr][1].distinct_pcs,
					__ATOMIC_RELAXED);
			/* pcres.local_distinct_pcs * calls is the
			 * per-call value scaled by the denominator
			 * of the mean (distinct_sum / calls); the
			 * predicate "pcs >= MULT * mean" becomes
			 * "pcs * calls >= MULT * distinct_sum"
			 * without ever performing the division.
			 * Overflow needs pcs * calls > ULONG_MAX, i.e.
			 * a single trace with ~2^32 PCs AND ~2^32
			 * lifetime calls on the same syscall, both
			 * orders of magnitude past the realised
			 * envelope; the OLD branch in frontier_cold_
			 * weight() relies on the same shape. */
			if (pcres->local_distinct_pcs * calls >=
			    DEEP_WARM_PCS_MEAN_MULT * distinct_sum)
				deep_pcs = true;
		}
	}

	/* Per-call PC trace length vs the kcov_trace_size buffer
	 * cap (the runtime --kcov-trace-size value; defaults to
	 * KCOV_TRACE_SIZE).  pcres.trace_size is the post-cap PC
	 * count kcov_collect() already computed (clamped at
	 * kcov_trace_size - 1 on truncation -- a saturated call
	 * satisfies the inequality trivially).  Cross-multiplied
	 * to avoid the runtime divide. */
	if (pcres->trace_size * DEEP_WARM_TRACE_DEN >=
	    (unsigned long)kcov_trace_size * DEEP_WARM_TRACE_NUM)
		near_truncation = true;

	if (deep_pcs || near_truncation) {
		__atomic_fetch_add(&shm->stats.picker_bandit.warm_reserve_candidates_total,
				   1UL, __ATOMIC_RELAXED);
		__atomic_fetch_add(&shm->stats.picker_bandit.warm_reserve_candidates[rec->nr],
				   1UL, __ATOMIC_RELAXED);

		/* SHADOW would-replay-demand intersection: the
		 * deep-but-warm candidate population AND the plateau
		 * window in which a STAGE B capped-reserve replay
		 * would actually fire (CMP_RISING_PC_FLAT, the same
		 * hypothesis the cmp-recent-first arm and the
		 * cmp_hyp_try_live_inject path in cmp_hints.c key off
		 * -- the read here matches that contract: RELAXED
		 * load of shm->plateau_current_hypothesis, compared
		 * to the enum cast to int).  Gated INSIDE the
		 * predicate-fire branch so the plateau field is only
		 * loaded on the deep-but-warm tail; a syscall that
		 * does not fire warm_reserve_candidates does not
		 * touch the field.  No live consumer reads either
		 * counter -- sizing/demand signal for the STAGE B
		 * build only. */
		if (__atomic_load_n(&shm->plateau_current_hypothesis,
				    __ATOMIC_RELAXED) ==
		    (int)PLATEAU_HYPOTHESIS_CMP_RISING_PC_FLAT) {
			__atomic_fetch_add(&shm->stats.picker_bandit.warm_reserve_during_plateau_total,
					   1UL, __ATOMIC_RELAXED);
			__atomic_fetch_add(&shm->stats.picker_bandit.warm_reserve_during_plateau[rec->nr],
					   1UL, __ATOMIC_RELAXED);
		}
	}
}

/* SHADOW cold-overflow would-save accounting.  Pure
 * measurement -- the existing save call (back in dispatch_step) is
 * byte-identical to the pre-row baseline, and no admission /
 * scoring / picking / corpus path consumes any of the
 * counters bumped here.  See the cold_overflow_would_
 * save_* block in include/stats.h for the predicate
 * composition and the SHADOW contract.
 *
 * MUST run BEFORE minicorpus_save_with_reason() below:
 * the live save publishes a new entry into
 * rings[rec->nr] and bumps its count from 0 to 1, which
 * would race the "absent" snapshot to always-false for
 * the headline first-admission case (the very event the
 * absent subset is meant to capture).  Reading the count
 * here, pre-save, pins absent to the pre-decision state
 * the overflow lane would see.
 *
 * Mirrors the existing save gate (entry->sanitise == NULL)
 * so the population matches the population the live save
 * lane would admit -- a sanitise-bearing syscall is
 * deliberately excluded by both lanes for the same
 * reason (the pointer args may be stale at replay time).
 *
 * Gates, in cheapest-first order so the hot found_something
 * arm short-circuits before touching the plateau /
 * minicorpus loads on the dominant new_edges-only,
 * non-plateau, in-corpus path:
 *
 *   entry->sanitise == NULL    -- match the live save lane
 *   new_cmp > 0                -- nonzero CMP signal
 *   rec->nr < MAX_NR_SYSCALL   -- bound the array index
 *   plateau == CMP_RISING_PC_FLAT
 *   cold OR corpus-absent      -- the overflow-tail
 *                                 predicate
 *
 * RELAXED on the bumps; ACQUIRE on the per-nr ring count
 * read so it pairs with the publishing release inside
 * minicorpus_save_with_reason on the peer side.  A peer
 * winning the first admission between our load and the
 * local save below still leaves our local view at zero
 * (we read first), so the over-count window collapses to
 * the parent-thread-only ordering enforced by this
 * "shadow-before-save" placement. */
void account_cold_overflow_would_save(struct syscallentry *entry,
					     struct syscallrecord *rec,
					     unsigned long new_cmp)
{
	bool cold, absent = false;

	if (entry->sanitise != NULL || new_cmp == 0 ||
	    rec->nr >= MAX_NR_SYSCALL ||
	    __atomic_load_n(&shm->plateau_current_hypothesis,
			    __ATOMIC_RELAXED) !=
	    (int)PLATEAU_HYPOTHESIS_CMP_RISING_PC_FLAT)
		return;

	cold = kcov_syscall_cold_skip_pct(rec->nr) > 0;

	if (minicorpus_shm != NULL)
		absent = __atomic_load_n(
			&minicorpus_shm->rings[rec->nr].count,
			__ATOMIC_ACQUIRE) == 0;

	if (cold || absent) {
		__atomic_fetch_add(
			&shm->stats.cold_overflow.would_save,
			1UL, __ATOMIC_RELAXED);
		if (cold)
			__atomic_fetch_add(
				&shm->stats.cold_overflow.would_save_cold,
				1UL, __ATOMIC_RELAXED);
		if (absent)
			__atomic_fetch_add(
				&shm->stats.cold_overflow.would_save_absent,
				1UL, __ATOMIC_RELAXED);
	}
}
