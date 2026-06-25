/*
 * Per-syscall frontier-edge ring accessors.  Split from strategy.c
 * so the frontier code compiles independently of the bandit / picker
 * / plateau / cmp-novelty translation units.
 */

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>

#include "child.h"		/* struct childdata */
#include "cred_throttle.h"	/* cred_class_for_nr, CRED_CLASS_NR */
#include "kcov.h"
#include "params.h"		/* frontier_live_cooldown */
#include "shm.h"
#include "stats.h"
#include "strategy.h"
#include "syscall.h"		/* MAX_NR_SYSCALL */

/*
 * Per-syscall frontier-edge ring accessors.
 *
 * The ring is a fixed-width window of FRONTIER_DECAY_WINDOWS slots per
 * syscall; the slot currently being filled is (frontier_slot &
 * (FRONTIER_DECAY_WINDOWS - 1)).  Producers (kcov_collect on the
 * new-edge branch) atomic-add into the current slot.  The rotation hook
 * advances the slot index and zeroes the slot it just moved into, so
 * sums across the ring give the trailing K-window frontier count for
 * each syscall -- effectively a sliding window with discrete decay.
 *
 * FRONTIER_DECAY_WINDOWS is currently 8 (see strategy.h); the AND-mask
 * approach assumes it stays a power of two -- enforced by the
 * static_assert below so a future change to a non-pot value fails at
 * compile time rather than silently producing wrong slot indices.
 */
_Static_assert((FRONTIER_DECAY_WINDOWS &
		(FRONTIER_DECAY_WINDOWS - 1)) == 0,
	       "FRONTIER_DECAY_WINDOWS must be a power of two");

void frontier_record_new_edge(unsigned int nr)
{
	uint32_t slot;
	unsigned long w;
	unsigned int cached;

	if (nr >= MAX_NR_SYSCALL)
		return;

	slot = __atomic_load_n(&shm->frontier_slot, __ATOMIC_RELAXED) &
	       (FRONTIER_DECAY_WINDOWS - 1);
	__atomic_fetch_add(&shm->frontier_history[nr][slot], 1U,
			   __ATOMIC_RELAXED);
	__atomic_fetch_add(&shm->frontier_recent_count_cached[nr], 1U,
			   __ATOMIC_RELAXED);

	/* RedQueen-source PC-edge attribution.  When the call that produced
	 * this new edge was a replay of a corpus entry whose args were
	 * originally captured under in_reexec (i.e. the RedQueen re-exec
	 * path harvested those args), credit the win to the dedicated
	 * rq_sourced_pcedge_wins_per_syscall[] counter so the periodic
	 * dump can report PC-edge conversion of RedQueen-sourced saves
	 * separately from the bulk per-strategy attribution.  Observability
	 * only -- no selection / reward code reads this counter.  RELAXED
	 * add-fetch matches the surrounding accounting. */
	{
		struct childdata *cc = this_child();

		if (cc != NULL && cc->replay_rq_sourced)
			__atomic_fetch_add(
				&shm->stats.rq_sourced_pcedge_wins_per_syscall[nr],
				1UL, __ATOMIC_RELAXED);

		/* errno-gradient-save conversion counter.  Sibling of the
		 * rq_sourced bump above for the errno-source provenance lane.
		 * Bumped only when the call that produced this PC win was a
		 * replay of a corpus entry whose errno_sourced flag was set --
		 * i.e. a downstream PC-edge win from an errno-gradient save.
		 * Observability only; cumulative-diagnostic semantics matches
		 * the rest of the strategy.c accounting. */
		if (cc != NULL && cc->replay_errno_sourced)
			__atomic_fetch_add(
				&shm->stats.errno_sourced_pcedge_wins_per_syscall[nr],
				1UL, __ATOMIC_RELAXED);
	}

	/* SHADOW-ONLY silent-streak reset.  This function is the canonical
	 * per-syscall new-edge productive-event hook -- already called from
	 * kcov_collect()'s found_new branch when a syscall's call has
	 * produced at least one fresh bucket bit, which is also the path
	 * that contributes the positive local_distinct_pcs delta the
	 * coverage-frontier picker treats as the "productive" signal.
	 * Resetting the silent-streak counter here therefore reuses the
	 * existing per-syscall productive-edge collection site -- no new
	 * collection path is added.
	 *
	 * The counter and the global frontier_shadow_decay_candidates it
	 * edge-triggers in random-syscall.c's silent-regime accept site
	 * are observability-only: no live selection or scoring code reads
	 * them, so the reset cannot perturb the picker distribution. */
	__atomic_store_n(
		&shm->stats.frontier_silent_streak_per_syscall[nr],
		0UL, __ATOMIC_RELAXED);

	/* SHADOW-ONLY LIVE-regime miss-streak reset, paired with the
	 * silent-streak reset above.  Same productive-event semantics: this
	 * function is the canonical per-syscall new-edge productive-event
	 * hook, so a fresh bucket bit on this syscall releases the LIVE-
	 * regime cooldown streak just as it releases the silent-streak
	 * decay.  Without this reset the per-syscall LIVE-miss streak would
	 * latch high after a single productive run of zero-edge LIVE picks
	 * and the frontier_live_cooldown_candidates / frontier_live_would_
	 * skip projections would be permanently inflated.
	 *
	 * Same observability-only contract as the silent-streak reset
	 * above; no live-path code reads either counter or its companion
	 * scalars. */
	__atomic_store_n(
		&shm->stats.frontier_live_miss_streak_per_syscall[nr],
		0UL, __ATOMIC_RELAXED);

	/* SHADOW-ONLY no-novelty baseline snapshot, paired with the streak
	 * reset above.  Snapshots the current value of the two non-PC-edge
	 * novelty signals (per-syscall CMP-pool inserts and per-syscall
	 * SUCCESS-bucket errno count) so the silent-regime accept site can
	 * detect whether either fired during the next silent streak via a
	 * cheap current-vs-baseline equality test.  A streak reset here is
	 * the right moment to refresh the baselines: by construction this
	 * call also bumped per_syscall_edges, so PC-edge novelty IS the
	 * reset event and the no-novelty UNLESS clause is being re-armed
	 * for the next streak.
	 *
	 * Same observability-only contract as the streak counter above --
	 * no selection or scoring code reads these baselines, only the
	 * shadow decay predicate at the silent-regime accept site does.
	 * kcov_shm NULL-checked because frontier_record_new_edge is
	 * unreachable without a coverage trace under collection, but the
	 * guard matches the pattern other kcov_shm consumers follow. */
	if (kcov_shm != NULL) {
		unsigned long cmp_snap, errno_snap;

		cmp_snap = __atomic_load_n(
			&kcov_shm->per_syscall_cmp_inserts[nr],
			__ATOMIC_RELAXED);
		errno_snap = __atomic_load_n(
			&kcov_shm->per_syscall_errno[nr][ERRNO_BUCKET_SUCCESS],
			__ATOMIC_RELAXED);
		__atomic_store_n(
			&shm->stats.frontier_silent_cmp_baseline[nr],
			cmp_snap, __ATOMIC_RELAXED);
		__atomic_store_n(
			&shm->stats.frontier_silent_errno_success_baseline[nr],
			errno_snap, __ATOMIC_RELAXED);
	}

	/* Ratchet the cached max upward if this bump pushed nr's recent
	 * count past it.  No CAS: a racing producer that also raises the
	 * max can clobber our store with its (also-correct) value, and a
	 * racing rotation will overwrite with the authoritative recompute.
	 * Both outcomes leave the cache within one window's slack. */
	w = frontier_recent_count(nr);
	if (w > UINT_MAX)
		w = UINT_MAX;
	cached = __atomic_load_n(&shm->frontier_max_weight_cached,
				 __ATOMIC_RELAXED);
	if ((unsigned int)w > cached)
		__atomic_store_n(&shm->frontier_max_weight_cached,
				 (unsigned int)w, __ATOMIC_RELAXED);
}

/*
 * Transition-discovery sibling of frontier_record_new_edge().  Bumps
 * the same per-syscall frontier-edge ring + cached max + silent-streak
 * reset triple, treating a transition-slot flip as evidence that the
 * syscall is currently producing fresh control-flow coverage.  The
 * canonical signal pattern is "PC-edge discovery plateaued while
 * transition discovery still moves" -- so under COMBINED mode the
 * frontier ring needs to be pushed up for syscalls
 * producing transitions but no fresh PC bucket bits, otherwise the
 * silent-regime picker steers away from exactly the syscalls that are
 * still earning the post-plateau coverage.
 *
 * Caller-side gates (in random-syscall.c at the kcov_collect call
 * site) handle the kcov_transition_reward_mode == COMBINED and
 * !child->is_explorer and !child->kcov.remote_mode filters before
 * invoking, so this function only sees calls that should bump the
 * ring.  The RedQueen-source PC-edge attribution branch in
 * frontier_record_new_edge() is deliberately omitted here -- that
 * counter measures PC-edge wins from RedQueen-sourced corpus replays
 * and a transition discovery is a different signal.  The silent-streak
 * reset DOES apply: a syscall producing transitions has demonstrably
 * been productive this window, which is the streak's reset semantics
 * (frontier_silent_streak_per_syscall is a "consecutive cold windows"
 * counter, agnostic to PC vs transition).
 */
void frontier_record_transition_edge(unsigned int nr)
{
	uint32_t slot;
	unsigned long w;
	unsigned int cached;

	if (nr >= MAX_NR_SYSCALL)
		return;

	slot = __atomic_load_n(&shm->frontier_slot, __ATOMIC_RELAXED) &
	       (FRONTIER_DECAY_WINDOWS - 1);
	__atomic_fetch_add(&shm->frontier_history[nr][slot], 1U,
			   __ATOMIC_RELAXED);
	__atomic_fetch_add(&shm->frontier_recent_count_cached[nr], 1U,
			   __ATOMIC_RELAXED);

	__atomic_store_n(
		&shm->stats.frontier_silent_streak_per_syscall[nr],
		0UL, __ATOMIC_RELAXED);

	/* SHADOW-ONLY LIVE-regime miss-streak reset.  Sibling of the reset
	 * in frontier_record_new_edge(): a transition-edge discovery is a
	 * productive event the LIVE-regime cooldown streak must release on,
	 * same as the silent-streak decay above and for the same reason.
	 * Leaving this out would let the LIVE-miss streak latch high on
	 * syscalls that are earning post-plateau transition coverage but no
	 * fresh PC bucket bits, inflating the cooldown projections on
	 * exactly the syscalls a live variant should NOT cool down. */
	__atomic_store_n(
		&shm->stats.frontier_live_miss_streak_per_syscall[nr],
		0UL, __ATOMIC_RELAXED);

	/* SHADOW-ONLY no-novelty baseline snapshot.  Mirror of the snapshot
	 * pair in frontier_record_new_edge(): a transition-edge discovery
	 * is also a productive event for the streak's purposes, so the
	 * decay predicate's UNLESS-clause baselines re-arm here too.  Same
	 * observability-only contract; see the matching block in
	 * frontier_record_new_edge() for full rationale. */
	if (kcov_shm != NULL) {
		unsigned long cmp_snap, errno_snap;

		cmp_snap = __atomic_load_n(
			&kcov_shm->per_syscall_cmp_inserts[nr],
			__ATOMIC_RELAXED);
		errno_snap = __atomic_load_n(
			&kcov_shm->per_syscall_errno[nr][ERRNO_BUCKET_SUCCESS],
			__ATOMIC_RELAXED);
		__atomic_store_n(
			&shm->stats.frontier_silent_cmp_baseline[nr],
			cmp_snap, __ATOMIC_RELAXED);
		__atomic_store_n(
			&shm->stats.frontier_silent_errno_success_baseline[nr],
			errno_snap, __ATOMIC_RELAXED);
	}

	w = frontier_recent_count(nr);
	if (w > UINT_MAX)
		w = UINT_MAX;
	cached = __atomic_load_n(&shm->frontier_max_weight_cached,
				 __ATOMIC_RELAXED);
	if ((unsigned int)w > cached)
		__atomic_store_n(&shm->frontier_max_weight_cached,
				 (unsigned int)w, __ATOMIC_RELAXED);
}

unsigned long frontier_recent_count(unsigned int nr)
{
	if (nr >= MAX_NR_SYSCALL)
		return 0;

	return __atomic_load_n(&shm->frontier_recent_count_cached[nr],
			       __ATOMIC_RELAXED);
}

/*
 * Errno-plateau decay predicate for the coverage-frontier picker's
 * silent-regime accept site.  See the FRONTIER_ERRNO_PLATEAU_* contract
 * in include/strategy.h for the design rationale; the four novelty-
 * restore lanes (PC edge / transition / CMP / new-errno) are all the
 * predicate ever needs because the underlying counters are monotonic --
 * any productive event flips the predicate permanently false for that
 * syscall without requiring a per-syscall reset hook in frontier_
 * record_new_edge / frontier_record_transition_edge.
 *
 * Reads are RELAXED.  A torn or stale snapshot only shifts the predicate
 * by at most one call's worth of evidence, well inside the slack the
 * outer accept/retry loop already tolerates, and the inequality tests
 * cannot misclassify across the threshold by more than one increment.
 *
 * Returns false when kcov_shm is NULL or nr is out of range so the
 * caller's accept gate degrades to the historical accept distribution
 * rather than wedging on a NULL deref -- matches the kcov-less fallback
 * frontier_cold_weight already takes.
 */
bool frontier_errno_plateau_should_decay(unsigned int nr, bool do32)
{
	unsigned long calls, edges, cmp_inserts, transition_edges;
	unsigned long max_failure_bucket = 0;
	unsigned int bucket;

	if (kcov_shm == NULL || nr >= MAX_NR_SYSCALL)
		return false;

	/* Coordinate with the landed --cred-throttle gate: credential-class
	 * syscalls have their own EPERM/EINVAL dominance throttle keyed on
	 * cred_class_* counters in cred_throttle.c, and a credential-class
	 * pick already burns its rejection budget on that gate.  Excluding
	 * the set here keeps a credential syscall from being decayed by both
	 * gates in lock-step -- the cred-throttle reject lands first inside
	 * set_syscall_nr_coverage_frontier, so this predicate only ever sees
	 * a credential pick that the throttle already let through. */
	if (cred_class_for_nr(nr, do32) != CRED_CLASS_NR)
		return false;

	calls = __atomic_load_n(&kcov_shm->per_syscall_calls[nr],
				__ATOMIC_RELAXED);
	if (calls < FRONTIER_ERRNO_PLATEAU_MIN_CALLS)
		return false;

	/* PC-edge novelty lane.  per_syscall_edges has call-count semantics
	 * (see include/kcov.h): one bump per call that discovered at least
	 * one fresh bucket bit.  A non-zero value means the syscall has been
	 * productive in PC-coverage terms at least once across its lifetime,
	 * so the decay must release.  Counter is monotonic non-decreasing,
	 * so once edges > 0 the predicate is permanently false for nr. */
	edges = __atomic_load_n(&kcov_shm->per_syscall_edges[nr],
				__ATOMIC_RELAXED);
	if (edges > 0)
		return false;

	/* CMP novelty lane.  per_syscall_cmp_inserts counts fresh inserts
	 * and evict-replaces in cmp_hints' per-syscall pool (dedup-refresh
	 * hits do not count, matching the global counter's semantics).  A
	 * syscall producing CMP signal without PC-edge progress is still
	 * earning post-plateau coverage of a different shape, so don't
	 * decay it.  Monotonic non-decreasing same as the edges counter. */
	cmp_inserts = __atomic_load_n(&kcov_shm->per_syscall_cmp_inserts[nr],
				      __ATOMIC_RELAXED);
	if (cmp_inserts > 0)
		return false;

	/* Transition-novelty lane.  per_syscall_transition_edges_real_local
	 * counts local-mode trace transition-slot first-flips (a new
	 * (prev_canon_pc, cur_canon_pc) ordering observed) for this syscall.
	 * Like the CMP lane: a syscall flipping new transition slots is
	 * earning control-flow coverage the PC bitmap misses, so the decay
	 * must release.  Monotonic non-decreasing. */
	transition_edges = __atomic_load_n(
		&kcov_shm->per_syscall_transition_edges_real_local[nr],
		__ATOMIC_RELAXED);
	if (transition_edges > 0)
		return false;

	/* New-errno novelty lane.  Scan the 7 non-SUCCESS buckets and find
	 * the dominant one.  SUCCESS is excluded from the dominance test
	 * because a syscall returning SUCCESS but bumping no PC edges is
	 * still exercising kernel state worth probing -- the decay targets
	 * syscalls whose calls the kernel is REJECTING with a single fixed
	 * errno.  Any new bucket (including a late SUCCESS) bumps per_
	 * syscall_calls and dilutes the dominant failure ratio below
	 * DOM_PCT, restoring the syscall to full sampling. */
	for (bucket = ERRNO_BUCKET_SUCCESS + 1;
	     bucket < ERRNO_BUCKET_NR; bucket++) {
		unsigned long c = __atomic_load_n(
			&kcov_shm->per_syscall_errno[nr][bucket],
			__ATOMIC_RELAXED);
		if (c > max_failure_bucket)
			max_failure_bucket = c;
	}
	/* Percent check rearranged to integer-safe form, matching the same
	 * shape cred_throttle_should_reject uses for HARD_FAIL_PCT. */
	if (max_failure_bucket * 100UL <
	    (unsigned long)FRONTIER_ERRNO_PLATEAU_DOM_PCT * calls)
		return false;

	return true;
}

void frontier_window_advance(void)
{
	uint32_t cur, next;
	unsigned int nr;
	unsigned long max_weight = 0;
	bool cooldown_enabled;

	/* Clear-then-publish, the opposite of the previous order.  The old
	 * code bumped frontier_slot first and then aged out the slot it had
	 * just published, which opened a window in which a producer could
	 * (a) add into the new slot before we cleared it, (b) have that
	 * write exchanged back to zero, and (c) issue its cached-sum
	 * increment AFTER our subtract.  In the worst case the rotator's
	 * fetch_sub ran with an old_slot value that was larger than the
	 * cached running sum -- because part of the producer's contribution
	 * was already in the slot but not yet in the cached counter -- so
	 * the subtract wrapped negative and the cached count flipped to a
	 * near-UINT32_MAX weight.  That bogus weight is consumed by
	 * random-syscall.c's frontier roulette wheel; an arm-wide blow-up
	 * either collapses the wheel onto one syscall or pushes the
	 * rejection sampler into an effectively-uniform reject loop.
	 *
	 * We now compute the next slot index without publishing it, age out
	 * the slot's contents from every per-nr running sum while no
	 * producer is targeting that slot (frontier_slot still points to
	 * the previous slot), and only then bump frontier_slot.  A producer
	 * racing the rotation keeps adding into the previous slot for a
	 * handful of instructions -- a bounded window-boundary attribution
	 * error -- instead of having its addition silently dropped or
	 * inverting the cached sum.
	 *
	 * The saturating subtract is kept as a hard guard: even with the
	 * reorder, a CAS-clamped update means a producer that races our
	 * read-modify-write on cached can't drive it negative.  Hitting the
	 * clamp bumps frontier_underflow_prevented -- the metric is
	 * expected to read zero in steady state. */
	cur = __atomic_load_n(&shm->frontier_slot, __ATOMIC_RELAXED);
	next = (cur + 1U) & (FRONTIER_DECAY_WINDOWS - 1);

	/* --frontier-live-cooldown flag short-circuit.  Read once per
	 * rotation rather than per-nr; the flag is set once at startup and
	 * never flipped at runtime, so a single RELAXED load amortises
	 * across the MAX_NR_SYSCALL inner loop.  Flag off keeps the
	 * rotation arithmetic byte-identical to the pre-flag baseline:
	 * cooldown_enabled gates the per-nr streak load AND the halving
	 * step below, so neither extra cost is paid on the default-off
	 * path. */
	cooldown_enabled = __atomic_load_n(&frontier_live_cooldown,
					   __ATOMIC_RELAXED);

	for (nr = 0; nr < MAX_NR_SYSCALL; nr++) {
		uint32_t old_slot;
		uint32_t old_cached;
		uint32_t new_sum;
		bool cool_this_nr = false;
		bool decayed_this_nr = false;

		old_slot = __atomic_exchange_n(&shm->frontier_history[nr][next],
					       0U, __ATOMIC_RELAXED);

		/* F4(X) per-nr cooldown predicate.  Reuses the F3 per-syscall
		 * LIVE-regime miss-streak (frontier_live_miss_streak_per_syscall
		 * -- bumped strictly after a zero-edge LIVE-regime pick at the
		 * random_syscall_step attribution path, reset on any productive
		 * event via the existing frontier_record_new_edge() /
		 * frontier_record_transition_edge() hooks): when the streak has
		 * crossed FRONTIER_LIVE_MISS_COOLDOWN this nr is a wall-mover
		 * candidate, and the halving step below drives its cached sum
		 * toward zero so frontier_max_weight_cached falls and the
		 * picker reaches the silent decay path on it.
		 *
		 * Loaded once per nr per rotation (NOT inside the CAS loop --
		 * the streak does not change with our CAS retry; only the
		 * cached running sum does) and only when the flag is on, so the
		 * default-off path pays for nothing here.  A racing
		 * random_syscall_step bump that raises the streak across the
		 * threshold between this load and the cached-sum update is
		 * picked up by the NEXT rotation -- bounded one-window lag,
		 * same as every other rotation-boundary attribution. */
		if (cooldown_enabled) {
			unsigned long streak;

			streak = __atomic_load_n(
				&shm->stats.frontier_live_miss_streak_per_syscall[nr],
				__ATOMIC_RELAXED);
			if (streak >= FRONTIER_LIVE_MISS_COOLDOWN)
				cool_this_nr = true;
		}

		/* CAS loop so a concurrent producer's fetch_add against the
		 * cached counter cannot be lost and cannot underflow the
		 * sum.  Producers should not be racing this nr at this
		 * point (frontier_slot still names the previous slot) but
		 * the loop costs at most a handful of retries and removes
		 * the underflow case unconditionally.
		 *
		 * F4(X) halving is folded into the SAME CAS retry so a racing
		 * producer cannot land an add between our subtract and our
		 * decay store.  The halving is a right-shift on a uint32_t
		 * that is by construction <= old_cached (clamped above), so
		 * it never wraps -- no extra underflow guard required, and
		 * the existing if (old_cached < old_slot) clamp metric stays
		 * scoped to the trailing-window subtract case it has always
		 * counted.  decayed_this_nr fires only when the halving
		 * actually reduced a non-zero sum, so a cool-marked nr whose
		 * window already aged to zero through the trailing-K
		 * subtraction does NOT inflate the did-decay observability
		 * counter. */
		old_cached = __atomic_load_n(
			&shm->frontier_recent_count_cached[nr],
			__ATOMIC_RELAXED);
		for (;;) {
			uint32_t after_decay;

			if (old_cached >= old_slot)
				new_sum = old_cached - old_slot;
			else
				new_sum = 0;
			if (cool_this_nr && new_sum > 0) {
				after_decay = new_sum >> 1;
				decayed_this_nr = true;
			} else {
				after_decay = new_sum;
				decayed_this_nr = false;
			}
			if (__atomic_compare_exchange_n(
				    &shm->frontier_recent_count_cached[nr],
				    &old_cached, after_decay, false,
				    __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
				new_sum = after_decay;
				break;
			}
		}
		if (old_cached < old_slot)
			__atomic_add_fetch(
				&shm->stats.frontier_underflow_prevented,
				1UL, __ATOMIC_RELAXED);
		if (decayed_this_nr)
			__atomic_add_fetch(
				&shm->stats.frontier_live_cooldown_decays,
				1UL, __ATOMIC_RELAXED);
		if (new_sum > max_weight)
			max_weight = new_sum;
	}

	/* Publish the new slot only after every per-nr clear has landed.
	 * From this point producers see the freshly-zeroed slot. */
	__atomic_store_n(&shm->frontier_slot, cur + 1U, __ATOMIC_RELAXED);

	if (max_weight > UINT_MAX)
		max_weight = UINT_MAX;
	__atomic_store_n(&shm->frontier_max_weight_cached,
			 (unsigned int)max_weight, __ATOMIC_RELAXED);
}
