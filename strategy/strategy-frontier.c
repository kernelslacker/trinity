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
#include "object-types.h"	/* OBJ_NONE */
#include "shm.h"
#include "stats.h"
#include "strategy.h"
#include "syscall.h"		/* MAX_NR_SYSCALL */
#include "tables.h"		/* syscalls / syscalls_32bit / syscalls_64bit */

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

/*
 * SHADOW-ONLY topology-pair latch + ring writer.  Invoked from the
 * two productive-event hooks: frontier_record_new_edge below for new
 * PC-edge bucket bits, and the ungated kcov_collect() transition block
 * in kcov.c (co-located with the per_syscall_transition_edges_real
 * bump) for new transition slots, so a single site owns the
 * read-of-child-latch / packed-store-into-ring sequence and both
 * reason codes share the same race contract.
 *
 * NR_CHILD_OP_TYPES must fit in the 8-bit setup_op slot of the packed
 * entry, and TOPO_PAIR_RING_SIZE must be a power of two so the
 * fetch-add'd head can be masked instead of modulo'd.  Both invariants
 * are pinned at compile time below; a future bump to NR_CHILD_OP_TYPES
 * past 256 entries (today: ~117) would silently truncate the recorded
 * setup_op without these asserts, and a non-power-of-two ring size
 * would invalidate the AND-mask address derivation in the producer.
 *
 * The writer chain:
 *   1. Skip silently when called from parent context (this_child() ==
 *      NULL); the productive-event hooks already tolerate this via the
 *      existing per-syscall accounting blocks below.
 *   2. If the firing child has not yet observed any setup childop on
 *      this run (last_setup_op == NR_CHILD_OP_TYPES sentinel), bump
 *      topo_pair_no_setup_observed instead -- the cumulative
 *      "productive events with no prior setup" denominator the
 *      aggregator surfaces alongside the per-setup_op breakdown.
 *   3. Otherwise: compute age = op_nr - last_setup_op_nr (clamped at
 *      TOPO_PAIR_AGE_MAX so a long-lived child does not overflow the
 *      20-bit age field), pack the {setup_op, reason, syscall_nr, age}
 *      tuple via topo_pair_pack(), claim a ring slot with a RELAXED
 *      fetch-add of topo_pair_ring_head, and store the packed entry
 *      with a single RELAXED 64-bit store.  Single-store discipline
 *      means a reader observes either the prior slot's tuple or the
 *      fresh one but never a torn mix -- the only race window is two
 *      producers fetch-adding to the same modulo-equal head, which
 *      simply collapses one of their writes into the older entry, an
 *      outcome bounded by the overwrite-oldest semantics the ring
 *      already accepts.
 *
 * Cumulative topo_pair_records bumps unconditionally on the write path
 * so the aggregator can distinguish a sparsely-filled ring (records <
 * TOPO_PAIR_RING_SIZE; tail slots still uninitialised) from a wrapped
 * ring (records >= TOPO_PAIR_RING_SIZE; aggregator can scan the full
 * width).  RELAXED add-fetch -- saturation past ULONG_MAX is bounded
 * by the lifetime of a single fuzz run and the aggregator only reads
 * the counter for the "is the ring fully populated" flag.
 */
_Static_assert(NR_CHILD_OP_TYPES <= 256,
	       "NR_CHILD_OP_TYPES must fit in 8 bits for topo_pair packing");
_Static_assert((TOPO_PAIR_RING_SIZE &
		(TOPO_PAIR_RING_SIZE - 1u)) == 0,
	       "TOPO_PAIR_RING_SIZE must be a power of two");

void topo_pair_record_shadow(unsigned int nr, unsigned int reason)
{
	struct childdata *cc = this_child();
	enum child_op_type setup_op;
	unsigned long setup_op_nr, now_op_nr;
	unsigned long age;
	unsigned int slot;
	uint64_t packed;

	if (cc == NULL)
		return;

	setup_op = cc->last_setup_op;
	if ((unsigned int)setup_op >= NR_CHILD_OP_TYPES) {
		__atomic_fetch_add(&shm->stats.topo_pair.no_setup_observed,
				   1UL, __ATOMIC_RELAXED);
		return;
	}

	setup_op_nr = cc->last_setup_op_nr;
	now_op_nr = cc->op_nr;
	/* Age in child iterations.  op_nr is the child's per-iter counter;
	 * the productive event fires inside iter now_op_nr (the post-call
	 * bump at the bottom of child_process() has not yet run).  A wrap
	 * or out-of-order read that yields setup_op_nr > now_op_nr clamps
	 * to age=0 rather than underflowing to ~ULONG_MAX -- mirrors the
	 * monotonic-clock guard pattern other shadow consumers use. */
	if (now_op_nr < setup_op_nr)
		age = 0;
	else
		age = now_op_nr - setup_op_nr;
	if (age > (unsigned long)TOPO_PAIR_AGE_MAX)
		age = (unsigned long)TOPO_PAIR_AGE_MAX;

	packed = topo_pair_pack((unsigned int)setup_op, reason, nr,
				(unsigned int)age);

	slot = __atomic_fetch_add(&shm->stats.topo_pair.ring_head, 1u,
				  __ATOMIC_RELAXED) & TOPO_PAIR_RING_MASK;
	__atomic_store_n(&shm->stats.topo_pair.ring[slot], packed,
			 __ATOMIC_RELAXED);
	__atomic_fetch_add(&shm->stats.topo_pair.records, 1UL,
			   __ATOMIC_RELAXED);
}

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
				&shm->stats.pc_edge_source.rq_pcedge_wins[nr],
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
				&shm->stats.pc_edge_source.errno_pcedge_wins[nr],
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
		&shm->stats.frontier.per_syscall.silent_streak_per_syscall[nr],
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
		&shm->stats.frontier.per_syscall.live_miss_streak_per_syscall[nr],
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
			&shm->stats.frontier.per_syscall.silent_cmp_baseline[nr],
			cmp_snap, __ATOMIC_RELAXED);
		__atomic_store_n(
			&shm->stats.frontier.per_syscall.silent_errno_success_baseline[nr],
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

	/* SHADOW-ONLY topology-pair sample.  See topo_pair_record_shadow()
	 * for the full design contract.  Sits at the tail of the function
	 * so the live new-edge bookkeeping above (frontier ring, RedQueen /
	 * errno-source attribution, silent-streak resets, max-weight
	 * ratchet) is byte-identical to the pre-shadow path -- this single
	 * tail call is the only behavioural addition. */
	topo_pair_record_shadow(nr, TOPO_PAIR_REASON_PC);
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
		&shm->stats.frontier.per_syscall.silent_streak_per_syscall[nr],
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
		&shm->stats.frontier.per_syscall.live_miss_streak_per_syscall[nr],
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
			&shm->stats.frontier.per_syscall.silent_cmp_baseline[nr],
			cmp_snap, __ATOMIC_RELAXED);
		__atomic_store_n(
			&shm->stats.frontier.per_syscall.silent_errno_success_baseline[nr],
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

	calls = per_syscall_calls_total(nr);
	if (calls < FRONTIER_ERRNO_PLATEAU_MIN_CALLS)
		return false;

	/* PC-edge novelty lane.  per_syscall_edges has call-count semantics
	 * (see include/kcov.h): one bump per call that discovered at least
	 * one fresh bucket bit.  A non-zero value means the syscall has been
	 * productive in PC-coverage terms at least once across its lifetime,
	 * so the decay must release.  Counter is monotonic non-decreasing,
	 * so once edges > 0 the predicate is permanently false for nr. */
	edges = per_syscall_edges_total(nr);
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
		 * cached running sum does).  A racing random_syscall_step bump
		 * that raises the streak across the threshold between this
		 * load and the cached-sum update is picked up by the NEXT
		 * rotation -- bounded one-window lag, same as every other
		 * rotation-boundary attribution. */
		{
			unsigned long streak;

			streak = __atomic_load_n(
				&shm->stats.frontier.per_syscall.live_miss_streak_per_syscall[nr],
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
				&shm->stats.frontier.core.underflow_prevented,
				1UL, __ATOMIC_RELAXED);
		if (decayed_this_nr)
			__atomic_add_fetch(
				&shm->stats.frontier.cooldown.live_cooldown_decays,
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

/*
 * Saturation-cooldown spare-lane helper.
 *
 * Producer-observer bitmap: the silent-regime satcool predicate (see
 * frontier_satcool_spare below) spares syscalls whose syscallentry has
 * a non-OBJ_NONE ret_objtype -- the object-producer set (openat /
 * socket / memfd_create / mmap / io_uring_setup / bpf etc.) whose
 * payoff is delayed and credited downstream to the consumer of the
 * produced object.  ret_objtype is a static, compile-time property of
 * the syscallentry never modified at runtime, so the spared set is
 * precomputed into a per-arch bitmap at first call from the silent-
 * regime accept site and read with a plain bit-test on the hot path --
 * collapsing the per-pick get_syscall_entry() table indirection (plus
 * the biarch branch) the inline shape paid for.
 *
 * NULL entry (table slot empty OR nr >= max_nr_*_syscalls) is folded
 * into the spared set so an unknown nr cannot wrongly register as a
 * would-skip; this matches the original inline
 * `entry == NULL || entry->ret_objtype != OBJ_NONE` shape exactly --
 * the helper exists to remove the per-pick lookup, not to change the
 * spared set.
 *
 * Publish ordering: build_producer_observer() runs once-per-process
 * (each child has its own copy of the file-scope statics under
 * fork()-COW; the work is small and idempotent so each child paying
 * for one build is fine).  The publish is a RELEASE store to
 * producer_observer_ready and the read in frontier_satcool_spare is
 * an ACQUIRE load -- a partially-initialised bitmap is NEVER visible
 * to a concurrent reader.  A second caller racing the first sees
 * ready==0, loses the CAS to claim the build slot, and spins on the
 * acquire load until the winner publishes -- bounded spin (the build
 * is a few hundred bit-stores).
 */
#define FRONTIER_PRODUCER_OBSERVER_WORDS ((MAX_NR_SYSCALL + 63) / 64)

#ifdef ARCH_IS_BIARCH
static uint64_t producer_observer_bits_32[FRONTIER_PRODUCER_OBSERVER_WORDS];
static uint64_t producer_observer_bits_64[FRONTIER_PRODUCER_OBSERVER_WORDS];
#else
static uint64_t producer_observer_bits[FRONTIER_PRODUCER_OBSERVER_WORDS];
#endif

/*
 * 0 = not yet built, 1 = build in progress, 2 = built and published.
 * Three states (instead of a simple bool) so a racing caller can wait
 * on the publish without re-entering the build.
 */
static int producer_observer_ready;

static void build_producer_observer_bitmap(const struct syscalltable *table,
					   unsigned int table_nr,
					   uint64_t *bitmap)
{
	unsigned int i;
	unsigned int cap = (table_nr < MAX_NR_SYSCALL) ? table_nr
						       : MAX_NR_SYSCALL;

	for (i = 0; i < MAX_NR_SYSCALL; i++) {
		bool is_spared;

		if (i >= cap) {
			/*
			 * Mirrors get_syscall_entry()'s out-of-range NULL
			 * return; the original inline shape treats a NULL
			 * entry as spared.
			 */
			is_spared = true;
		} else if (table[i].entry == NULL) {
			is_spared = true;
		} else {
			is_spared = (table[i].entry->ret_objtype != OBJ_NONE);
		}

		if (is_spared)
			bitmap[i / 64] |= ((uint64_t) 1) << (i % 64);
	}
}

static void ensure_producer_observer_built(void)
{
	int state;
	int expected;

	state = __atomic_load_n(&producer_observer_ready, __ATOMIC_ACQUIRE);
	if (state == 2)
		return;

	expected = 0;
	if (__atomic_compare_exchange_n(&producer_observer_ready, &expected,
					1, false, __ATOMIC_ACQUIRE,
					__ATOMIC_ACQUIRE)) {
#ifdef ARCH_IS_BIARCH
		build_producer_observer_bitmap(syscalls_64bit,
					       max_nr_64bit_syscalls,
					       producer_observer_bits_64);
		build_producer_observer_bitmap(syscalls_32bit,
					       max_nr_32bit_syscalls,
					       producer_observer_bits_32);
#else
		build_producer_observer_bitmap(syscalls, max_nr_syscalls,
					       producer_observer_bits);
#endif
		__atomic_store_n(&producer_observer_ready, 2,
				 __ATOMIC_RELEASE);
		return;
	}

	/*
	 * Lost the CAS -- another caller is building.  Wait until they
	 * publish; the build is a bounded sequence of bit-stores so the
	 * spin terminates in microseconds.
	 */
	while (__atomic_load_n(&producer_observer_ready,
			       __ATOMIC_ACQUIRE) != 2)
		;
}

static bool producer_observer_lookup(unsigned int nr,
				     bool do32 __attribute__((unused)))
{
	const uint64_t *bm;

	if (nr >= MAX_NR_SYSCALL) {
		/*
		 * Mirrors get_syscall_entry()'s out-of-range NULL return:
		 * the original inline shape treats a NULL entry as spared.
		 */
		return true;
	}

#ifdef ARCH_IS_BIARCH
	bm = do32 ? producer_observer_bits_32 : producer_observer_bits_64;
#else
	bm = producer_observer_bits;
#endif

	return (bm[nr / 64] >> (nr % 64)) & 1;
}

/*
 * Spare-lane decision shared by the silent-regime satcool helper
 * (frontier_satcool_spare below) and the LIVE-regime cooldown helper
 * (frontier_live_cool_spare further below).  Returns the FIRST matching
 * spare reason, or FRONTIER_SPARE_NONE when no lane fires -- the caller
 * applies its own outer mode gate, magnitude floor, and counter-bump
 * cascade, so this routine is the bare predicate body the two siblings
 * share.  Extracting it keeps the lane logic from drifting between the
 * silent and LIVE call sites (one predicate body, two callers, zero
 * duplication).
 *
 * Lane order encodes precedence -- the bpf-backstop windowed-edges
 * spare wins over arggen, and arggen wins over the ret_objtype
 * producer spare (the more specific signal beats the broader catch).
 * Windowed-edges first: a syscall whose K-window ring is nonzero is
 * recently productive regardless of every other signal, so the
 * predicate stops there and the caller never reads cmp / errno
 * baselines on the windowed-nonzero path -- the recent-count check
 * returns FRONTIER_SPARE_WINDOWED_EDGES directly, skipping the four
 * RELAXED atomic loads that follow.
 *
 * All loads RELAXED: a mixed snapshot taken across non-atomic
 * instants at most causes one rotation of mis-classification, the
 * same one-window attribution lag the rotation loop already documents.
 * The cmp_now / cmp_base / errno_now / errno_base comparisons are
 * equality / ordering tests, never arithmetic, so a stale or torn
 * read cannot drive an unsigned subtraction or latch permanent state.
 * The producer-observer lookup is a single bit-test against the
 * immutable-after-init bitmap, published release-acquire by
 * ensure_producer_observer_built() above; the rotation-hot caller
 * (frontier_live_cool_spare on every LIVE-regime miss) pays one
 * lookup per call, no get_syscall_entry indirection.
 */
/* enum frontier_spare_reason lives in include/strategy.h so the shadow
 * attribution-confidence dump in stats/dump.c can bucket per-syscall
 * clean/noisy readings by the same spare-cascade classification the
 * silent- and LIVE-regime cooldown helpers here consume. */

enum frontier_spare_reason
frontier_spare_lane_decide(unsigned int syscallnr, bool do32)
{
	unsigned long cmp_now, cmp_base;
	unsigned long errno_now, errno_base;

	if (frontier_recent_count(syscallnr) != 0)
		return FRONTIER_SPARE_WINDOWED_EDGES;

	cmp_now = __atomic_load_n(
		&kcov_shm->per_syscall_cmp_inserts[syscallnr],
		__ATOMIC_RELAXED);
	cmp_base = __atomic_load_n(
		&shm->stats.frontier.per_syscall.silent_cmp_baseline[syscallnr],
		__ATOMIC_RELAXED);
	errno_now = __atomic_load_n(
		&kcov_shm->per_syscall_errno[syscallnr][ERRNO_BUCKET_SUCCESS],
		__ATOMIC_RELAXED);
	errno_base = __atomic_load_n(
		&shm->stats.frontier.per_syscall.silent_errno_success_baseline[syscallnr],
		__ATOMIC_RELAXED);

	/*
	 * CRITICAL: first-success TRANSITION, NOT raw success-count delta.
	 * A syscall that succeeds on every call (syncfs) has errno_base > 0
	 * at every baseline snapshot and so CANNOT spare itself by raw
	 * success accumulation; the spare fires only when the syscall
	 * transitions from never-having-succeeded (errno_base == 0) to
	 * producing its first success in the current window.  Distinct
	 * CMP-inserts use the existing baseline machinery (refreshed at
	 * every productive-event reset in frontier_record_new_edge() /
	 * frontier_record_transition_edge()), which already counts only
	 * first-inserts / evict-replaces in per_syscall_cmp_inserts -- the
	 * "distinct hint additions" the design names.
	 */
	if ((cmp_now != cmp_base) || (errno_base == 0 && errno_now > 0))
		return FRONTIER_SPARE_ARGGEN;

	/*
	 * Object-producer spare: ret_objtype != OBJ_NONE exempts the
	 * producers whose payoff is delayed and credited downstream to the
	 * consumer of the produced object.  Lookup is against the
	 * precomputed producer-observer bitmap above -- the per-pick
	 * get_syscall_entry() table indirection (and the biarch branch
	 * inside it) the original inline shape paid for is collapsed to a
	 * single bit-test.  Build is lazy with release/acquire publish so a
	 * partially-built bitmap is NEVER visible to a concurrent reader.
	 */
	ensure_producer_observer_built();
	if (producer_observer_lookup(syscallnr, do32))
		return FRONTIER_SPARE_OBJPRODUCER;

	return FRONTIER_SPARE_NONE;
}

/*
 * SHADOW-ONLY saturation-cooldown predicate, extracted from the silent-
 * regime accept site in random-syscall.c.  Gated by
 * --frontier-saturation-cooldown != off.  Sibling of the silent-streak
 * decay block and the errno-plateau block at the call site; this one
 * targets the same wasteful-silent-pick shape but uses the windowed
 * frontier-edge ring (frontier_recent_count, decays by construction
 * via the per-rotation slot zero + CAS-decrement of
 * frontier_recent_count_cached in frontier_window_advance) for the
 * plateau trigger, and the corrected first-success-TRANSITION +
 * distinct-CMP-insert spare lanes for the under-explored struct-arg
 * backlog.  See the enum frontier_saturation_cooldown_mode comment in
 * include/strategy.h for the predicate contract, the
 * FRONTIER_SATCOOL_CMIN comment for the magnitude-gate rationale, and
 * the per-counter struct comments in include/stats.h for semantics.
 *
 * Why this gate exists alongside the silent-streak decay at the call
 * site: that gate's UNLESS clause keys on raw ERRNO_BUCKET_SUCCESS
 * count, which advances on every successful return.  A syscall that
 * succeeds on every call (syncfs / sendfile with valid args / writev
 * to /dev/null) bumps the success bucket monotonically and the
 * existing UNLESS clause's baseline-equality test never trips -- the
 * streak decay cannot cool the single biggest reclaim target.  Keying
 * plateau on the windowed edge ring instead (which ages out old
 * productivity by construction) and gating the spare lane on a
 * first-success TRANSITION (errno_base == 0 AND errno_now > 0) rather
 * than a raw success-count delta closes the gap; the magnitude gate +
 * ret_objtype exemption keep the under-explored struct-arg backlog
 * (removexattrat / futex / fcntl) and the object-producers (openat /
 * socket / memfd_create / mmap / io_uring_setup / bpf) out of the
 * demote set.
 *
 * SHADOW-ONLY by construction: the helper computes the predicate and
 * bumps the frontier_satcool_* shadow counters but never reaches a
 * goto-retry at the call site, so the picker's accept distribution
 * stays byte-identical to the default-off baseline regardless of which
 * non-OFF mode is selected.  Wiring the COMBINED live reject is a
 * deliberate follow-up after a SHADOW_ONLY run validates the demote
 * mass concentrates on syncfs / sendfile / semget / writev and is ~0
 * on removexattrat / futex / io_uring_setup / bpf.
 *
 * Outer guard keeps the OFF path byte-identical to a build before the
 * feature: no kcov_shm load, no bitmap lookup, no atomic loads beyond
 * the single RELAXED mode read.  The MAX_NR_SYSCALL bound mirrors the
 * existing silent-streak block's bound at the call site so the per-
 * syscall would-skip array index is safe.
 *
 * Byte-identical to the pre-extraction inline shape: the candidate
 * gate is (calls_total >= FRONTIER_SATCOOL_CMIN AND windowed_edges
 * == 0); a windowed_edges != 0 nr early-returns from the shared
 * spare-lane decide function with FRONTIER_SPARE_WINDOWED_EDGES, which
 * this wrapper treats as the same "no bump" outcome the original
 * candidate-gate early-return produced.  The arggen-wins-over-
 * objproducer precedence in the bump cascade is preserved by the
 * lane-order in frontier_spare_lane_decide above.
 */
void frontier_satcool_spare(unsigned int syscallnr, bool do32)
{
	enum frontier_saturation_cooldown_mode satcool_mode;
	enum frontier_spare_reason reason;
	unsigned long calls_total;

	satcool_mode = __atomic_load_n(&frontier_saturation_cooldown_mode,
				       __ATOMIC_RELAXED);
	if (satcool_mode == FRONTIER_SATURATION_COOLDOWN_MODE_OFF)
		return;
	if (kcov_shm == NULL)
		return;
	if (syscallnr >= MAX_NR_SYSCALL)
		return;

	calls_total = per_syscall_calls_total(syscallnr);
	if (calls_total < FRONTIER_SATCOOL_CMIN)
		return;

	reason = frontier_spare_lane_decide(syscallnr, do32);

	/*
	 * Windowed-edges spare is folded into the early-return path the
	 * pre-extraction shape used (the original candidate gate required
	 * windowed_edges == 0).  Preserving that early-return keeps the
	 * satcool counter cascade byte-identical: a windowed-nonzero nr
	 * never bumped candidates / spared_arggen / spared_objproducer
	 * before extraction and still does not after.
	 */
	if (reason == FRONTIER_SPARE_WINDOWED_EDGES)
		return;

	__atomic_fetch_add(&shm->stats.frontier.saturation.satcool_candidates,
			   1UL, __ATOMIC_RELAXED);

	if (reason == FRONTIER_SPARE_ARGGEN) {
		__atomic_fetch_add(&shm->stats.frontier.saturation.satcool_spared_arggen,
				   1UL, __ATOMIC_RELAXED);
	} else if (reason == FRONTIER_SPARE_OBJPRODUCER) {
		__atomic_fetch_add(
			&shm->stats.frontier.saturation.satcool_spared_objproducer,
			1UL, __ATOMIC_RELAXED);
	} else {
		__atomic_fetch_add(&shm->stats.frontier.saturation.satcool_would_skip,
				   1UL, __ATOMIC_RELAXED);
		__atomic_fetch_add(
			&shm->stats.frontier.per_syscall.satcool_would_skip_per_syscall[syscallnr],
			1UL, __ATOMIC_RELAXED);
		/*
		 * COMBINED live-reject would sit here gated on satcool_mode
		 * == COMBINED; intentionally NOT wired in this commit.  The
		 * block is observability-only regardless of mode so the
		 * SHADOW_ONLY counters can be validated against a real run
		 * before any live divergence is introduced.  See the enum
		 * comment in include/strategy.h for the ramp discipline.
		 */
	}
}

/*
 * SHADOW-ONLY floored-barren sub-floor demote helper.  Sibling of
 * frontier_satcool_spare above; targets the pure zero-arg getter set
 * whose lifetime PC-edge yield has plateaued to a hard floor rather
 * than the windowed-plateau-of-saturated-productive set the satcool
 * predicate owns.  The two shadow projections are disjoint by
 * construction: the barren predicate requires lifetime edges == 0
 * (never productive) at a small calls floor, the satcool predicate
 * requires the FRONTIER_SATCOOL_CMIN 10000-call magnitude and keys
 * plateau on the K-window ring going flat for a syscall that HAS
 * produced.
 *
 * Vetted skeleton: num_args == 0 excludes struct-arg backlogs whose
 * yield is gated by arg-gen progress; ret_objtype == OBJ_NONE excludes
 * the object-producer set (openat / socket / memfd_create / mmap /
 * io_uring_setup / bpf) whose payoff is delayed and credited
 * downstream to the consumer; sanitise == NULL excludes state-
 * mutators (munlockall / setsid / sched_yield) whose payoff sits in
 * post-call side effects, not in the syscall's own edge yield; reach
 * <= FRONTIER_BARREN_MAX_REACH excludes slots that have already
 * earned productivity, which the reach-band picker's HIGH-band boost
 * owns.  num_args == 0 alone is NECESSARY but NOT SUFFICIENT --
 * without the vetting layer above the predicate would swallow
 * inotify_init (object producer), sched_yield (state mutator), and
 * rseq (heuristic-arm spike source).
 *
 * Sub-floor mechanism a COMBINED live variant would apply: swap the
 * silent-branch accept denominator from (FRONTIER_COLD_SCALE + 1) to
 * (FRONTIER_COLD_SCALE * FRONTIER_BARREN_DEMOTE_MULT + 1), leaving
 * the +1 numerator intact so a demoted slot keeps a residual sample
 * rather than starving.  The errno-success lane is intentionally
 * ignored -- for a no-arg getter with no producer and no mutator,
 * "success" is information-free; only a real PC-edge or transition
 * reset (already wired via frontier_record_new_edge in strategy.c)
 * releases the demote.
 *
 * Called from the silent-regime accept site in random-syscall.c
 * immediately after frontier_satcool_spare so the two shadow
 * projections sit alongside each other in the pick path and share
 * the outer MAX_NR_SYSCALL bound the caller already established.
 *
 * Counter cascade:
 *   frontier_barren_candidates
 *      Cumulative: one bump per silent-regime pick where the vetted
 *      skeleton matches (num_args == 0 AND ret_objtype == OBJ_NONE
 *      AND sanitise == NULL AND reach <= MAX_REACH AND calls >
 *      C_MIN).  The candidate set the demote lane peels from.
 *   frontier_barren_would_skip
 *      Cumulative: subset of candidates whose full demote predicate
 *      also holds (lifetime edges == 0 AND windowed edges == 0) --
 *      the mass a COMBINED sub-floor variant would demote.  Ratio
 *      against frontier_silent_picks is the projected silent-regime
 *      pick share the demote reclaims.
 *   frontier_barren_would_skip_per_syscall[nr]
 *      Per-syscall split of the scalar above; the headline
 *      diagnostic for SHADOW_ONLY.  Read by no live-path code.
 *
 * NULL entry (out-of-range nr or empty table slot) is treated as
 * "not a barren candidate" and short-circuits before any counter
 * bump -- matches get_syscall_entry()'s out-of-range NULL contract
 * and mirrors the NULL-safe shape the sibling producer-observer
 * bitmap builder above uses.
 *
 * Outer OFF guard keeps the byte-identical pre-feature path: no
 * get_syscall_entry() lookup, no kcov_shm loads, no ring reads --
 * only the single RELAXED mode load, matching the discipline
 * frontier_satcool_spare / frontier_live_cool_spare use.
 */
void frontier_barren_demote(unsigned int syscallnr, bool do32)
{
	enum frontier_barren_demote_mode mode;
	struct syscallentry *entry;
	unsigned long calls, edges, reach;

	mode = __atomic_load_n(&frontier_barren_demote_mode,
			       __ATOMIC_RELAXED);
	if (mode == FRONTIER_BARREN_DEMOTE_MODE_OFF)
		return;
	if (kcov_shm == NULL)
		return;
	if (syscallnr >= MAX_NR_SYSCALL)
		return;

	entry = get_syscall_entry(syscallnr, do32);
	if (entry == NULL)
		return;
	if (entry->num_args != 0)
		return;
	if (entry->ret_objtype != OBJ_NONE)
		return;
	if (entry->sanitise != NULL)
		return;

	/* Single hoisted per_syscall_edges load: the reach comparison and
	 * the "lifetime edges == 0" full-predicate check both consume the
	 * same lifetime count, and reloading under RELAXED atomics would
	 * open a race window where reach reads > MAX_REACH but a second
	 * load reads 0 (or vice versa) and races the candidates/would_skip
	 * cascade out of lock-step.  One load, both checks. */
	edges = per_syscall_edges_total(syscallnr);
	reach = edges + per_syscall_edges_prior_total(syscallnr);
	if (reach > FRONTIER_BARREN_MAX_REACH)
		return;

	calls = per_syscall_calls_total(syscallnr);
	if (calls <= FRONTIER_BARREN_C_MIN)
		return;

	__atomic_fetch_add(&shm->stats.frontier.saturation.barren_candidates,
			   1UL, __ATOMIC_RELAXED);

	if (edges != 0)
		return;
	if (frontier_recent_count(syscallnr) != 0)
		return;

	__atomic_fetch_add(&shm->stats.frontier.saturation.barren_would_skip,
			   1UL, __ATOMIC_RELAXED);
	__atomic_fetch_add(
		&shm->stats.frontier.per_syscall.barren_would_skip_per_syscall[syscallnr],
		1UL, __ATOMIC_RELAXED);

	/*
	 * COMBINED sub-floor demote would sit here gated on mode ==
	 * COMBINED, swapping the caller's silent-branch accept
	 * denominator to (FRONTIER_COLD_SCALE * FRONTIER_BARREN_DEMOTE_
	 * MULT + 1); intentionally NOT wired in this commit.  The
	 * block is observability-only regardless of mode so the
	 * SHADOW_ONLY counters can be validated against a real run
	 * before any live divergence is introduced.  See the enum
	 * comment in include/strategy.h for the ramp discipline.
	 */
}

/*
 * SHADOW-ONLY LIVE-regime cooldown discriminator, sibling of
 * frontier_satcool_spare above.  Reuses the shared spare-lane decide
 * function so the lane logic stays in one place; the differences are
 * the outer mode gate (frontier_live_cooldown_mode), the magnitude
 * floor (FRONTIER_LIVE_COOL_CMIN ~256, NOT FRONTIER_SATCOOL_CMIN
 * 10000 -- see include/strategy.h for the low-floor rationale), and
 * the shadow counter family the bumps land in (frontier_live_cool_*).
 *
 * Called from the LIVE-regime miss-attribution path in random-syscall.c
 * inside the existing (streak >= FRONTIER_LIVE_MISS_COOLDOWN) branch,
 * right next to the undiscriminated frontier_live_would_skip projection
 * the existing F3 shadow row bumps.  The pairing puts the
 * undiscriminated and discriminated demote-mass projections in the
 * same stats dump so (live_cool_would_skip / live_would_skip) reads
 * off exactly how much over-cool the discriminator removes -- the
 * SHADOW_ONLY measurement the ramp discipline needs before flipping
 * COMBINED.
 *
 * Windowed-edges spare is bumped explicitly (NOT folded into an early
 * return like the satcool wrapper does) because the bpf-class backstop
 * is exactly the LIVE-regime over-cool the discriminator is meant to
 * catch: a syscall whose K-window ring is nonzero is recently
 * productive even after a 4-pick miss-streak, and the per-syscall
 * would-spare attribution needs to record THAT as a spare reason so
 * the operator can see the bpf / openat / io_uring_setup productive
 * set surfacing on the spare side of the partition.  See the design
 * note's §3.2 (c) "frontier_recent_count > 0 bpf backstop" lane.
 *
 * SHADOW-ONLY by construction: the helper computes the discriminator
 * and bumps the frontier_live_cool_* shadow counters but never reaches
 * a live reject at the call site -- the existing F3 frontier_live_
 * would_skip + frontier_live_would_skip_per_syscall[] bumps still run
 * unconditionally regardless of this mode, so the LIVE-regime picker
 * decision stays byte-identical to the pre-row baseline.  Wiring the
 * COMBINED live divergence (rotation-loop halving in frontier_window_
 * advance gated on the discriminator + per-syscall miss-attribution
 * reject) is a deliberate follow-up after a SHADOW_ONLY run validates
 * the demote mass concentrates on gettid / sched_get_priority_max and
 * is ~0 on bpf / io_uring_setup / openat / io_setup / futex /
 * setxattrat.
 *
 * Outer guard keeps the OFF path byte-identical to a build before the
 * row: no kcov_shm load, no spare-lane evaluation, no atomic loads
 * beyond the single RELAXED mode read.  The MAX_NR_SYSCALL bound
 * matches the surrounding per-syscall arrays at the call site so the
 * per-syscall would-skip / would-spare array indices are safe.
 */
void frontier_live_cool_spare(unsigned int syscallnr, bool do32)
{
	enum frontier_live_cooldown_mode live_mode;
	enum frontier_spare_reason reason;
	unsigned long calls_total;

	live_mode = __atomic_load_n(&frontier_live_cooldown_mode,
				    __ATOMIC_RELAXED);
	if (live_mode == FRONTIER_LIVE_COOLDOWN_MODE_OFF)
		return;
	if (kcov_shm == NULL)
		return;
	if (syscallnr >= MAX_NR_SYSCALL)
		return;

	/*
	 * Low live floor.  Productive syscalls the LIVE-regime cooldown
	 * over-cools today (bpf / openat / io_uring_setup / io_setup /
	 * futex / setxattrat) sit at 775..2813 calls/run -- far below the
	 * satcool FRONTIER_SATCOOL_CMIN 10000, so reusing CMIN as the
	 * gate here would filter them OUT of the spare-lane evaluation
	 * (sparing them for the wrong reason -- low magnitude rather than
	 * productivity) and would simultaneously leave the legitimately-
	 * barren gettid (9.5k) UNDER the gate so the live cooldown could
	 * never fire on it.  The low floor (~256) admits the gettid /
	 * sched_get_priority_max getters into the discriminator while
	 * keeping a syscall with only a handful of picks out -- the
	 * spare lanes (NOT the magnitude) protect the producers.
	 */
	calls_total = per_syscall_calls_total(syscallnr);
	if (calls_total < FRONTIER_LIVE_COOL_CMIN)
		return;

	reason = frontier_spare_lane_decide(syscallnr, do32);

	__atomic_fetch_add(&shm->stats.frontier.discriminator.live_cool_candidates,
			   1UL, __ATOMIC_RELAXED);

	switch (reason) {
	case FRONTIER_SPARE_WINDOWED_EDGES:
		__atomic_fetch_add(
			&shm->stats.frontier.discriminator.live_cool_spared_windowed,
			1UL, __ATOMIC_RELAXED);
		__atomic_fetch_add(
			&shm->stats.frontier.discriminator.live_cool_would_spare_per_syscall[syscallnr],
			1UL, __ATOMIC_RELAXED);
		break;
	case FRONTIER_SPARE_ARGGEN:
		__atomic_fetch_add(
			&shm->stats.frontier.discriminator.live_cool_spared_arggen,
			1UL, __ATOMIC_RELAXED);
		__atomic_fetch_add(
			&shm->stats.frontier.discriminator.live_cool_would_spare_per_syscall[syscallnr],
			1UL, __ATOMIC_RELAXED);
		break;
	case FRONTIER_SPARE_OBJPRODUCER:
		__atomic_fetch_add(
			&shm->stats.frontier.discriminator.live_cool_spared_objproducer,
			1UL, __ATOMIC_RELAXED);
		__atomic_fetch_add(
			&shm->stats.frontier.discriminator.live_cool_would_spare_per_syscall[syscallnr],
			1UL, __ATOMIC_RELAXED);
		break;
	case FRONTIER_SPARE_NONE:
	default:
		__atomic_fetch_add(&shm->stats.frontier.discriminator.live_cool_would_skip,
				   1UL, __ATOMIC_RELAXED);
		__atomic_fetch_add(
			&shm->stats.frontier.discriminator.live_cool_would_skip_per_syscall[syscallnr],
			1UL, __ATOMIC_RELAXED);
		/*
		 * COMBINED live cooldown divergence would sit here gated on
		 * live_mode == COMBINED; intentionally NOT wired in this
		 * commit.  The block is observability-only regardless of
		 * mode so the SHADOW_ONLY counter distribution can be
		 * validated against a real run before any live decision is
		 * gated on the discriminator.  See the enum comment in
		 * include/strategy.h for the ramp discipline.
		 */
		break;
	}
}

/*
 * SHADOW-ONLY Path-A "regular_suppressed" classifier + shadow bump.
 * Sibling of frontier_satcool_spare / frontier_live_cool_spare above;
 * lives in the same translation unit so it can consume the file-static
 * frontier_spare_lane_decide() predicate body (windowed-edges plateau
 * spare, distinct-CMP / first-success-TRANSITION arggen spare,
 * ret_objtype producer-observer spare) without duplicating the lane
 * logic or growing a private exception list.
 *
 * The observed axis is orthogonal to cost: cost partitions on the
 * static EXPENSIVE bit (the sibling cost_pool_selector_shadow_note
 * observer), context partitions on empirical per-syscall EPERM
 * behaviour.  A syscall clears the classifier when its run-persistent
 * kcov counters say it is regular-dead -- lifetime call sample past
 * the CONTEXT_REGULAR_SUPPRESSED_CMIN magnitude floor, ZERO success
 * observations, ZERO edge observations, EPERM bucket dominating
 * >= CONTEXT_REGULAR_SUPPRESSED_EPERM_PCT of the total return
 * distribution -- AND the shared spare-lane decide function returns
 * FRONTIER_SPARE_NONE at the same pick, so a syscall the K-window ring
 * says is recently productive (or one mid-CMP-insert / mid-first-
 * success transition) is spared from the would_skip attribution
 * regardless of the lifetime EPERM aggregate.
 *
 * Called from the pick-finalise site in random_syscall/pickers.c on
 * both the HEURISTIC and RANDOM arms, alongside the sibling
 * cost_pool_selector_live_note attribution so the finalised-pick
 * cadence is shared and the (would_skip / candidates) ratio reads
 * directly off the finalised-pick population without an attempt-vs-
 * finalise skew.  SHADOW-ONLY by construction: this helper computes
 * the classifier + spare cascade and bumps the context_regular_
 * suppressed_* shadow counters but NEVER touches the picker's accept
 * distribution -- selection in set_syscall_nr_heuristic() and
 * set_syscall_nr_random() stays byte-identical to a build before the
 * row for a given seed, regardless of which non-OFF mode is selected.
 * Wiring the COMBINED live suppression (deactivate_syscall_locked on
 * the regular_suppressed subset out of the regular cost pools) is a
 * deliberate follow-up after a SHADOW_ONLY run validates the
 * classifier's demote mass concentrates on the measured EPERM hogs
 * (fchown / chown / lchown / fchownat + the cred family as seen at
 * uid 1026) and is ~0 on syscalls with unprivileged regular value.
 *
 * Outer guard keeps the OFF path byte-identical to a build before the
 * row: no kcov_shm load, no counter loads, no spare-lane evaluation,
 * no atomic bumps beyond the single RELAXED mode read.  The
 * MAX_NR_SYSCALL bound matches the sibling helpers' bounds so the
 * per-syscall would-skip array index is safe.
 *
 * All counter loads RELAXED: a mixed snapshot across non-atomic
 * instants at most produces a one-pick mis-classification -- the same
 * one-window attribution slack the sibling shadow helpers already
 * document.  Overflow discipline: the percentage comparison is written
 * as (eperm * 100) >= (total * PCT) so the multiplication cannot
 * observe an unsigned-subtraction wrap even under a pathological
 * counter reset mid-load; total is bounded by lifetime pick count
 * which fits comfortably below ULONG_MAX / 100 for any run length that
 * matters.
 */
void context_regular_suppressed_shadow(unsigned int syscallnr, bool do32)
{
	enum context_pool_mode mode;
	enum frontier_spare_reason reason;
	unsigned long calls_total, edges_total;
	unsigned long eperm, success;

	mode = __atomic_load_n(&context_pool_mode, __ATOMIC_RELAXED);
	if (mode == CONTEXT_POOL_MODE_OFF)
		return;
	if (kcov_shm == NULL)
		return;
	if (syscallnr >= MAX_NR_SYSCALL)
		return;

	calls_total = per_syscall_calls_total(syscallnr);
	if (calls_total < CONTEXT_REGULAR_SUPPRESSED_CMIN)
		return;

	/*
	 * Strict success / edges gates first -- a single first-success
	 * bucket entry or a single edge observation is hard disproof of
	 * the "regular-dead" classification and short-circuits the whole
	 * predicate cheaply before the spare-lane load.  Ordered success
	 * -> edges -> EPERM so the cheapest disproof gets first crack.
	 */
	success = __atomic_load_n(
		&kcov_shm->per_syscall_errno[syscallnr][ERRNO_BUCKET_SUCCESS],
		__ATOMIC_RELAXED);
	if (success != 0)
		return;

	edges_total = per_syscall_edges_total(syscallnr);
	if (edges_total != 0)
		return;

	eperm = __atomic_load_n(
		&kcov_shm->per_syscall_errno[syscallnr][ERRNO_BUCKET_EPERM],
		__ATOMIC_RELAXED);
	if ((eperm * 100UL) <
	    (calls_total * CONTEXT_REGULAR_SUPPRESSED_EPERM_PCT))
		return;

	__atomic_fetch_add(&shm->stats.context_regular_suppressed_candidates,
			   1UL, __ATOMIC_RELAXED);

	reason = frontier_spare_lane_decide(syscallnr, do32);

	switch (reason) {
	case FRONTIER_SPARE_WINDOWED_EDGES:
		__atomic_fetch_add(
			&shm->stats.context_regular_suppressed_spared_windowed,
			1UL, __ATOMIC_RELAXED);
		break;
	case FRONTIER_SPARE_ARGGEN:
		__atomic_fetch_add(
			&shm->stats.context_regular_suppressed_spared_arggen,
			1UL, __ATOMIC_RELAXED);
		break;
	case FRONTIER_SPARE_OBJPRODUCER:
		__atomic_fetch_add(
			&shm->stats.context_regular_suppressed_spared_objproducer,
			1UL, __ATOMIC_RELAXED);
		break;
	case FRONTIER_SPARE_NONE:
	default:
		__atomic_fetch_add(
			&shm->stats.context_regular_suppressed_would_skip,
			1UL, __ATOMIC_RELAXED);
		__atomic_fetch_add(
			&shm->stats.context_regular_suppressed_would_skip_per_syscall[syscallnr],
			1UL, __ATOMIC_RELAXED);
		/*
		 * COMBINED live suppression would sit here gated on mode ==
		 * COMBINED; intentionally NOT wired in this commit.  The
		 * block is observability-only regardless of mode so the
		 * SHADOW_ONLY counter distribution can be validated against
		 * a real run before any live regular-pool deactivation is
		 * gated on the classifier.  See the enum comment in
		 * include/strategy.h for the ramp discipline.
		 */
		break;
	}
}
