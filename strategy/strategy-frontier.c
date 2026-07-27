/*
 * Per-syscall frontier-edge ring accessors.  Split from strategy.c
 * so the frontier code compiles independently of the bandit / picker
 * / plateau / cmp-novelty translation units.
 */

#include <limits.h>
#include <sched.h>		/* sched_yield */
#include <stdbool.h>
#include <stdint.h>

#include "arch.h"		/* biarch */
#include "child.h"		/* struct childdata */
#include "cred_throttle.h"	/* cred_class_for_nr, CRED_CLASS_NR */
#include "kcov.h"
#include "object-types.h"	/* OBJ_NONE */
#include "shm.h"
#include "stats.h"
#include "strategy.h"
#include "syscall.h"		/* MAX_NR_SYSCALL */
#include "tables.h"		/* syscalls / syscalls_32bit / syscalls_64bit */

#include "strategy-frontier-internal.h"

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
	 * edge-triggers in random_syscall/pick-frontier.c's silent-regime accept site
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
			&kcov_shm->per_syscall_cmp.per_syscall_cmp_inserts[nr],
			__ATOMIC_RELAXED);
		errno_snap = __atomic_load_n(
			&kcov_shm->errno_state.per_syscall_errno[nr][ERRNO_BUCKET_SUCCESS],
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
 * Caller-side gates (in random_syscall/dispatch.c at the kcov_collect call
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
			&kcov_shm->per_syscall_cmp.per_syscall_cmp_inserts[nr],
			__ATOMIC_RELAXED);
		errno_snap = __atomic_load_n(
			&kcov_shm->errno_state.per_syscall_errno[nr][ERRNO_BUCKET_SUCCESS],
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
	cmp_inserts = __atomic_load_n(&kcov_shm->per_syscall_cmp.per_syscall_cmp_inserts[nr],
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
		&kcov_shm->transitions.per_syscall_transition_edges_real_local[nr],
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
			&kcov_shm->errno_state.per_syscall_errno[nr][bucket],
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
		&kcov_shm->errno_state.per_syscall_errno[syscallnr][ERRNO_BUCKET_SUCCESS],
		__ATOMIC_RELAXED);
	if (success != 0)
		return;

	edges_total = per_syscall_edges_total(syscallnr);
	if (edges_total != 0)
		return;

	eperm = __atomic_load_n(
		&kcov_shm->errno_state.per_syscall_errno[syscallnr][ERRNO_BUCKET_EPERM],
		__ATOMIC_RELAXED);
	if ((eperm * 100UL) <
	    (calls_total * CONTEXT_REGULAR_SUPPRESSED_EPERM_PCT))
		return;

	__atomic_fetch_add(&shm->stats.context_suppress.candidates,
			   1UL, __ATOMIC_RELAXED);

	reason = frontier_spare_lane_decide(syscallnr, do32);

	switch (reason) {
	case FRONTIER_SPARE_WINDOWED_EDGES:
		__atomic_fetch_add(
			&shm->stats.context_suppress.spared_windowed,
			1UL, __ATOMIC_RELAXED);
		break;
	case FRONTIER_SPARE_ARGGEN:
		__atomic_fetch_add(
			&shm->stats.context_suppress.spared_arggen,
			1UL, __ATOMIC_RELAXED);
		break;
	case FRONTIER_SPARE_OBJPRODUCER:
		__atomic_fetch_add(
			&shm->stats.context_suppress.spared_objproducer,
			1UL, __ATOMIC_RELAXED);
		break;
	case FRONTIER_SPARE_NONE:
	default:
		__atomic_fetch_add(
			&shm->stats.context_suppress.would_skip,
			1UL, __ATOMIC_RELAXED);
		__atomic_fetch_add(
			&shm->stats.context_suppress.would_skip_per_syscall[syscallnr],
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
