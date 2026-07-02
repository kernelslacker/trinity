/*
 * Call a single random syscall with random args.
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
#include "strategy.h"
#include "syscall.h"
#include "syscall_record.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

/* The per-pending-index success counter in kcov_shared is sized off
 * REEXEC_PENDING_PICK_HIST_NR (include/kcov.h); the per-call attribution
 * buffer it indexes is sized off MAX_REEXEC_PENDING (include/cmp_hints.h).
 * They MUST stay equal -- a wider counter under-uses the kcov_shm field
 * and a narrower one would let the clamped index drop the last slots'
 * success signal on the floor.  kcov.h does not include cmp_hints.h
 * (to stay self-contained), so the parity check lives here, where both
 * headers are in scope. */
_Static_assert(REEXEC_PENDING_PICK_HIST_NR == MAX_REEXEC_PENDING,
	       "REEXEC_PENDING_PICK_HIST_NR must equal MAX_REEXEC_PENDING");

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

/*
 * Adaptive remote-KCOV mode disposition for the upcoming dispatch.
 * Reads the per-syscall mode-keyed yield counters bumped in
 * kcov_collect() (remote_pc_calls / remote_pc_edge_calls /
 * local_pc_calls / local_pc_edge_calls in struct kcov_shared) and
 * returns the adaptive remote_mode the upcoming call should run with;
 * the caller threads that through the per-child Arm A/B gate so Arm A
 * stays byte-identical to the static policy.
 *
 * Three dispositions can fire, mutually exclusive on the
 * (entry->flags & KCOV_REMOTE_HEAVY) axis (DEMOTE on the HEAVY path,
 * PROMOTE and FORCE on the non-HEAVY path; PROMOTE pre-empts FORCE):
 *
 *   DEMOTE  fires only on HEAVY-flagged syscalls whose static decision
 *           was remote_mode==true and whose lifetime remote_pc_calls
 *           has crossed REMOTE_ADAPTIVE_MIN_REMOTE_CALLS without ever
 *           producing a single remote_pc_edge_calls bump.  The HEAVY
 *           rate (1-in-2) is wasted on that syscall in this kernel
 *           and the adaptive policy flips remote_mode to false so the
 *           call lands on the local PC fd instead.
 *
 *   PROMOTE fires only on unflagged syscalls whose static decision was
 *           remote_mode==false, whose lifetime remote AND local samples
 *           have BOTH crossed their MIN_*_CALLS sample floors, whose
 *           remote sample produced at least one edge, AND whose remote
 *           edge rate beats the local edge rate by the configured
 *           REMOTE_ADAPTIVE_PROMOTE_MARGIN_NUM/PROMOTE_MARGIN_DEN
 *           relative margin.  The comparison is performed via cross-
 *           multiplication so neither rate has to be divided -- the
 *           naive form
 *
 *               remote_edge_calls / remote_pc_calls
 *                 > local_edge_calls / local_pc_calls
 *
 *           is replaced by
 *
 *               remote_edge_calls * local_pc_calls * MARGIN_DEN
 *                 > local_edge_calls  * remote_pc_calls * MARGIN_NUM
 *
 *           which is equivalent in the positive denominators the
 *           MIN_*_CALLS gates guarantee and never divides.  Both
 *           products are checked with __builtin_mul_overflow; on
 *           overflow the promote disposition is suppressed (treated as
 *           agree with static) so a long run with very large counters
 *           cannot silently wrap into a false promote.
 *
 *   FORCE   fires only when the parent-published plateau hypothesis
 *           is PLATEAU_HYPOTHESIS_REMOTE_DOMINANT AND the unflagged-
 *           path PROMOTE disposition did NOT already fire on this
 *           call AND the syscall's lifetime remote sample has crossed
 *           the looser REMOTE_ADAPTIVE_PLATEAU_FORCE_MIN_REMOTE_CALLS
 *           floor AND its lifetime remote_pc_edge_calls is at least
 *           REMOTE_ADAPTIVE_PLATEAU_FORCE_MIN_EDGES (ever yielded).
 *           Widens promote during the plateau emergency: a remote-
 *           dominant plateau is direct evidence the fleet is making
 *           forward progress via remote sampling, so a proven remote
 *           yielder is worth keeping in the remote pool even before
 *           its rate has cleared the PROMOTE_MARGIN bar.  The HEAVY
 *           DEMOTE branch is intentionally NOT widened (see the
 *           constant block in include/kcov.h for the rationale).
 *
 * SHADOW: bump one of remote_adaptive_{would_demote, would_promote,
 * would_force, agree} per call and bump remote_adaptive_samples once.
 * The bumps happen unconditionally on the helper entry path so both
 * A/B arms contribute to the same denominator and the would-be
 * divergence stays observable on Arm A (the control cohort) too.
 *
 * Returns the static decision verbatim when kcov_shm is unavailable or
 * nr is out of range -- matches the kcov-less fallback the rest of the
 * file already takes (see frontier_cold_weight above for the sibling
 * pattern).
 */
static bool remote_adaptive_decide(unsigned int nr,
				   struct syscallentry *entry,
				   bool static_remote)
{
	unsigned long rcalls, redgec, lcalls, ledgec;
	bool would_demote = false, would_promote = false, would_force = false;
	bool would_gate_promote = false;
	bool adaptive_remote = static_remote;

	if (kcov_shm == NULL || nr >= MAX_NR_SYSCALL || entry == NULL)
		return static_remote;

	rcalls = __atomic_load_n(&kcov_shm->remote_pc_calls[nr],
				 __ATOMIC_RELAXED);
	redgec = __atomic_load_n(&kcov_shm->remote_pc_edge_calls[nr],
				 __ATOMIC_RELAXED);
	lcalls = __atomic_load_n(&kcov_shm->local_pc_calls[nr],
				 __ATOMIC_RELAXED);
	ledgec = __atomic_load_n(&kcov_shm->local_pc_edge_calls[nr],
				 __ATOMIC_RELAXED);

	if ((entry->flags & KCOV_REMOTE_HEAVY) && static_remote) {
		/* Demote: HEAVY syscall, static says remote, but the
		 * lifetime evidence is that remote sampling on this
		 * syscall has produced zero edges across enough samples
		 * to be confident.  Flip to local. */
		if (rcalls >= REMOTE_ADAPTIVE_MIN_REMOTE_CALLS &&
		    redgec == 0) {
			adaptive_remote = false;
			would_demote = true;
		}
	} else if (!(entry->flags & KCOV_REMOTE_HEAVY) && !static_remote) {
		/* Promote: not HEAVY, static says local, but the
		 * lifetime evidence is that remote sampling on this
		 * syscall has out-yielded local by the configured
		 * margin.  Both sample-size floors must be met and the
		 * remote sample must have produced at least one edge --
		 * otherwise the numerator is zero and the rate
		 * comparison is uninformative. */
		if (rcalls >= REMOTE_ADAPTIVE_MIN_REMOTE_CALLS &&
		    lcalls >= REMOTE_ADAPTIVE_MIN_LOCAL_CALLS &&
		    redgec > 0) {
			unsigned long lhs, rhs = 0;
			bool ok;

			ok = !__builtin_mul_overflow(redgec, lcalls, &lhs);
			if (ok)
				ok = !__builtin_mul_overflow(
					lhs,
					REMOTE_ADAPTIVE_PROMOTE_MARGIN_DEN,
					&lhs);
			if (ok)
				ok = !__builtin_mul_overflow(
					ledgec, rcalls, &rhs);
			if (ok)
				ok = !__builtin_mul_overflow(
					rhs,
					REMOTE_ADAPTIVE_PROMOTE_MARGIN_NUM,
					&rhs);
			if (ok && lhs > rhs) {
				adaptive_remote = true;
				would_promote = true;

				/* Shadow plateau-gate evaluation: the
				 * proposed live gate would suppress this
				 * promote unless the current plateau
				 * hypothesis is REMOTE_DOMINANT.  Sample
				 * the parent-published hypothesis via
				 * shm (same read pattern as the
				 * CMP_RISING_PC_FLAT consumer in
				 * dispatch_step's REDQUEEN gate -- the
				 * strategy.c-internal static is parent-
				 * private and stays stale across the
				 * fork boundary).  Live disposition is
				 * not touched; the counter only records
				 * how often the gate would diverge from
				 * the current always-promote behaviour
				 * once it is flipped on by default. */
				if (__atomic_load_n(
					    &shm->plateau_current_hypothesis,
					    __ATOMIC_RELAXED) !=
				    PLATEAU_HYPOTHESIS_REMOTE_DOMINANT)
					would_gate_promote = true;
			}
		}

		/* Plateau-aware widening of the promote branch.  Only
		 * runs when the regular promote check did NOT already
		 * fire on this call (would_promote == false) so the
		 * disposition counters stay mutually exclusive; the
		 * mid-call sample of the parent-published plateau
		 * hypothesis matches the shadow-gate read above so the
		 * two predicates see the same hypothesis value.  Sample
		 * floors are deliberately looser than the regular
		 * promote rule's: see the constant block in
		 * include/kcov.h for the per-floor justification. */
		if (!would_promote &&
		    rcalls >= REMOTE_ADAPTIVE_PLATEAU_FORCE_MIN_REMOTE_CALLS &&
		    redgec >= REMOTE_ADAPTIVE_PLATEAU_FORCE_MIN_EDGES &&
		    __atomic_load_n(&shm->plateau_current_hypothesis,
				    __ATOMIC_RELAXED) ==
		    PLATEAU_HYPOTHESIS_REMOTE_DOMINANT) {
			adaptive_remote = true;
			would_force = true;
		}
	}

	__atomic_fetch_add(&shm->stats.remote_adaptive_samples, 1UL,
			   __ATOMIC_RELAXED);
	if (would_demote)
		__atomic_fetch_add(&shm->stats.remote_adaptive_would_demote,
				   1UL, __ATOMIC_RELAXED);
	else if (would_promote)
		__atomic_fetch_add(&shm->stats.remote_adaptive_would_promote,
				   1UL, __ATOMIC_RELAXED);
	else if (would_force)
		__atomic_fetch_add(&shm->stats.remote_adaptive_would_force,
				   1UL, __ATOMIC_RELAXED);
	else
		__atomic_fetch_add(&shm->stats.remote_adaptive_agree, 1UL,
				   __ATOMIC_RELAXED);

	if (would_gate_promote)
		__atomic_fetch_add(
			&shm->stats.remote_adaptive_would_gate_promote,
			1UL, __ATOMIC_RELAXED);

	return adaptive_remote;
}

/*
 * Check the rotation boundary and, if crossed, atomically claim the
 * switch and update shm->current_strategy to whatever the configured
 * picker (round-robin or UCB1 bandit, see strategy.h) selects next.
 *
 * The rotation clock is shm_published->fleet_op_count, which mirrors
 * the parent-private fleet op_count (every child contributes ticks at
 * the same rate, including non-syscall alt-ops).  A child that observes
 * (op_count - syscalls_at_last_switch) >= STRATEGY_WINDOW tries to CAS
 * syscalls_at_last_switch forward to the current op_count; the CAS
 * winner performs the switch and emits the
 * stats line, the losers fall through and continue with the new strategy
 * on their next syscall pick.
 *
 * Per-strategy attribution: the just-finished window's call-count delta
 * is pc_edge_calls_by_strategy[prev] - pc_edge_calls_at_window_start and
 * the parallel real bucket-count delta is pc_edge_count_by_strategy[prev]
 * - pc_edge_count_at_window_start.  After the switch, both *at_window_start
 * snapshots are reseeded from the new strategy's current cumulative
 * counters, so the next switch will compute the deltas correctly even if
 * other strategies' counters are bumped during the grace period.
 */
static void maybe_rotate_strategy(void)
{
	unsigned long now;
	unsigned long last;
	int prev, next;
	int prev_reason_raw;
	enum strategy_selection_reason prev_reason;
	enum strategy_selection_reason next_reason = SR_NORMAL_UCB;
	unsigned long calls_now, calls_in_window;
	unsigned long edges_now, edges_in_window;
	unsigned long syscalls_in_window;
	unsigned long cmp_now, cmp_in_window;
	unsigned long warn_now = 0;
	unsigned long warn_in_window = 0;
	bool was_chaos;

	/* Read fleet op_count off the parent-published mirror page; the
	 * canonical aggregate is parent-private and not visible to children.
	 * The mirror is republished once per parent main_loop iteration so
	 * a stale read here only delays the rotation by drain cadence. */
	now = (shm_published != NULL)
	      ? __atomic_load_n(&shm_published->fleet_op_count, __ATOMIC_RELAXED)
	      : 0;
	last = __atomic_load_n(&shm->syscalls_at_last_switch, __ATOMIC_RELAXED);

	/* Tighten the rotation window while the plateau detector is latched
	 * on, so the plateau-intervention layer (SR_PLATEAU_FORCE etc.) re-
	 * applies many times inside one 600s detector window rather than
	 * ~1.6 times.  ACQUIRE pairs with the parent's RELEASE-store of
	 * plateau_active in kcov_plateau_check(); kcov_shm may be NULL when
	 * kcov is disabled, fall back to the healthy-run cadence. */
	{
		unsigned long window = STRATEGY_WINDOW;

		if (kcov_shm != NULL &&
		    __atomic_load_n(&kcov_shm->plateau_active,
				    __ATOMIC_ACQUIRE))
			window = PLATEAU_STRATEGY_WINDOW;

		if (now - last < window)
			return;
	}

	if (!__atomic_compare_exchange_n(&shm->syscalls_at_last_switch,
					 &last, now,
					 false,
					 __ATOMIC_RELAXED, __ATOMIC_RELAXED))
		return;

	prev = __atomic_load_n(&shm->current_strategy, __ATOMIC_RELAXED);
	if (prev < 0 || prev >= NR_STRATEGIES)
		prev = STRATEGY_HEURISTIC;

	/* Selection reason for the just-finished window -- the intervention
	 * orchestrator stamped this when it picked prev.  Treated as raw int
	 * across the shm boundary and re-validated here so a wild write
	 * landing on the field falls back to the "policy chose this" path
	 * rather than skipping the learner update spuriously. */
	prev_reason_raw = __atomic_load_n(&shm->current_selection_reason,
					  __ATOMIC_RELAXED);
	switch (prev_reason_raw) {
	case SR_NORMAL_UCB:
	case SR_ROUND_ROBIN:
	case SR_COLD_START:
	case SR_PLATEAU_FORCE:
		prev_reason = (enum strategy_selection_reason)prev_reason_raw;
		break;
	default:
		prev_reason = SR_NORMAL_UCB;
		break;
	}

	calls_now = __atomic_load_n(&shm->pc_edge_calls_by_strategy[prev],
				    __ATOMIC_RELAXED);
	calls_in_window = calls_now -
		__atomic_load_n(&shm->pc_edge_calls_at_window_start,
				__ATOMIC_RELAXED);
	edges_now = __atomic_load_n(&shm->pc_edge_count_by_strategy[prev],
				    __ATOMIC_RELAXED);
	edges_in_window = edges_now -
		__atomic_load_n(&shm->pc_edge_count_at_window_start,
				__ATOMIC_RELAXED);
	syscalls_in_window = now - last;

	/* CMP-novelty delta: number of comparison constants the active arm
	 * exposed for the first time within CMP_NOVELTY_DECAY_WINDOWS this
	 * window.  Folded into the bandit reward by bandit_record_pull as
	 * a 0.25-weight secondary signal so an arm whose PC growth has
	 * plateaued but whose validation surface is still mutating doesn't
	 * lose to a noisier arm on PC delta alone. */
	cmp_now = __atomic_load_n(&shm->bandit_cmp_new_constants[prev],
				  __ATOMIC_RELAXED);
	cmp_in_window = cmp_now -
		__atomic_load_n(&shm->bandit_cmp_at_window_start,
				__ATOMIC_RELAXED);

	/* WARN-fires delta + chaos-cohort snapshot for the chaos-mode V2
	 * attribution.  warn_now reads the live counter kmsg-monitor bumps
	 * on every classified kernel diagnostic; the at-window-start
	 * snapshot was reseeded at the bottom of the previous rotation (or
	 * is zero on the very first window).  was_chaos samples
	 * cmp_hints_chaos_active BEFORE cmp_hints_chaos_tick advances the
	 * schedule below, so it reflects the chaos state that was in effect
	 * across the just-finished window -- which is the cohort the delta
	 * should be attributed to.  Skipped when kcov_shm is NULL (kcov
	 * unavailable, no kmsg counter to read): the delta is zero and the
	 * cohort sample becomes a no-op for that window. */
	if (kcov_shm != NULL) {
		warn_now = __atomic_load_n(&kcov_shm->kmsg_warn_fires,
					   __ATOMIC_RELAXED);
		warn_in_window = warn_now -
			__atomic_load_n(&shm->kmsg_warn_fires_at_window_start,
					__ATOMIC_RELAXED);
	} else {
		warn_in_window = 0UL;
	}
	was_chaos = cmp_hints_chaos_query();

	/* Feed the just-finished window into the bandit before asking
	 * the picker to choose the next arm, so UCB1 sees up-to-date
	 * pulls/reward when scoring.  The learner consumes the call-count
	 * delta as today; the real bucket-count delta is recorded into the
	 * parallel diagnostic reward series so the operator can compare the
	 * two reward shapes without changing the learner's behaviour.
	 * Round-robin mode ignores the counters but the bookkeeping is
	 * harmless and lets the end-of-run summary print pulls under either
	 * picker.
	 *
	 * Called on EVERY window including SR_PLATEAU_FORCE.  The
	 * per-arm-per-reason bucketing inside bandit_record_pull captures
	 * every cohort (forced included) so dump-side analysis can split
	 * each arm's exposure by selection path, while the learner-facing
	 * update (bandit_pulls[] / bandit_reward_calls[] / EMA) skips
	 * SR_PLATEAU_FORCE internally to keep the UCB scorer's view of
	 * RANDOM uncontaminated.  All other bookkeeping
	 * (bandit_window_count tick, frontier ring advance, window-start
	 * snapshot reseed) runs unconditionally -- those are coverage-side
	 * structures and must stay aligned with the rotation cadence. */
	bandit_record_pull(prev, prev_reason, calls_in_window,
			   edges_in_window, cmp_in_window,
			   warn_in_window, was_chaos);

	/* Tick the rotation counter so bandit_cmp_observe()'s per-syscall
	 * bloom decay sees the new window index on subsequent calls.
	 * Bumped after bandit_record_pull so a concurrent observer racing
	 * the rotation either sees the old (still-valid) window or the
	 * fresh one — both attribute correctly. */
	__atomic_fetch_add(&shm->bandit_window_count, 1UL, __ATOMIC_RELAXED);

	/* Roll the per-syscall frontier-edge ring forward and zero the new
	 * slot so it represents only edges discovered in the upcoming
	 * window.  Same K-window decay horizon as the CMP-novelty bloom
	 * above. */
	frontier_window_advance();

	/* Advance the cmp_hints chaos-mode window counter.  Flips the
	 * hint-suppression toggle on every CHAOS_WINDOW_MODULO'th window
	 * so random-arg generation gets a fair shot at the
	 * invalid-combination space that the kernel-validated cmp_hints
	 * pool otherwise biases away from. */
	cmp_hints_chaos_tick();

	next = select_next_strategy(prev, &next_reason);
	if (next < 0 || next >= NR_STRATEGIES) {
		next = (prev + 1) % NR_STRATEGIES;
		next_reason = SR_ROUND_ROBIN;
	}

	__atomic_store_n(&shm->pc_edge_calls_at_window_start,
			 __atomic_load_n(&shm->pc_edge_calls_by_strategy[next],
					 __ATOMIC_RELAXED),
			 __ATOMIC_RELAXED);
	__atomic_store_n(&shm->pc_edge_count_at_window_start,
			 __atomic_load_n(&shm->pc_edge_count_by_strategy[next],
					 __ATOMIC_RELAXED),
			 __ATOMIC_RELAXED);
	__atomic_store_n(&shm->bandit_cmp_at_window_start,
			 __atomic_load_n(&shm->bandit_cmp_new_constants[next],
					 __ATOMIC_RELAXED),
			 __ATOMIC_RELAXED);
	/* Reseed the transition reward window-start snapshots so the per-
	 * window delta bandit_record_pull reads on the next rotation
	 * matches the (next, this-window) cohort.  Same RELAXED cadence
	 * and single-writer ordering as the pc_edge_*_at_window_start
	 * pair above; consumed by bandit_record_pull under COMBINED mode
	 * (it folds (transition_edge_count_by_strategy[arm] - this
	 * snapshot) / TRANSITION_BANDIT_REWARD_WEIGHT_RECIPROCAL into the
	 * per-arm reward total).  Reseeded unconditionally so OFF/SHADOW_
	 * ONLY runs keep the snapshot fresh; COMBINED can be flipped on
	 * mid-run without the bandit reading a stale window-start. */
	__atomic_store_n(&shm->stats.transition_edge_count_at_window_start,
			 __atomic_load_n(&shm->stats.transition_edge_count_by_strategy[next],
					 __ATOMIC_RELAXED),
			 __ATOMIC_RELAXED);
	__atomic_store_n(&shm->stats.transition_edge_calls_at_window_start,
			 __atomic_load_n(&shm->stats.transition_edge_calls_by_strategy[next],
					 __ATOMIC_RELAXED),
			 __ATOMIC_RELAXED);
	/* Reseed the kmsg_warn_fires snapshot from the live counter (not a
	 * per-strategy mirror -- the underlying counter is global).  A
	 * future commit in this stack reads this snapshot at the top of the
	 * rotation handler to compute the per-window WARN delta and feeds
	 * it through bandit_record_pull for chaos cohort attribution.
	 * Reseeded under RELAXED matching the other *_at_window_start stores
	 * above; the snapshot tolerates a race between read and store
	 * because the delta is a coarse cohort-level signal, not a precise
	 * per-call attribution. */
	__atomic_store_n(&shm->kmsg_warn_fires_at_window_start,
			 kcov_shm != NULL ?
				 __atomic_load_n(&kcov_shm->kmsg_warn_fires,
						 __ATOMIC_RELAXED) :
				 0UL,
			 __ATOMIC_RELAXED);
	/* Publish the selection reason BEFORE current_strategy: the RELEASE
	 * store on current_strategy below pairs with the picker's and the
	 * plateau gates' ACQUIRE loads of current_strategy, making the
	 * reason and the companion plateau fields (published earlier under
	 * RELAXED in select_next_strategy) visible to any child that
	 * observes the new strategy. */
	__atomic_store_n(&shm->current_selection_reason,
			 (int)next_reason, __ATOMIC_RELAXED);
	__atomic_store_n(&shm->current_strategy, next, __ATOMIC_RELEASE);

	output(0, "strategy: switched to %s (%d) [%s] (prev %s (%d) [%s]: edge_calls=%lu, edge_count=%lu, syscalls=%lu, cmp_novel=%lu%s)\n",
	       strategy_name(next), next,
	       strategy_selection_reason_name(next_reason),
	       strategy_name(prev), prev,
	       strategy_selection_reason_name(prev_reason),
	       calls_in_window, edges_in_window, syscalls_in_window,
	       cmp_in_window,
	       prev_reason == SR_PLATEAU_FORCE ?
	       ", learner-update skipped" : "");
}

/*
 * Greedy CMP RedQueen re-exec helper.  Forward-declared so dispatch_step's
 * tail can call it; definition lives after replay_syscall_step where the
 * fresh-args-then-pin-slot story is symmetric with the replay contract.
 *
 * pending_idx is the position in child->reexec_pending[] that the
 * consumer at the dispatch_step tail picked (0..reexec_pending_count);
 * carried through to the inner_new_cmp > 0 success block so the
 * per-pending-index success counter (kcov_shm->reexec_pending_pick_success[])
 * can be bumped at the chosen index without retaining the index in
 * per-child scratch.
 */
static bool redqueen_reexec_step(struct childdata *child,
				 const struct reexec_pending *p,
				 unsigned int pending_idx);

/*
 * Dispatch a fully-prepared syscallrecord and run the per-call
 * post-dispatch bookkeeping: kcov collection / cmp-hint collection,
 * edge-pair recording, mutator-attribution commit, mini-corpus save,
 * trace output, fd-ring update, group/last_syscall_nr tracking.
 *
 * Caller has already populated rec->nr, rec->do32bit, rec->a1..a6, the
 * postbuffer is already cleared, and any chain substitution has been
 * applied.  The two callers (random_syscall_step and replay_syscall_step)
 * differ only in how they got the args into rec; everything from
 * output_syscall_prefix forward is shared.
 */

/* A/B cohort denominators for the reexec_* lift signal.
 * This is the parent CMP call: every CMP-mode child reaches
 * here exactly once per dispatch, and child->redqueen_enabled
 * is the stable per-fork stamp that partitions CMP-mode
 * children 50/50 into the enabled vs control arms.  Bumping
 * once per parent call (and accumulating new_cmp into the
 * matching cohort sum) gives the missing denominator the
 * existing reexec_* numerator counters need so the per-
 * parent-call lift question is answerable from the periodic
 * dump.  Bump unconditionally on the cohort path -- even a
 * parent call that returned new_cmp == 0 is a parent-call
 * the re-exec gate could have sampled, so excluding it would
 * bias the denominator. */
static void account_reexec_ab_cohort(struct childdata *child, unsigned long new_cmp)
{
	if (kcov_shm == NULL)
		return;

	if (child->redqueen_enabled) {
		__atomic_fetch_add(&kcov_shm->cmp_parent_calls_enabled,
				   1UL, __ATOMIC_RELAXED);
		if (new_cmp > 0)
			__atomic_fetch_add(
				&kcov_shm->cmp_parent_new_cmps_enabled,
				new_cmp, __ATOMIC_RELAXED);
	} else {
		__atomic_fetch_add(&kcov_shm->cmp_parent_calls_control,
				   1UL, __ATOMIC_RELAXED);
		if (new_cmp > 0)
			__atomic_fetch_add(
				&kcov_shm->cmp_parent_new_cmps_control,
				new_cmp, __ATOMIC_RELAXED);
	}
}

/* Per-syscall new-edge attribution split by strategy pool, plus the
 * companion frontier-yield (kill-list feedstock) accounting.  Both
 * blocks key off rec->nr / new_edge_count / frontier_pick_regime and
 * neither touches kcov_shm, so they collapse into a single helper that
 * runs immediately after the kcov-collect path.  Behaviour is the
 * sequential composition of the two original blocks.
 *
 * First block (strategy-pool split):
 *   Skipped when the call produced no new edges (the dump only
 *   consumes the positive delta side) and when rec->nr falls outside
 *   the table.  Biarch attribution follows the same raw-rec->nr
 *   indexing the existing kcov_shm->per_syscall_edges array uses; the
 *   dump iterates only the active 64-bit table when biarch, so 32-bit
 *   calls are effectively ignored there as they are everywhere else.
 *
 * Second block (frontier-yield kill-list feedstock):
 *   Reads the per-call frontier_pick_regime stamp the picker wrote at
 *   one of the two coverage-frontier accept sites; non-frontier
 *   strategy picks leave the stamp at NONE and naturally skip this
 *   whole block.  The decision is keyed off the live new_edge_count
 *   count -- a frontier pick that earned at least one PC edge bumps
 *   the regime-agnostic productive_wins counter and stamps the current
 *   rotation window into frontier_last_productive_window so the kill-
 *   list analyser can read "windows since last productive frontier
 *   pick on this syscall" without retaining a per-window time series;
 *   a LIVE-regime frontier pick that earned zero edges bumps the
 *   live_misses counter, the headline kill-list signal for "the live
 *   ring keeps biasing toward this syscall but it never converts".
 *   Silent-regime misses are NOT tallied -- silent picks are by
 *   definition operating in the plateau-fallback regime where low
 *   yield is the expected baseline and folding them into the same
 *   counter would bury the live-regime signal.
 *
 *   ADDITIVE / SHADOW: no live-path code reads any of the per-syscall
 *   frontier yield arrays; the bumps run strictly AFTER the per-call
 *   new-edge attribution decision and the picker accept/retry math is
 *   byte-identical to the pre-row baseline.  Validator-rejected calls
 *   (rec->validator_rejected = true, kcov never ran) reach here with
 *   new_edge_count = 0 forced above; treating those as live_misses
 *   would over-count the kill-list signal with picks the kernel never
 *   actually saw, so the live_miss branch additionally gates on
 *   !rec->validator_rejected.  Same MAX_NR_SYSCALL bound the sibling
 *   edges_per_syscall_bandit[] block above uses. */
static void account_per_syscall_new_edges(struct childdata *child,
					  struct syscallrecord *rec,
					  unsigned long new_edge_count)
{
	if (new_edge_count > 0 && rec->nr < MAX_NR_SYSCALL) {
		unsigned long *bucket = child->is_explorer
			? shm->stats.edges_per_syscall_explorer
			: shm->stats.edges_per_syscall_bandit;
		__atomic_fetch_add(&bucket[rec->nr], new_edge_count,
				   __ATOMIC_RELAXED);
	}

	if (child->frontier_pick_regime != FRONTIER_PICK_NONE &&
	    rec->nr < MAX_NR_SYSCALL) {
		if (new_edge_count > 0) {
			__atomic_fetch_add(
				&shm->stats.frontier_productive_wins_per_syscall[rec->nr],
				1UL, __ATOMIC_RELAXED);
			__atomic_store_n(
				&shm->stats.frontier_last_productive_window_per_syscall[rec->nr],
				__atomic_load_n(&shm->bandit_window_count,
						__ATOMIC_RELAXED),
				__ATOMIC_RELAXED);
		} else if (child->frontier_pick_regime == FRONTIER_PICK_LIVE &&
			   !rec->validator_rejected) {
			unsigned long streak;

			__atomic_fetch_add(
				&shm->stats.frontier_live_misses_per_syscall[rec->nr],
				1UL, __ATOMIC_RELAXED);

			/* SHADOW-ONLY per-syscall LIVE-regime miss-streak
			 * accounting.  Mirrors the silent-streak shadow
			 * decay block at the silent-regime accept site: the
			 * per-syscall counter advances strictly AFTER the
			 * existing live_misses bump above, and the two
			 * scalar companions edge-trigger and accumulate on
			 * the threshold-crossing pick.  Frontier_record_new_
			 * edge() / _record_transition_edge() reset the per-
			 * syscall counter on any productive event, so the
			 * streak captures the run-length of CONSECUTIVE
			 * zero-edge LIVE-regime picks of this syscall since
			 * it last earned coverage.
			 *
			 *  frontier_live_cooldown_candidates
			 *      Edge bump: fires on the (streak ==
			 *      FRONTIER_LIVE_MISS_COOLDOWN) crossing -- one
			 *      bump per distinct cooldown episode for this
			 *      syscall.
			 *  frontier_live_would_skip
			 *      Cumulative bump on every LIVE-regime miss
			 *      that lands with the post-increment streak at
			 *      or past the threshold -- the projected demote
			 *      count a live cooldown variant of the picker
			 *      would produce.
			 *
			 * Selection-byte-identical contract: the picker
			 * accept/retry math at the LIVE accept site is
			 * untouched; these bumps run strictly after the per-
			 * call attribution decision and write only NEW
			 * counters that no live-path code reads.  Same
			 * MAX_NR_SYSCALL bound the surrounding per-syscall
			 * arrays use. */
			streak = __atomic_add_fetch(
				&shm->stats.frontier_live_miss_streak_per_syscall[rec->nr],
				1UL, __ATOMIC_RELAXED);
			if (streak >= FRONTIER_LIVE_MISS_COOLDOWN) {
				__atomic_fetch_add(
					&shm->stats.frontier_live_would_skip,
					1UL, __ATOMIC_RELAXED);
				__atomic_fetch_add(
					&shm->stats.frontier_live_would_skip_per_syscall[rec->nr],
					1UL, __ATOMIC_RELAXED);

				/* SHADOW-ONLY LIVE-regime cooldown discriminator
				 * (gated by --frontier-live-cooldown-mode != off).
				 * Sits inside the same threshold-crossing branch as
				 * the F3 frontier_live_would_skip bumps above so the
				 * undiscriminated projection and the discriminated
				 * projection share the candidate gate (post-increment
				 * streak >= FRONTIER_LIVE_MISS_COOLDOWN) and the
				 * (live_cool_would_skip / live_would_skip) ratio
				 * reads off exactly how much over-cool the
				 * discriminator removes -- the SHADOW_ONLY
				 * measurement the ramp discipline needs before
				 * flipping COMBINED.  Helper applies its own outer
				 * mode gate, the FRONTIER_LIVE_COOL_CMIN low live
				 * floor (NOT FRONTIER_SATCOOL_CMIN -- see the
				 * include/strategy.h comment for the rationale), and
				 * the spare-lane evaluation; the bumps land in the
				 * frontier_live_cool_* shadow counter family and no
				 * live-path code reads them.  Same MAX_NR_SYSCALL
				 * bound the surrounding per-syscall arrays use. */
				frontier_live_cool_spare(rec->nr, rec->do32bit);
			}
			if (streak == FRONTIER_LIVE_MISS_COOLDOWN)
				__atomic_fetch_add(
					&shm->stats.frontier_live_cooldown_candidates,
					1UL, __ATOMIC_RELAXED);
		}
	}
}

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
static void account_warm_reserve(struct childdata *child,
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
		unsigned long calls = __atomic_load_n(
			&kcov_shm->per_syscall_calls[rec->nr],
			__ATOMIC_RELAXED);
		if (calls >= DEEP_WARM_PCS_MIN_CALLS) {
			unsigned long distinct_sum =
				__atomic_load_n(&kcov_shm->per_syscall_diag[rec->nr][0].distinct_pcs,
					__ATOMIC_RELAXED) +
				__atomic_load_n(&kcov_shm->per_syscall_diag[rec->nr][1].distinct_pcs,
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
		__atomic_fetch_add(&shm->stats.warm_reserve_candidates_total,
				   1UL, __ATOMIC_RELAXED);
		__atomic_fetch_add(&shm->stats.warm_reserve_candidates[rec->nr],
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
			__atomic_fetch_add(&shm->stats.warm_reserve_during_plateau_total,
					   1UL, __ATOMIC_RELAXED);
			__atomic_fetch_add(&shm->stats.warm_reserve_during_plateau[rec->nr],
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
static void account_cold_overflow_would_save(struct syscallentry *entry,
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
			&shm->stats.cold_overflow_would_save,
			1UL, __ATOMIC_RELAXED);
		if (cold)
			__atomic_fetch_add(
				&shm->stats.cold_overflow_would_save_cold,
				1UL, __ATOMIC_RELAXED);
		if (absent)
			__atomic_fetch_add(
				&shm->stats.cold_overflow_would_save_absent,
				1UL, __ATOMIC_RELAXED);
	}
}

/* PC-edge-only bookkeeping.  Deliberately separate from the
 * found_something save block back in dispatch_step so CMP-source saves
 * can't trigger snapshot cadence, per-strategy edge attribution, or
 * pool edge counters -- see the new_edges/new_cmp gating comment for
 * why those must stay PC-only.
 *
 * Gated on new_edges (caller short-circuits in the !new_edges hot
 * path).  Three pieces, in execution order:
 *   - minicorpus_maybe_snapshot()   -- coverage-delta-triggered
 *                                       persistence cadence
 *   - explorer/bandit pool split    -- per-strategy edge attribution
 *                                       for the bandit arms, skipped
 *                                       for explorer-pool children
 *   - random-rescue classification  -- only meaningful under
 *                                       SR_PLATEAU_FORCE windows */
static void account_pc_edge_only(struct childdata *child,
				 struct syscallrecord *rec,
				 unsigned long new_edge_count,
				 unsigned int rescue_cold_skip_pct_before)
{
	/* Coverage-delta-triggered persistence: snapshot the
	 * minicorpus to disk every MINICORPUS_SNAPSHOT_EDGES
	 * fleet-wide edges so a crash mid-run only loses the
	 * last cadence window of state, not the whole run.
	 * Cheap fast path when the gap isn't reached; only one
	 * caller per window actually runs the save. */
	minicorpus_maybe_snapshot();

	if (child->is_explorer) {
		/* Explorer-pool discoveries are real edges and count
		 * toward the run-wide fleet totals, but skip the
		 * per-strategy reward attribution: explorers always
		 * run STRATEGY_RANDOM, so feeding their edges into
		 * the bandit's current arm would either inflate a
		 * non-RANDOM arm's reward (when the bandit picked
		 * something else) or double-count when the bandit
		 * also picked RANDOM. */
		__atomic_fetch_add(&shm->stats.explorer_pool_edges_discovered,
				   1, __ATOMIC_RELAXED);
	} else {
		/* Attribute this new-edge call to the strategy that
		 * PICKED the syscall, not whichever strategy happens
		 * to be shm->current_strategy by the time the syscall
		 * has returned and we got around to scoring the
		 * reward.  The two values can disagree any time a
		 * rotation lands between set_syscall_nr() and here,
		 * which is frequent for long or blocking syscalls;
		 * reading the pick-time stamp keeps the bandit's
		 * reward signal pointed at the arm that actually
		 * earned the credit.
		 *
		 * Two parallel cumulative counters:
		 * pc_edge_calls_by_strategy[] bumps by 1 (the
		 * historical "edges_by_strategy[]" signal under its
		 * honest name -- calls-with-≥1-edge) and
		 * pc_edge_count_by_strategy[] bumps by the real
		 * bucket-edge count from kcov_collect().  Window
		 * deltas are computed by maybe_rotate_strategy against
		 * the matching *_at_window_start snapshots. */
		int strat = child->strategy_at_pick;
		if (strat >= 0 && strat < NR_STRATEGIES) {
			__atomic_fetch_add(&shm->pc_edge_calls_by_strategy[strat],
					   1, __ATOMIC_RELAXED);
			__atomic_fetch_add(&shm->pc_edge_count_by_strategy[strat],
					   new_edge_count,
					   __ATOMIC_RELAXED);
		}
		__atomic_fetch_add(&shm->stats.bandit_pool_edges_discovered,
				   1, __ATOMIC_RELAXED);

		/* Random-rescue classification.  Only meaningful when
		 * the current window is a SR_PLATEAU_FORCE intervention
		 * -- the classifier exists to explain why a forced
		 * RANDOM rescue produced the edge a structured picker
		 * missed.  Reading current_selection_reason rather than
		 * stamping it at pick-time is fine here: the
		 * intervention windows are long (~100 sec at 10K
		 * iter/sec) and a child whose syscall straddled a
		 * rotation boundary is rare enough that misattributing
		 * a handful of rescues per rotation is below the
		 * noise floor on the per-class counts.  The orchestrator
		 * reads the cumulative distribution at the next
		 * rotation boundary to decide which class to amplify. */
		if (__atomic_load_n(&shm->current_selection_reason,
				    __ATOMIC_RELAXED) ==
		    SR_PLATEAU_FORCE) {
			enum random_rescue_class rrc =
				classify_random_rescue(rec, child,
					rescue_cold_skip_pct_before);
			if (rrc >= 0 && rrc < RRC_NR_CLASSES)
				__atomic_fetch_add(
					&shm->random_rescue_class_count[rrc],
					1UL, __ATOMIC_RELAXED);
		}
	}
}

/* Per-strategy transition-reward attribution.  Independent of the
 * new_edges gate above: a call can flip transition slots (a new
 * ordering between two PCs) without flipping any new bucket bit
 * -- the canonical "transition fires on warm-known PCs through a
 * new route" case is exactly the signal the operator wants
 * separated from the PC-edge stream.  The kcov_collect path
 * already filters pcres.transition_edges_real_local on
 * !kc->remote_mode and on kcov_transition_reward_mode != OFF
 * (see the result-population branch in kcov_collect), so a
 * non-zero value here means a local-mode call earned a reward-
 * eligible transition delta.
 *
 * Explorer-pool calls are skipped for the same reason PC-edge
 * attribution skips them above: explorers always run STRATEGY_
 * RANDOM, so crediting the active bandit arm here would either
 * inflate a non-RANDOM arm's reward (when the bandit picked
 * something else) or double-count when both pools picked RANDOM.
 *
 * The raw transition count is capped at TRANSITION_PER_CALL_
 * REWARD_CAP before being added to transition_edge_count_by_
 * strategy[] so a single pathological trace (e.g. a syscall that
 * opens a brand-new control-flow region and flips thousands of
 * transition slots in one call) cannot monopolize the per-window
 * delta the bandit reads as reward.  The uncapped real-flip
 * counter per_syscall_transition_edges_real keeps reporting the
 * full magnitude for the stats-dump top-N; the cap only applies
 * to the reward-attribution path. */
static void account_transition_reward(struct childdata *child,
				      struct syscallrecord *rec,
				      const struct kcov_pc_result *pcres)
{
	int strat;
	unsigned long capped;

	if (pcres->transition_edges_real_local == 0 ||
	    child->is_explorer || rec->nr >= MAX_NR_SYSCALL)
		return;

	strat = child->strategy_at_pick;
	if (strat < 0 || strat >= NR_STRATEGIES)
		return;

	capped = pcres->transition_edges_real_local;
	if (capped > TRANSITION_PER_CALL_REWARD_CAP)
		capped = TRANSITION_PER_CALL_REWARD_CAP;
	__atomic_fetch_add(
		&shm->stats.transition_edge_calls_by_strategy[strat],
		1UL, __ATOMIC_RELAXED);
	__atomic_fetch_add(
		&shm->stats.transition_edge_count_by_strategy[strat],
		capped, __ATOMIC_RELAXED);
}

/* FD leak tracking (count successful fd-creating and fd-closing
 * syscalls per child for leak diagnosis), the live-fd ring push for
 * preferential reuse in arg generation, the group_bias-gated
 * last_group stamp, and the F-RSEQ group-pin damper per-child
 * bookkeeping (group-change streak reset, streak bump, fd-warm
 * bump, coverage watermark advance).  All pieces are per-call
 * child-state updates that key off the just-completed syscall's
 * entry / rec and touch no shared region, so they collapse into
 * one helper at the end of the dispatch_step bookkeeping tail.
 *
 * found_local_coverage is the dispatch-step coverage signal the
 * watermark advance keys on: true when this call landed at least
 * one new PC-edge or one new LOCAL transition-edge.  Remote-
 * collected coverage is intentionally excluded -- remote /
 * deferred edges can land on whichever syscall happened to harvest
 * them and would falsely productive-mark a pure observer, so the
 * watermark uses the same _real_local lane satcool already
 * isolates.  Computed at the dispatch_step seam where new_edges
 * and pcres.transition_edges_real_local are both in scope. */
static void account_fd_and_group(struct childdata *child,
				 struct syscallentry *entry,
				 struct syscallrecord *rec,
				 bool found_local_coverage)
{
	enum frontier_group_antilock_mode antilock_mode;

	if (rec->retval != -1UL) {
		if (entry->rettype == RET_FD) {
			child->fd_created++;
			if (entry->group < NR_GROUPS)
				child->fd_created_by_group[entry->group]++;
			/* Track returned fd for preferential reuse in arg generation. */
			if ((int)rec->retval > 2)
				child_fd_ring_push(&child->live_fds, (int)rec->retval);
		}
		if (entry->is_close_syscall)
			child->fd_closed++;
	}

	/* F-RSEQ group-pin damper per-child bookkeeping.  Gated on
	 * frontier_group_antilock_mode != OFF so default mode=OFF is
	 * byte-identical to a build before this commit -- the mode load
	 * is the only added cost when off, and the field writes inside
	 * the branch are owner-only with no shm touched.  Inner gate on
	 * group_bias mirrors the last_group write below: the streak
	 * state is a per-pin counter on top of last_group, so it only
	 * makes sense to advance it under the same flag that keeps
	 * last_group meaningful (the F-RSEQ-5 fleet-invocation caveat
	 * in the design note).  See the group_streak_len / last_cov_at_
	 * streak / group_fd_created_in_streak field comments in
	 * include/child.h for the bookkeeping order rationale. */
	antilock_mode = __atomic_load_n(&frontier_group_antilock_mode,
					__ATOMIC_RELAXED);
	if (antilock_mode != FRONTIER_GROUP_ANTILOCK_MODE_OFF && group_bias) {
		/* Group-change reset: a new pin starts clean.  Compared
		 * BEFORE last_group is overwritten below so the
		 * comparison sees the previous pin's group. */
		if (entry->group != child->last_group) {
			child->group_streak_len = 0;
			child->last_cov_at_streak = 0;
			child->group_fd_created_in_streak = 0;
		}
		/* Saturate at UINT_MAX to keep the predicate arithmetic
		 * defined even after pathological pin lengths -- a real
		 * pin will never reach UINT_MAX, but a saturating bump
		 * costs the same as an unguarded one on the hot path
		 * and is correct against the unsigned-subtraction guard
		 * the pin_stale predicate uses (streak_len -
		 * last_cov_at_streak). */
		if (child->group_streak_len != UINT_MAX)
			child->group_streak_len++;
		/* fd-warm bump: a pin holding live state (warm setup
		 * chains -- socket -> bind -> sendmsg, openat -> read ->
		 * close) is spared from release even when coverage-
		 * barren, because the produced object is the locality
		 * the group bias is really protecting.  Gated by the
		 * same retval-not-(-1) AND RET_FD condition the
		 * fd_created bump above uses so the warm signal stays
		 * symmetric with the leak-instrumentation signal.  No
		 * group bound check needed -- the bump tracks any fd
		 * produced inside the current pin, regardless of which
		 * group that pin is. */
		if (rec->retval != -1UL && entry->rettype == RET_FD &&
		    child->group_fd_created_in_streak != UINT_MAX)
			child->group_fd_created_in_streak++;
		/* Coverage watermark advance: tracks the most recent
		 * streak position at which the pin landed an edge.
		 * Productive group clusters (NET socket -> bind ->
		 * sendto, VFS openat -> read -> close) advance this on
		 * every yielding member so pin_stale never holds, and
		 * the pin is preserved; pure-getter pins (no edges,
		 * no transitions) leave it pinned at 0 so after
		 * MIN_STREAK + COV_WINDOW picks the pin goes stale. */
		if (found_local_coverage)
			child->last_cov_at_streak = child->group_streak_len;
	}

	/* Track the group for biasing.  WRITE LAST so the F-RSEQ
	 * group-change detection above can compare against the
	 * previous pin's group; reordering this above the F-RSEQ
	 * block would null out every reset. */
	if (group_bias)
		child->last_group = entry->group;
}

static bool dispatch_step(struct childdata *child, struct syscallentry *entry,
			  bool *found_new, unsigned long *new_cmp_out,
			  unsigned long *new_transition_out)
{
	struct syscallrecord *rec = &child->syscall;
	bool new_edges;
	unsigned long new_edge_count = 0;

	/* Stamp the resolved entry on the rec so .sanitise / .post handlers
	 * (and helpers like this_syscallname()) can reach it without
	 * re-running get_syscall_entry(nr, do32bit) on every probe. */
	rec->entry = entry;

	/* Clear the per-call validator-reject flag.  do_syscall() sets this
	 * when validate_arg_coupling() rejects the call before the kernel is
	 * entered; the kcov_collect() gate below reads it to skip the
	 * total_calls / per_syscall_calls[nr] bumps that would otherwise
	 * poison kcov_syscall_cold_skip_pct() for strict-validator syscalls. */
	rec->validator_rejected = false;

	output_syscall_prefix(rec, entry);

	/* PC mode: per-child kcov fd collects edge coverage, optionally
	 * via KCOV_REMOTE_ENABLE to also pick up softirq / threaded-irq /
	 * kthread coverage triggered by this syscall.  CMP mode: per-child
	 * cmp fd collects comparison-operand records that feed the
	 * cmp_hints pool.  Mode is fixed at child init; remote_mode is
	 * only meaningful in PC mode (KCOV_REMOTE_ENABLE applies to the PC
	 * fd, not the cmp fd).
	 *
	 * Sample rate is per-syscall: calls whose interesting kernel work
	 * is deferred to kthreads / workqueues / softirqs (netlink async
	 * delivery, io_uring workers, BPF attach, mount workqueues, cgroup
	 * migration, namespace setup) are flagged with KCOV_REMOTE_HEAVY
	 * and sampled at the heavier 1-in-KCOV_REMOTE_RATIO_HEAVY rate so
	 * those deferred-work edges don't get stuck cold; everything else
	 * uses the default 1-in-KCOV_REMOTE_RATIO trickle. */
	if (child->kcov.mode == KCOV_MODE_PC) {
		/* When the kernel did not let this child enable KCOV_REMOTE,
		 * neither the static nor the adaptive policy can flip
		 * remote_mode true.  Match the historical short-circuit
		 * (which never invoked ONE_IN in that case) exactly so the
		 * caller's RNG stream stays byte-identical to the pre-row
		 * baseline for non-capable children. */
		if (!child->kcov.remote_capable) {
			child->kcov.remote_mode = false;
		} else {
			unsigned int remote_reciprocal =
				(entry->flags & KCOV_REMOTE_HEAVY) ?
					KCOV_REMOTE_RATIO_HEAVY :
					KCOV_REMOTE_RATIO;
			bool static_remote = ONE_IN(remote_reciprocal);
			/* The adaptive helper bumps shadow counters in
			 * lock-step from both A/B arms so the would-be
			 * divergence stays observable on Arm A (the control
			 * cohort) too.  Arm A then discards the adaptive
			 * disposition and runs the static decision so its
			 * live remote_mode is byte-identical to the pre-row
			 * baseline; Arm B substitutes the adaptive
			 * disposition as the live remote_mode. */
			bool adaptive_remote = remote_adaptive_decide(
				rec->nr, entry, static_remote);
			child->kcov.remote_mode = child->remote_adaptive_arm_b ?
				adaptive_remote : static_remote;
		}
	} else {
		child->kcov.remote_mode = false;
	}

	do_syscall(rec, entry, &child->kcov, child);

	/* kcov_collect() returns the real per-call bucket-edge count via the
	 * out-param alongside its bool found_new return.  Diff-ing the global
	 * kcov_shm->edges_found around the call would race other children's
	 * concurrent increments and over-attribute their edges to this
	 * syscall; the per-call count is the authoritative number.
	 *
	 * CMP-mode children contribute zero PC edges (their PC fd is never
	 * enabled), so new_edge_count stays 0 and the per-strategy edge
	 * attribution block below naturally skips on its `new_edge_count > 0`
	 * gate.  Frontier ring updates and bandit reward attribution also
	 * skip cleanly via `if (new_edges)` further down -- CMP-mode
	 * children deliberately don't contribute to those PC-edge concepts.
	 *
	 * CMP-source corpus saves are the exception: kcov_collect_cmp
	 * returns the per-call count of bloom-novel KCOV_CMP_CONST
	 * comparisons, captured here in new_cmp.  Under a PC-edge plateau
	 * (cmp_rising_pc_flat) that count is the only available novelty
	 * signal -- the save gate below widens to `new_edges || new_cmp
	 * > 0` so the corpus can still grow and mutator wins can still be
	 * credited, breaking the self-reinforcing
	 * PC-plateau->no-saves->no-mutator-wins loop.  See
	 * investigations/corpus-mutator-zero-wins-2026-05-20 for the full
	 * analysis. */
	unsigned long new_cmp = 0;

	/* Snapshot the rescue classifier's cold-skip-pct input BEFORE
	 * kcov_collect runs.  On a new edge kcov_collect bumps
	 * last_edge_at[rec->nr] to the current total_calls, after which
	 * kcov_syscall_cold_skip_pct(rec->nr) returns 0 -- the exact case
	 * classify_random_rescue exists to recognise as RRC_COLD_SKIP.
	 * Reading it here, at draw time, keeps the classifier's "would the
	 * picker have skipped this?" question pinned to the picker's actual
	 * pre-call state.  Only meaningful in PC mode; the CMP path never
	 * reaches the classifier (new_edges stays false there). */
	unsigned int rescue_cold_skip_pct_before = 0;

	/* Initialised here so the transition-attribution block below (which
	 * runs unconditionally on the CMP-mode side too, gated on
	 * pcres.transition_edges_real_local > 0) sees a clean zero when
	 * the kcov_collect path is skipped. */
	struct kcov_pc_result pcres = { 0 };

	if (child->kcov.mode == KCOV_MODE_PC) {
		rescue_cold_skip_pct_before =
			kcov_syscall_cold_skip_pct(rec->nr);
		/* Pre-validation reject in do_syscall() -- the kernel was never
		 * entered, so there is no coverage to collect and bumping
		 * total_calls / per_syscall_calls[nr] inside kcov_collect()
		 * would poison kcov_syscall_cold_skip_pct() on syscalls whose
		 * validators are strict.  last_edge_at[] only moves on the
		 * found_new branch and stays correctly frozen here. */
		if (rec->validator_rejected)
			new_edges = false;
		else
			/* Pass &pcres (not NULL) so the per-strategy
			 * transition reward attribution below has access to
			 * pcres.transition_edges_real_local.  The bucket_bits
			 * / distinct_edges / local_distinct_pcs fields are
			 * also populated but the existing PC-edge attribution
			 * path consumes new_edge_count instead, so they are
			 * written but not read here -- the extra struct stores
			 * are zero-atomics and unmeasurable on the per-call
			 * cost. */
			new_edges = kcov_collect(&child->kcov, rec->nr,
						 rec->do32bit,
						 &new_edge_count, &pcres);
	} else {
		new_cmp = kcov_collect_cmp(&child->kcov, rec->nr,
					   rec->do32bit,
					   child->is_explorer,
					   child->strategy_at_pick);
		new_edges = false;

		account_reexec_ab_cohort(child, new_cmp);
	}

	account_per_syscall_new_edges(child, rec, new_edge_count);

	/* Surface this step's new-coverage signal to the chain executor
	 * (when called via run_sequence_chain). */
	if (found_new != NULL)
		*found_new = new_edges;

	/* CMP-bloom novelty is an equivalent corpus-save / mutator-win
	 * signal alongside PC-edge novelty.  Under a PC-edge plateau the
	 * PC-only gate fires for ~0% of calls; the OR-with-CMP gate keeps
	 * the corpus growing on arg neighbourhoods that exercise new
	 * compile-time-constant comparisons (the cmp_rising_pc_flat
	 * frontier).  PC-edge-specific bookkeeping below (frontier ring,
	 * snapshot cadence, per-strategy edge attribution, explorer/bandit
	 * pool edge counters) STAYS gated on new_edges -- those are
	 * PC-edge concepts by definition and contaminating them with
	 * CMP-source events would silently bias the bandit reward and
	 * corrupt the plateau diagnostics. */
	bool found_something = new_edges || (new_cmp > 0);

	account_warm_reserve(child, rec, new_edges, new_cmp, &pcres);

	/* If the win signal came from CMP novelty rather than PC novelty,
	 * tag the pending mutator attribution.  Tag-before-commit + the
	 * unconditional clear inside commit() together mean a stale tag
	 * from a !found_something path never leaks into the next call. */
	if (new_cmp > 0)
		minicorpus_mut_attrib_set_cmp_source();

	/* Credit each mutator case picked during this call's arg
	 * generation, with wins iff this call produced ANY novelty
	 * signal (PC-edge OR CMP-bloom).  PC-only credit was the matching
	 * half of the PC-only save gate; expanding both together keeps
	 * mutator productivity stats and corpus growth in lockstep. */
	minicorpus_mut_attrib_commit(found_something);

	/*
	 * SHADOW per-entry cmp-hint feedback scoring ([11-feedback-loop]
	 * PHASE 4).  Drain the per-child stash that cmp_hints_try_get_ex
	 * pushed onto during arg generation; credit per-entry pool wins/
	 * misses on the matching pool entries and bump the flat
	 * cmp_hint_wins / cmp_hint_misses / cmp_hint_cmp_novelty_wins
	 * counters.  Exactly ONE drain per parent dispatch:
	 *  - PC mode: credit_pc(true) on new_edges, credit_pc(false) on
	 *    no-edge.  PC-edge is the win signal the follow-up live-pick
	 *    weight will read.
	 *  - CMP mode with new_cmp > 0: credit_cmp_novelty (SEPARATE
	 *    counter; spec mandate -- CMP novelty must not masquerade as
	 *    PC-edge conversion).
	 *  - CMP mode with new_cmp == 0: just reset the stash, no credit
	 *    (PC-mode score is undefined for a CMP-mode call, and CMP
	 *    novelty did not fire).
	 *
	 * SHADOW: live pool selection in cmp_hints_try_get is uniform
	 * here -- only the per-entry scores and the flat counters record
	 * outcomes.  A future A/B-gated path will turn the scores into a
	 * weighted live pick.
	 *
	 * Gated on !child->in_reexec so the inner re-exec dispatch does
	 * not credit the outer parent's stash a second time.  The outer
	 * dispatch_step already credited and reset the stash above; the
	 * inner generate_syscall_args under in_reexec did not push (the
	 * stash helper gates on the same flag), so the inner stash is
	 * provably empty here.  Belt-and-braces vs an accidental future
	 * push that forgets the gate.
	 */
	if (!child->in_reexec) {
		/* Typed-hyp side channels: credit TRANSITION_WIN and
		 * CORPUS_SAVE on each hyp_injected stash entry BEFORE the
		 * PC / CMP-novelty drain below resets the stash.  Mirrors
		 * the same novelty conditions the parent dispatch uses:
		 * transition wins are credited when the kernel-side
		 * transition-edge counter advanced this call, and corpus
		 * saves are credited when this dispatch's args will land
		 * in the minicorpus (same gate the save block below
		 * checks).  Both credits are typed-hyp only -- the flat
		 * cmp_hint_* counters are unaffected. */
		if (pcres.transition_edges_real_local > 0)
			cmp_hints_feedback_credit_transition();
		if (unlikely(found_something) && entry->sanitise == NULL)
			cmp_hints_feedback_credit_corpus_save();

		if (child->kcov.mode == KCOV_MODE_PC) {
			cmp_hints_feedback_credit_pc(new_edges);
		} else if (new_cmp > 0) {
			cmp_hints_feedback_credit_cmp_novelty();
		} else {
			cmp_hints_feedback_reset_stash();
		}
	}

	/* Save args that produced any novelty signal, but only for
	 * syscalls without sanitise (which may stash pointers).  Tag with
	 * the source so saves_by_reason[] separates PC-promoted from
	 * CMP-promoted entries; PC wins the tag on calls where both
	 * signals fire so the historical accounting is preserved. */
	if (unlikely(found_something)) {
		account_cold_overflow_would_save(entry, rec, new_cmp);

		if (entry->sanitise == NULL)
			minicorpus_save_with_reason(rec,
				new_edges ? CORPUS_SAVE_REASON_PC
					  : CORPUS_SAVE_REASON_CMP);
	}

	if (unlikely(new_edges))
		account_pc_edge_only(child, rec, new_edge_count,
				     rescue_cold_skip_pct_before);

	account_transition_reward(child, rec, &pcres);

	/* COMBINED-mode only: bump the per-syscall frontier-edge ring on
	 * the transition-discovery path so syscalls producing transitions
	 * (a new ordering through warm-known code) but no fresh PC bucket
	 * bits still earn frontier credit -- this is the whole point of
	 * promoting the signal, since the empirically-observed regime is
	 * one where transition discovery is healthy while PC-edge
	 * discovery has plateaued.  Under SHADOW_ONLY (the rollback path)
	 * the ring stays driven only by frontier_record_new_edge() so the
	 * silent-regime picker distribution remains byte-identical to the
	 * pre-knob baseline.  Same is_explorer + nr-bounds guards as the
	 * attribution block above. */
	if (pcres.transition_edges_real_local > 0 &&
	    !child->is_explorer && rec->nr < MAX_NR_SYSCALL &&
	    __atomic_load_n(&kcov_transition_reward_mode,
			    __ATOMIC_RELAXED) ==
	    KCOV_TRANSITION_REWARD_COMBINED)
		frontier_record_transition_edge((unsigned int)rec->nr);

	output_syscall_postfix(rec);

	handle_syscall_ret(rec, entry);

	/* Snapshot the completed call into the per-child ring so the parent
	 * has a chronological window of recent activity if a kernel taint
	 * fires before the next syscall. */
	child_syscall_ring_push(&child->syscall_ring, rec);

	/* Also append a compact record to the per-child pre-crash ring,
	 * dumped on __BUG() to attribute the assertion to a specific
	 * recent syscall.  rec->tp was just refreshed in do_syscall(). */
	pre_crash_ring_record(child, rec, &rec->tp);

	/* Single combined enqueue: op_count + success/failure +
	 * syscall_category_count[] all ride on one STATS_FIELD_CALL_COMPLETE
	 * slot.  The drain expands it back into three logical bumps.
	 * Result class is derived post-handle_syscall_ret(), which has
	 * already coerced rec->retval for retfd_rejected and is the
	 * canonical settle point for rec->state. */
	{
		enum stats_result_class result;

		if (__atomic_load_n(&rec->state, __ATOMIC_ACQUIRE) != AFTER)
			result = STATS_RESULT_INCOMPLETE;
		else if (rec->retval == (unsigned long)-1L)
			result = STATS_RESULT_FAILURE;
		else
			result = STATS_RESULT_SUCCESS;

		stats_ring_enqueue_call_complete(child->stats_ring,
						 (uint16_t)entry->syscall_category,
						 result);

		/* childop_split telemetry: attribute this syscall to the
		 * in-childop or random-syscall bucket based on the per-child
		 * flag set by child_process()'s per-op bracket.  Set when
		 * random_syscall() was reached from inside an alt-op op_fn
		 * (e.g. sched_cycler's inner loop), clear otherwise (direct
		 * CHILD_OP_SYSCALL fallthrough via run_sequence_chain).
		 * RELAXED add-fetch: cumulative diagnostic, lost-update races
		 * are tolerated.  Owner is the only writer of in_childop so
		 * no read race -- this child either is or isn't inside its
		 * own op_fn at this point. */
		if (child->in_childop) {
			__atomic_add_fetch(&shm->stats.syscalls_in_childops,
					   1UL, __ATOMIC_RELAXED);
		} else {
			__atomic_add_fetch(&shm->stats.syscalls_random,
					   1UL, __ATOMIC_RELAXED);
		}
	}

	/* found_local_coverage feeds the F-RSEQ coverage watermark advance
	 * inside account_fd_and_group.  Local PC-edge novelty (new_edges)
	 * is the PC-mode signal; the LOCAL transition-edge count (pcres.
	 * transition_edges_real_local, populated by kcov_collect on the
	 * PC-mode side, zero-initialised on the CMP-mode side) is the
	 * transition-novelty signal.  Both are LOCAL by construction --
	 * remote-collected coverage is deliberately excluded so a pure
	 * observer that happened to harvest a remote edge is not falsely
	 * productive-marked.  The OR-of-both shape matches the design's
	 * watermark-advance contract (PC + local transition); each lane
	 * is independently sufficient. */
	{
		bool found_local_coverage = new_edges ||
			(pcres.transition_edges_real_local > 0);

		account_fd_and_group(child, entry, rec, found_local_coverage);
	}

	/* Per-arm completion exposure: bump the arm this call was attributed
	 * to.  Two distinct cases reach here with strategy_at_pick == -1:
	 *
	 *   - Explorer-pool children: set_syscall_nr() leaves the sentinel
	 *     in place and bumps strategy_picks[STRATEGY_RANDOM] directly.
	 *     The completion bump mirrors that pick by crediting RANDOM
	 *     here so picks and completions stay symmetric for the explorer
	 *     contribution.
	 *
	 *   - Replay steps from run_sequence_chain(): replay_syscall_step()
	 *     deliberately clears strategy_at_pick to -1 to avoid crediting
	 *     replay work to whichever arm started the chain.  Replays did
	 *     not bump strategy_picks[] either, so the completion bump must
	 *     skip them to keep picks and completions paired.
	 *
	 * Gate the fallback on child->is_explorer specifically rather than
	 * sap < 0 so the two cases stay separated.  Replay-step visibility
	 * lives in chain_corpus_shm->replay_steps_dispatched. */
	{
		int sap = child->strategy_at_pick;
		if (sap < 0 && child->is_explorer)
			sap = STRATEGY_RANDOM;
		if (sap >= 0 && sap < NR_STRATEGIES)
			__atomic_fetch_add(
				&shm->strategy_completed_calls[sap],
				1UL, __ATOMIC_RELAXED);
	}

	/*
	 * CMP RedQueen greedy re-exec tail.  Fires after the
	 * parent call's handle_syscall_ret has settled so .post / .cleanup
	 * are done before the re-exec dispatch reuses rec.  A single
	 * insertion point in dispatch_step so all callers
	 * (random_syscall_step, replay_syscall_step, sequence-chain step)
	 * inherit re-exec coverage automatically.
	 *
	 * Gates (ALL must pass):
	 *   - !in_reexec     -- recursion guard; otherwise we'd self-reinforce
	 *     a runaway loop.
	 *   - redqueen_enabled -- A/B-comparison stamp.
	 *   - kcov.mode == KCOV_MODE_CMP -- PC-mode children produce no
	 *     attribution.  Defensive: redqueen_enabled is only stamped
	 *     true on CMP-mode children today, but the gate keeps the
	 *     dispatch invariant local to this site.
	 *   - !in_chain_mid_step -- chains save their step sequence for
	 *     replay; a mid-chain re-exec is not part of that contract
	 *     and would double-count the step against the chain depth.
	 *   - new_cmp > 0 -- the parent must have produced at least one
	 *     bloom-novel CMP record.  A call that only re-harvested
	 *     known constants adds no information for re-exec.
	 *   - reexec_pending_count > 0 -- attribution scan in the parent's
	 *     cmp_hints_collect actually found a slot match.
	 *   - rate gate: ONE_IN(REDQUEEN_REEXEC_GATE_DENOM) baseline,
	 *     always-on while the plateau detector classifies the run as
	 *     CMP_RISING_PC_FLAT.  Combines low-cost steady-state lift
	 *     with full intensification under the diagnostic this re-exec
	 *     was designed to break.
	 */
	{
		/* Per-call gate disposition bucketing (PHASE 0 measurement-
		 * correctness): every dispatch_step that reaches this tail
		 * bumps EXACTLY ONE counter, partitioning the gap between
		 * reexec_attribution_found and reexec_attempts.  The
		 * evaluation order below mirrors the original short-circuited
		 * compound `if`; gate_skipped holds the counter address for
		 * the first failing gate (NULL == all gates cleared, the
		 * re-exec actually fired).  Behaviour is unchanged -- the
		 * reexec call site and rate-gate semantics are identical to
		 * the prior code; only the accounting around it is new. */
		unsigned long *gate_skipped = NULL;
		bool gate_passed = false;
		bool plateau_burst = false;

		if (child->in_reexec) {
			gate_skipped = (kcov_shm != NULL)
				? &kcov_shm->reexec_gate_skip_in_reexec
				: NULL;
		} else if (!child->redqueen_enabled) {
			gate_skipped = (kcov_shm != NULL)
				? &kcov_shm->reexec_gate_skip_disabled
				: NULL;
		} else if (child->kcov.mode != KCOV_MODE_CMP) {
			gate_skipped = (kcov_shm != NULL)
				? &kcov_shm->reexec_gate_skip_mode
				: NULL;
		} else if (child->in_chain_mid_step) {
			gate_skipped = (kcov_shm != NULL)
				? &kcov_shm->reexec_gate_skip_chain_mid
				: NULL;
		} else if (new_cmp == 0) {
			gate_skipped = (kcov_shm != NULL)
				? &kcov_shm->reexec_gate_skip_no_new_cmp
				: NULL;
		} else if (child->reexec_pending_count == 0) {
			gate_skipped = (kcov_shm != NULL)
				? &kcov_shm->reexec_gate_skip_no_pending
				: NULL;
		} else {
			/* All boolean gates cleared; the rate gate
			 * (ONE_IN(N) baseline plus always-on during a
			 * CMP_RISING_PC_FLAT plateau) decides between
			 * gate_pass and the rate-skip bucket. */
			if (kcov_shm != NULL &&
			    __atomic_load_n(&kcov_shm->plateau_active,
					    __ATOMIC_RELAXED)) {
				int h = __atomic_load_n(
					&shm->plateau_current_hypothesis,
					__ATOMIC_RELAXED);

				if (h == PLATEAU_HYPOTHESIS_CMP_RISING_PC_FLAT)
					plateau_burst = true;
			}

			if (plateau_burst ||
			    ONE_IN(REDQUEEN_REEXEC_GATE_DENOM)) {
				/* Drain ALL staged reexec_pending entries
				 * for this parent dispatch (bounded by the
				 * producer-side MAX_REEXEC_PENDING cap).
				 * Each entry was independently
				 * attribution-scanned by cmp_hints_collect
				 * from the parent's CMP records, so each is
				 * an equally valid re-exec candidate; the
				 * prior single-drain rule discarded
				 * (count - 1) entries per dispatch even
				 * though every discarded entry had already
				 * cleared the parent's full outer-gate
				 * sequence (in_reexec, redqueen_enabled,
				 * kcov_mode, chain_mid, new_cmp, rate gate
				 * / plateau_burst).
				 *
				 * Per-entry safety is enforced inside
				 * redqueen_reexec_step (destructive-syscall
				 * denylist, validate_specific_syscall_silent,
				 * p->slot bounds, REDQUEEN_REEXEC_WINDOW_CAP);
				 * the window cap naturally bounds the
				 * per-window total attempts even when
				 * multiple drains fire per parent dispatch.
				 *
				 * in_reexec brackets the whole drain so each
				 * inner dispatch_step short-circuits at the
				 * outer in_reexec gate and cannot recurse
				 * into this drain.
				 *
				 * The --redqueen-pending-pick A/B flag is
				 * a no-op for this code path now (every
				 * staged entry is drained regardless of
				 * pick order); the per-pending-index
				 * success counters
				 * (kcov_shm->reexec_pending_pick_success[])
				 * still get bumped inside
				 * redqueen_reexec_step at the entry's true
				 * index, so per-slot/per-index lift remains
				 * directly readable.  MAX_REEXEC_PENDING
				 * clamp on the loop bound is defence in
				 * depth against a corrupted count reaching
				 * the array index. */
				unsigned int count = child->reexec_pending_count;
				unsigned int i;

				if (count > MAX_REEXEC_PENDING)
					count = MAX_REEXEC_PENDING;

				child->in_reexec = true;
				for (i = 0; i < count; i++) {
					struct reexec_pending p =
						child->reexec_pending[i];

					redqueen_reexec_step(child, &p, i);
				}
				child->in_reexec = false;
				gate_passed = true;
			} else {
				gate_skipped = (kcov_shm != NULL)
					? &kcov_shm->reexec_gate_skip_rate
					: NULL;
			}
		}

		if (kcov_shm != NULL) {
			if (gate_passed)
				__atomic_fetch_add(
					&kcov_shm->reexec_gate_pass,
					1UL, __ATOMIC_RELAXED);
			else if (gate_skipped != NULL)
				__atomic_fetch_add(gate_skipped,
						   1UL, __ATOMIC_RELAXED);
		}
	}

	/* Per-call attribution scratch is single-use: drained or not, the
	 * next call starts with a clean slate so a stale slot from the
	 * previous call cannot bleed into this call's attribution census. */
	child->reexec_pending_count = 0;

	/* Cheap end-of-call check for the strategy rotation boundary.
	 * Two relaxed loads + a compare in the common case; the CAS only
	 * fires once per ~STRATEGY_WINDOW ops fleet-wide. */
	maybe_rotate_strategy();

	if (new_cmp_out != NULL)
		*new_cmp_out = new_cmp;

	if (new_transition_out != NULL)
		*new_transition_out = pcres.transition_edges_real_local;

	return true;
}

bool random_syscall_step(struct childdata *child,
			 bool have_substitute,
			 unsigned long substitute_retval,
			 bool *found_new,
			 unsigned long *new_transition_out,
			 unsigned long *new_cmp_out)
{
	struct syscallrecord *rec = &child->syscall;
	struct syscallentry *entry;

	if (set_syscall_nr(rec, child) == FAIL)
		return FAIL;

	rec->postbuffer[0] = '\0';

	/* Generate arguments, print them out */
	generate_syscall_args(rec);

	/* Sequence-chain substitution.  When the previous step in the chain
	 * returned a usable value, with CHAIN_SUBST_PCT probability splice
	 * it into one randomly-chosen arg slot of this call, overwriting
	 * whatever the generator produced.  Done after generate_syscall_args
	 * so the substituted value is what the kernel actually sees, and
	 * before output_syscall_prefix so the trace reflects the real call. */
	entry = get_syscall_entry(rec->nr, rec->do32bit);
	apply_chain_substitution(rec, entry, have_substitute, substitute_retval);

	return dispatch_step(child, entry, found_new, new_cmp_out,
			     new_transition_out);
}

bool random_syscall(struct childdata *child)
{
	return random_syscall_step(child, false, 0, NULL, NULL, NULL);
}

/*
 * Fresh-args dispatch for a pre-picked syscall NR.  The chain executor
 * calls this when --chain-resource-typing=live has classified the
 * previous step as a resource producer and wants to steer the next
 * link to a random consumer of the same kind.  Skips set_syscall_nr()
 * (and its strategy attribution) exactly the way replay_syscall_step
 * does: any PC / CMP / transition novelty the biased step produces
 * gets credited to no arm, so the bandit reward signal is not
 * contaminated by an external NR override.
 *
 * Returns FAIL when the biased NR is no longer callable in this run
 * (out of range, no entry, sanitise, deactivated / AVOID / lost cap);
 * the chain executor then falls back to a plain random_syscall_step
 * for the same slot so the iteration still does useful work.
 */
bool random_syscall_step_biased(struct childdata *child,
				unsigned int bias_nr, bool bias_do32,
				bool have_substitute,
				unsigned long substitute_retval,
				bool *found_new,
				unsigned long *new_transition_out,
				unsigned long *new_cmp_out)
{
	struct syscallrecord *rec = &child->syscall;
	struct syscallentry *entry;

	if (bias_nr >= MAX_NR_SYSCALL)
		return FAIL;

	entry = get_syscall_entry(bias_nr, bias_do32);
	if (entry == NULL)
		return FAIL;

	/* Same sanitise gate replay_syscall_step uses: sanitise-bearing
	 * syscalls stash heap pointers into arg slots during
	 * generic_sanitise, and a fresh-args regeneration here would
	 * still route through generate_syscall_args -- but the bias
	 * consumer table is a static NR list, so a NR whose entry
	 * carries .sanitise cannot come out of pick_consumer(); the
	 * gate is defensive against a future table addition slipping a
	 * sanitise-tagged NR through unnoticed. */
	if (entry->sanitise != NULL)
		return FAIL;

	if (!validate_specific_syscall_silent(
			bias_do32 ? syscalls_32bit :
			(biarch ? syscalls_64bit : syscalls),
			(int)bias_nr))
		return FAIL;

	/* Bias dispatches never credit a bandit arm.  Same rationale as
	 * replay_syscall_step: the arm at shm->current_strategy did not
	 * actually pick this NR; letting its stamp ride through
	 * dispatch_step would leak reward attribution to whichever arm
	 * happens to be current at the time of the override. */
	child->strategy_at_pick = -1;
	child->frontier_pick_regime = FRONTIER_PICK_NONE;

	/* Publish (nr, do32bit) inside the srec bracket so an outside
	 * reader (watchdog, pre_crash_ring decode) cannot see the new
	 * (nr, do32bit) paired with the previous syscall's args.
	 * generate_syscall_args carries its own bracket for the a1..a6
	 * writes, and apply_chain_substitution writes through a1..a6
	 * again, so both come after this publish window closes. */
	srec_publish_begin(rec);
	rec->do32bit = bias_do32;
	rec->nr = bias_nr;
	srec_publish_end(rec);

	rec->postbuffer[0] = '\0';
	generate_syscall_args(rec);
	apply_chain_substitution(rec, entry, have_substitute, substitute_retval);

	return dispatch_step(child, entry, found_new, new_cmp_out,
			     new_transition_out);
}

/*
 * Replay a saved chain step: stage the saved (nr, do32bit, args) into
 * rec, run the saved args through the per-arg mutator chain, apply any
 * Phase 1 retval substitution from the prior step, and dispatch through
 * the same path random_syscall_step uses.  Returns FAIL when the saved
 * syscall is no longer callable in this run (deactivated, AVOID_SYSCALL,
 * needs root we don't have, or has a sanitise that would stash stale
 * pointers); the chain executor falls back to fresh args in that case.
 *
 * The mutator call goes to minicorpus_mutate_args, which is the same
 * splice + weighted-stack-mutate engine the per-syscall mini-corpus
 * replay uses.  Sharing the mutator means chain replay automatically
 * inherits productivity tuning from the existing weighted scheduler
 * rather than duplicating the mutation logic with its own counters.
 */
bool replay_syscall_step(struct childdata *child,
			 const struct chain_step *saved,
			 bool have_substitute,
			 unsigned long substitute_retval,
			 bool *found_new,
			 unsigned long *new_transition_out,
			 unsigned long *new_cmp_out)
{
	struct syscallrecord *rec = &child->syscall;
	struct syscallentry *entry;
	unsigned long args[6];

	if (saved->nr >= MAX_NR_SYSCALL)
		return FAIL;

	entry = get_syscall_entry(saved->nr, saved->do32bit);
	if (entry == NULL)
		return FAIL;

	/* sanitise-bearing syscalls allocate and stash heap pointers into
	 * arg slots during generic_sanitise; replay would feed stale args
	 * to those slots.  Same gate the mini-corpus uses for the same
	 * reason. */
	if (entry->sanitise != NULL)
		return FAIL;

	/* The syscall may have been deactivated since the chain was saved
	 * (returned ENOSYS, hit AVOID_SYSCALL, lost a CAP_*).  Bail out
	 * rather than replay an inert call. */
	if (!validate_specific_syscall_silent(
			saved->do32bit ? syscalls_32bit :
			(biarch ? syscalls_64bit : syscalls),
			(int)saved->nr))
		return FAIL;

	memcpy(args, saved->args, sizeof(args));
	minicorpus_mutate_args(args, entry, saved->nr);

	/* Replay steps bypass set_syscall_nr() (which is where the bandit's
	 * per-arm pick stamp normally lands), so the child still holds the
	 * strategy_at_pick value from whichever fresh pick started the
	 * chain.  Letting that stale stamp ride through dispatch_step would
	 * credit replay-step PC/CMP novelty -- and the per-arm completion
	 * bump -- to an arm that did not actually pick the replayed syscall,
	 * contaminating the reward signal the bandit is meant to learn
	 * from.  Reset to the -1 sentinel so the existing strategy_at_pick
	 * gates at the consumer sites (kcov_collect_cmp / bandit_cmp_observe,
	 * the PC-edge per-strategy attribution in dispatch_step, the per-arm
	 * completion bump) all skip attribution for this step.
	 *
	 * The next fresh set_syscall_nr() overwrites strategy_at_pick
	 * unconditionally on the bandit-pool path, so leaving -1 here does
	 * not leak into subsequent non-replay calls. */
	child->strategy_at_pick = -1;

	if (chain_corpus_shm != NULL)
		__atomic_fetch_add(&chain_corpus_shm->replay_steps_dispatched,
				   1UL, __ATOMIC_RELAXED);

	/* Publish the (nr, do32bit) advance, the arg writes, the
	 * postbuffer reset, and the chain substitution as one coherent
	 * step.  An outside reader (watchdog thread, parent inspecting
	 * via shm, pre_crash_ring decode) that samples rec mid-step must
	 * not see the new (nr, do32bit) paired with the previous
	 * syscall's a1..a6 — that torn pairing miscredits args to the
	 * wrong syscall in divergence stats and crash-ring reconstruction.
	 * apply_chain_substitution writes rec->aN, so the publish_end
	 * has to come after it. */
	srec_publish_begin(rec);
	rec->do32bit = saved->do32bit;
	rec->nr = saved->nr;

	rec->a1 = args[0];
	rec->a2 = args[1];
	rec->a3 = args[2];
	rec->a4 = args[3];
	rec->a5 = args[4];
	rec->a6 = args[5];

	rec->postbuffer[0] = '\0';

	apply_chain_substitution(rec, entry, have_substitute, substitute_retval);
	srec_publish_end(rec);

	return dispatch_step(child, entry, found_new, new_cmp_out,
			     new_transition_out);
}

/*
 * Pin a single arg slot to a learned-constant value.  Slot is 1-based
 * (matches the rec->aN naming and reexec_pending::slot encoding).  Out-
 * of-range slots are dropped silently -- the caller validated against
 * the entry's num_args at attribution emit time, but defensive against
 * a corrupted pending entry that survived the slot bound check.
 */
static void redqueen_pin_slot(struct syscallrecord *rec, unsigned int slot,
			      unsigned long value)
{
	switch (slot) {
	case 1: rec->a1 = value; break;
	case 2: rec->a2 = value; break;
	case 3: rec->a3 = value; break;
	case 4: rec->a4 = value; break;
	case 5: rec->a5 = value; break;
	case 6: rec->a6 = value; break;
	default: break;
	}
}

/*
 * Field-scoped pin ([11-field-scoped]).  Unlike redqueen_pin_slot, the
 * targeted slot holds a POINTER to a freshly-regenerated fixed-size
 * struct; pin a single field inside that buffer and leave the rest of
 * the generated struct intact, so a kernel comparison that fired on one
 * field is satisfied without clobbering the whole arg.  Slot is 1-based.
 *
 * The buffer pointer is read AFTER generate_syscall_args() has run, so
 * it is whatever the generator just produced -- which for ARG_TIMESPEC
 * is either a valid pool pointer or the generator's ~10% NULL arm.  A
 * NULL / implausibly small pointer is left unpinned (the re-exec still
 * runs with fresh args, just without the field pin); the per-window cap
 * bounds the wasted budget.  Only the ARG_TIMESPEC tv_sec/tv_nsec pair
 * is wired today.
 */
static void redqueen_pin_field(struct syscallrecord *rec,
			       const struct reexec_pending *p)
{
	unsigned long ptr;
	struct timespec *ts;

	switch (p->slot) {
	case 1: ptr = rec->a1; break;
	case 2: ptr = rec->a2; break;
	case 3: ptr = rec->a3; break;
	case 4: ptr = rec->a4; break;
	case 5: ptr = rec->a5; break;
	case 6: ptr = rec->a6; break;
	default: return;
	}

	if (ptr < 4096)
		return;

	switch (p->field_kind) {
	case REEXEC_FIELD_TIMESPEC_SEC:
		ts = (struct timespec *) ptr;
		ts->tv_sec = (time_t) p->value;
		break;
	case REEXEC_FIELD_TIMESPEC_NSEC:
		ts = (struct timespec *) ptr;
		ts->tv_nsec = (long) p->value;
		break;
	case REEXEC_FIELD_NONE:
	default:
		break;
	}
}

/*
 * Greedy CMP RedQueen re-exec step.  Mirrors replay_syscall_step's
 * contract: resolve the entry, gate on sanitise-free (heap-pointer-
 * laundering inside generic_sanitise would either resurrect freed
 * slots or stomp the pin), gate on AVOID_REEXEC (auditable opt-out
 * for sanitise-free destructive entries -- see include/syscall.h),
 * gate on validate_specific_syscall_silent (caller may have lost a
 * cap / hit AVOID_SYSCALL / been deactivated since dispatch).  Then
 * regenerate fresh args via generate_syscall_args, overwrite the
 * targeted slot with the captured kernel-side constant, and re-enter
 * dispatch_step for the actual call.  Rec state is snapshotted on
 * entry and restored on exit so the chain-corpus save in sequence.c
 * (which reads rec->a1..a6 after dispatch_step returns) sees the
 * ORIGINAL dispatched args, not the re-exec's args.
 *
 * Per-call cap is enforced at the dispatch_step tail (C-1: 1 re-exec
 * per parent); per-window cap is enforced here so a corrupted /
 * misbehaving caller can't bypass it by calling the helper directly.
 */
static bool redqueen_reexec_step(struct childdata *child,
				 const struct reexec_pending *p,
				 unsigned int pending_idx)
{
	struct syscallrecord *rec = &child->syscall;
	struct syscallentry *entry;
	unsigned long saved_a[6];
	unsigned long saved_retval, saved_post_state;
	int saved_errno_post;
	bool ok;

	/* Per-window cap.  Reset to a fresh window
	 * once REDQUEEN_REEXEC_WINDOW_OPS child iterations have elapsed
	 * since the last reset; cap exceedance within a window short-
	 * circuits before any of the more expensive entry resolution. */
	if (child->op_nr - child->reexec_window_start_op >=
	    REDQUEEN_REEXEC_WINDOW_OPS) {
		child->reexec_window_start_op = child->op_nr;
		child->reexec_count_window = 0;
	}
	if (child->reexec_count_window >= REDQUEEN_REEXEC_WINDOW_CAP) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(&kcov_shm->reexec_window_cap_hit,
					   1UL, __ATOMIC_RELAXED);
		return FAIL;
	}

	entry = get_syscall_entry(rec->nr, rec->do32bit);
	if (entry == NULL) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(&kcov_shm->reexec_step_skip_entry_null,
					   1UL, __ATOMIC_RELAXED);
		return FAIL;
	}

	/* Destructive-syscall gate: sanitise-bearing entries replay would
	 * either re-allocate (and leak) heap state for slots whose previous
	 * sanitise has already been freed by .cleanup, or stomp the captured
	 * pin with the re-sanitise's preferred value.  Same gate
	 * replay_syscall_step uses for the same reason.  Layered with the
	 * AVOID_REEXEC denylist for sanitise-free entries whose effects are
	 * still destructive to the calling child or to global state. */
	if ((entry->sanitise != NULL && !(entry->flags & REEXEC_SANITISE_OK)) ||
	    (entry->flags & AVOID_REEXEC)) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(&kcov_shm->reexec_skipped_destructive,
					   1UL, __ATOMIC_RELAXED);
		return FAIL;
	}

	if (!validate_specific_syscall_silent(
			rec->do32bit ? syscalls_32bit :
			(biarch ? syscalls_64bit : syscalls),
			(int)rec->nr)) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(&kcov_shm->reexec_skipped_validate_silent,
					   1UL, __ATOMIC_RELAXED);
		return FAIL;
	}

	if (p->slot == 0 || p->slot > entry->num_args) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(&kcov_shm->reexec_step_skip_bad_slot,
					   1UL, __ATOMIC_RELAXED);
		return FAIL;
	}

	/* Snapshot the rec fields the re-exec's dispatch_step will rewrite.
	 * Restore on exit so a caller that reads rec after the helper
	 * returns -- the chain-corpus save in sequence.c being the
	 * load-bearing one -- sees the original dispatched call's args /
	 * retval, not the re-exec's.  nr / do32bit are NOT in the snapshot
	 * set: redqueen always dispatches the same (nr, do32) as the
	 * parent, so those fields stay invariant across the helper. */
	saved_a[0] = rec->a1;
	saved_a[1] = rec->a2;
	saved_a[2] = rec->a3;
	saved_a[3] = rec->a4;
	saved_a[4] = rec->a5;
	saved_a[5] = rec->a6;
	saved_retval = rec->retval;
	saved_post_state = rec->post_state;
	saved_errno_post = rec->errno_post;

	/* Coherent re-publishes around the re-exec dispatch state.  Same
	 * (nr, do32bit) as the parent so those don't need re-publication,
	 * but three other rec mutations do, and each runs in its own
	 * publish bracket (generate_syscall_args carries its own bracket
	 * internally, so it can't be folded into either neighbour):
	 *   1. postbuffer reset (this bracket) -- a pre_crash decoder
	 *      sampling between dispatches must not pair stale postbuffer
	 *      bytes with the new in-flight call.
	 *   2. fresh args, published by generate_syscall_args's own bracket.
	 *   3. the slot / field pin (bracket below) -- generate_syscall_args
	 *      has already closed its publish_end by the time the pin runs,
	 *      so the pin would otherwise land OUTSIDE any publish section
	 *      and an out-of-band reader (parent watchdog, pre_crash
	 *      decoder) could observe the pinned slot torn against the
	 *      generator's freshly-published aN values. */
	srec_publish_begin(rec);
	rec->postbuffer[0] = '\0';
	srec_publish_end(rec);

	generate_syscall_args(rec);

	srec_publish_begin(rec);
	if (p->field_kind == REEXEC_FIELD_NONE)
		redqueen_pin_slot(rec, p->slot, p->value);
	else
		redqueen_pin_field(rec, p);
	srec_publish_end(rec);

	/* Don't credit the bandit for re-exec wins -- same rationale as
	 * replay_syscall_step.  -1 sentinel makes the per-strategy
	 * attribution and per-arm completion sites skip this dispatch. */
	child->strategy_at_pick = -1;

	if (kcov_shm != NULL) {
		unsigned int op_type = (unsigned int)child->op_type;

		__atomic_fetch_add(&kcov_shm->reexec_attempts, 1UL,
				   __ATOMIC_RELAXED);
		/* per-nr partition of the re-exec attempt
		 * counter.  Reaching this site means the destructive /
		 * validate_silent / slot-bounds gates above already cleared,
		 * so the bump is attributed to the same syscall that the
		 * inner dispatch_step will actually re-run. */
		if (rec->nr < MAX_NR_SYSCALL)
			__atomic_fetch_add(
				&kcov_shm->reexec_attempts_by_syscall[rec->nr],
				1UL, __ATOMIC_RELAXED);
		/* per-childop partition of the re-exec attempt counter,
		 * sibling of the per-syscall bump above.  Lets a re-exec
		 * driven by a non-OP_SYSCALL childop (recipe runner, io_uring
		 * flood, etc.) be counted separately from the same nr fired
		 * from the default OP_SYSCALL flow. */
		if (op_type < KCOV_CHILDOP_NR_MAX)
			__atomic_fetch_add(
				&kcov_shm->reexec_attempts_by_childop[op_type],
				1UL, __ATOMIC_RELAXED);
	}
	child->reexec_count_window++;

	{
		unsigned long inner_new_cmp = 0;

		/* The re-exec's lift signal is the inner dispatch's per-call
		 * bloom-novel CMP count -- the authoritative value
		 * kcov_collect_cmp() returns to dispatch_step's local new_cmp.
		 * Surfacing it via the out-param avoids sampling the shared
		 * cmp_records_collected counter around the call: those relaxed
		 * loads race other CMP children's increments (over-attributing
		 * their records to this re-exec) and count raw duplicate
		 * records (not just novel ones), the same bug class avoided
		 * for PC edges via kcov_collect()'s new_edge_count out-param. */
		ok = dispatch_step(child, entry, NULL, &inner_new_cmp, NULL);

		if (kcov_shm != NULL && inner_new_cmp > 0) {
			unsigned int op_type = (unsigned int)child->op_type;

			/* Discrete count of attempts that produced novelty
			 * (PHASE 0 measurement).  Sibling of reexec_attempts
			 * (the denominator) and reexec_new_cmps_total (the
			 * SUM of inner_new_cmp).  The existing sum / attempts
			 * pair conflates hit-rate with mean-novelty-per-win;
			 * this discrete bump splits them. */
			__atomic_fetch_add(&kcov_shm->reexec_attempts_with_new_cmp,
					   1UL, __ATOMIC_RELAXED);
			__atomic_fetch_add(&kcov_shm->reexec_new_cmps_total,
					   inner_new_cmp, __ATOMIC_RELAXED);
			if (rec->nr < MAX_NR_SYSCALL)
				__atomic_fetch_add(
					&kcov_shm->per_syscall_cmp_novelty_reexec[rec->nr],
					inner_new_cmp, __ATOMIC_RELAXED);
			/* per-childop partition of the re-exec lift signal,
			 * sibling of the per-syscall sibling above.  Same
			 * inner_new_cmp accumulation; the childop dimension
			 * answers "which non-OP_SYSCALL childops are
			 * harvesting the bulk of the re-exec CMP novelty". */
			if (op_type < KCOV_CHILDOP_NR_MAX)
				__atomic_fetch_add(
					&kcov_shm->per_childop_cmp_novelty_reexec[op_type],
					inner_new_cmp, __ATOMIC_RELAXED);
			/* per-slot success counter.  Pair
			 * with reexec_attribution_slot_hist (the per-slot
			 * attempt-attribution histogram) to read per-slot
			 * success rate -- a slot that attracts the bulk of
			 * attributions but produces no novelty wins is
			 * wasted re-exec budget.  p->slot is 1-based and
			 * was bounds-checked at the consumer-side
			 * (p->slot <= entry->num_args) gate above. */
			if (p->slot >= 1 &&
			    p->slot <= CMP_REDQUEEN_SLOT_HIST_NR)
				__atomic_fetch_add(
					&kcov_shm->reexec_success_by_slot[p->slot - 1],
					1UL, __ATOMIC_RELAXED);
			/* Per-pending-buffer-index success counter, the
			 * A/B signal for --redqueen-pending-pick.  The
			 * caller's pick site clamps pending_idx to
			 * [0, child->reexec_pending_count) and the
			 * reexec_pending_count==0 short-circuit one level
			 * above guarantees count > 0 there, so a sane
			 * caller always lands in range -- the explicit
			 * REEXEC_PENDING_PICK_HIST_NR clamp here is
			 * defence in depth against a future caller
			 * passing an out-of-range index (or a corrupted
			 * reexec_pending_count value reaching
			 * rnd_modulo_u32 and rolling past the bound). */
			if (pending_idx < REEXEC_PENDING_PICK_HIST_NR)
				__atomic_fetch_add(
					&kcov_shm->reexec_pending_pick_success[pending_idx],
					1UL, __ATOMIC_RELAXED);
		}
	}

	/* Restore the dispatched-call state so downstream readers (the
	 * chain-corpus save in particular) see the parent's args / retval,
	 * not the re-exec's.  Wrap in a publish bracket so a watchdog
	 * sampling rec mid-restore does not catch the rec halfway between
	 * the re-exec values and the parent values. */
	srec_publish_begin(rec);
	rec->a1 = saved_a[0];
	rec->a2 = saved_a[1];
	rec->a3 = saved_a[2];
	rec->a4 = saved_a[3];
	rec->a5 = saved_a[4];
	rec->a6 = saved_a[5];
	rec->retval = saved_retval;
	rec->post_state = saved_post_state;
	rec->errno_post = saved_errno_post;
	srec_publish_end(rec);

	return ok;
}
