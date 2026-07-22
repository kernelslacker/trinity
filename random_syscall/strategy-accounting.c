/*
 * Strategy-window rotation and per-syscall reward / cohort attribution.
 * Everything the random-syscall cluster knows about the strategy
 * window bookkeeping lives here: the SR_* rotation gate, the
 * remote-adaptive decision helper called before dispatch, the bandit
 * / A-B cohort attribution helpers called after dispatch, and the
 * SHADOW warm-reserve / cold-overflow probes that ride the same
 * post-collect seam.
 *
 * maybe_rotate_strategy, remote_adaptive_decide, and the account_*
 * helpers are cross-cluster private and declared in
 * include/random-syscall-internal.h.
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
bool remote_adaptive_decide(unsigned int nr,
				   struct syscallentry *entry,
				   bool static_remote)
{
	unsigned long rcalls, redgec, lcalls, ledgec;
	bool would_demote = false, would_promote = false, would_force = false;
	bool would_gate_promote = false;
	bool adaptive_remote = static_remote;

	if (kcov_shm == NULL || nr >= MAX_NR_SYSCALL || entry == NULL)
		return static_remote;

	rcalls = __atomic_load_n(&kcov_shm->pc_ctx.remote_pc_calls[nr],
				 __ATOMIC_RELAXED);
	redgec = __atomic_load_n(&kcov_shm->pc_ctx.remote_pc_edge_calls[nr],
				 __ATOMIC_RELAXED);
	lcalls = __atomic_load_n(&kcov_shm->pc_ctx.local_pc_calls[nr],
				 __ATOMIC_RELAXED);
	ledgec = __atomic_load_n(&kcov_shm->pc_ctx.local_pc_edge_calls[nr],
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

	__atomic_fetch_add(&shm->stats.remote_adaptive.samples, 1UL,
			   __ATOMIC_RELAXED);
	if (would_demote)
		__atomic_fetch_add(&shm->stats.remote_adaptive.would_demote,
				   1UL, __ATOMIC_RELAXED);
	else if (would_promote)
		__atomic_fetch_add(&shm->stats.remote_adaptive.would_promote,
				   1UL, __ATOMIC_RELAXED);
	else if (would_force)
		__atomic_fetch_add(&shm->stats.remote_adaptive.would_force,
				   1UL, __ATOMIC_RELAXED);
	else
		__atomic_fetch_add(&shm->stats.remote_adaptive.agree, 1UL,
				   __ATOMIC_RELAXED);

	if (would_gate_promote)
		__atomic_fetch_add(
			&shm->stats.remote_adaptive.would_gate_promote,
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
void maybe_rotate_strategy(void)
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
		warn_now = __atomic_load_n(&kcov_shm->kmsg.kmsg_warn_fires,
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
	__atomic_store_n(&shm->stats.transition_edge.count_at_window_start,
			 __atomic_load_n(&shm->stats.transition_edge.count_by_strategy[next],
					 __ATOMIC_RELAXED),
			 __ATOMIC_RELAXED);
	__atomic_store_n(&shm->stats.transition_edge.calls_at_window_start,
			 __atomic_load_n(&shm->stats.transition_edge.calls_by_strategy[next],
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
				 __atomic_load_n(&kcov_shm->kmsg.kmsg_warn_fires,
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
void account_reexec_ab_cohort(struct childdata *child, unsigned long new_cmp)
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
 *   indexing the existing kcov_shm->per_syscall.per_syscall_edges array uses; the
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
void account_per_syscall_new_edges(struct childdata *child,
					  struct syscallrecord *rec,
					  unsigned long new_edge_count)
{
	if (new_edge_count > 0 && rec->nr < MAX_NR_SYSCALL) {
		unsigned long *bucket = child->is_explorer
			? shm->stats.picker_bandit.edges_per_syscall_explorer
			: shm->stats.picker_bandit.edges_per_syscall_bandit;
		__atomic_fetch_add(&bucket[rec->nr], new_edge_count,
				   __ATOMIC_RELAXED);
	}

	if (child->frontier_pick_regime != FRONTIER_PICK_NONE &&
	    rec->nr < MAX_NR_SYSCALL) {
		if (new_edge_count > 0) {
			__atomic_fetch_add(
				&shm->stats.frontier.per_syscall.productive_wins_per_syscall[rec->nr],
				1UL, __ATOMIC_RELAXED);
			__atomic_store_n(
				&shm->stats.frontier.per_syscall.last_productive_window_per_syscall[rec->nr],
				__atomic_load_n(&shm->bandit_window_count,
						__ATOMIC_RELAXED),
				__ATOMIC_RELAXED);
		} else if (child->frontier_pick_regime == FRONTIER_PICK_LIVE &&
			   !rec->validator_rejected) {
			unsigned long streak;

			__atomic_fetch_add(
				&shm->stats.frontier.per_syscall.live_misses_per_syscall[rec->nr],
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
				&shm->stats.frontier.per_syscall.live_miss_streak_per_syscall[rec->nr],
				1UL, __ATOMIC_RELAXED);
			if (streak >= FRONTIER_LIVE_MISS_COOLDOWN) {
				__atomic_fetch_add(
					&shm->stats.frontier.cooldown.live_would_skip,
					1UL, __ATOMIC_RELAXED);
				__atomic_fetch_add(
					&shm->stats.frontier.cooldown.live_would_skip_per_syscall[rec->nr],
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
					&shm->stats.frontier.cooldown.live_cooldown_candidates,
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
void account_pc_edge_only(struct childdata *child,
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
		__atomic_fetch_add(&shm->stats.picker_bandit.explorer_pool_edges_discovered,
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
		__atomic_fetch_add(&shm->stats.picker_bandit.bandit_pool_edges_discovered,
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
void account_transition_reward(struct childdata *child,
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
		&shm->stats.transition_edge.calls_by_strategy[strat],
		1UL, __ATOMIC_RELAXED);
	__atomic_fetch_add(
		&shm->stats.transition_edge.count_by_strategy[strat],
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
void account_fd_and_group(struct childdata *child,
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
