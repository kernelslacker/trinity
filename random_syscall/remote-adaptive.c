/*
 * Adaptive remote-KCOV mode disposition.  Consulted from dispatch_step
 * before the raw call to override the static remote_mode when lifetime
 * evidence disagrees with the static policy on this syscall.
 *
 * Carved out of strategy-accounting.c; the sibling seams (rotation,
 * per-syscall edge accounting, warm-cold reserve, fd+group accounting)
 * live in their own TUs under random_syscall/.
 *
 * remote_adaptive_decide is cross-cluster private and declared in
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
