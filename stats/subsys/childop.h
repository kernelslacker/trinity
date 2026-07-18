#ifndef _TRINITY_STATS_SUBSYS_CHILDOP_H
#define _TRINITY_STATS_SUBSYS_CHILDOP_H

#include "child-api.h"		/* NR_CHILD_OP_TYPES */

/*
 * Width of the per-childop decaying edge+wall recency ring
 * (edge_history[][] / wall_history[][]).  Matches
 * FRONTIER_DECAY_WINDOWS so the per-syscall and per-childop recency
 * horizons stay aligned -- a window rotation on either side ages out
 * the same wall-clock slice of history.  Must be a power of two; the
 * bump path masks the cursor with (CHILDOP_DECAY_WINDOWS - 1) to derive
 * the active slot.
 */
#define CHILDOP_DECAY_WINDOWS	8

/*
 * Per-childop accounting -- edge / call / setup / data-path / latch /
 * demote-promote / budget / wedge / wall-time / fd-delta / decay-
 * recency arrays plus scattered scalars.
 *
 * Bespoke (non-category) RAW group.  All arrays are indexed by enum
 * child_op_type (NR_CHILD_OP_TYPES slots).  The decay/recency ring
 * uses CHILDOP_DECAY_WINDOWS as the second axis; that macro stays
 * defined in include/stats.h.  RELAXED add-fetch throughout --
 * multi-producer (one writer per child).  The surrounding
 * struct stats_s composes an instance of struct childop_stats as
 * its "childop" member.
 */
struct childop_stats {
	/* Per-childop edge-discovery attribution, indexed by enum
	 * child_op_type.  Bumped per alt-op invocation in child_process()'s
	 * post-call have_kcov block with the same edges_after - edges_before
	 * delta that adapt_budget() consumes; CHILD_OP_SYSCALL is skipped to
	 * avoid double-counting (the syscall path attributes new edges via
	 * the explorer/bandit strategy counters).  Without this attribution
	 * alt-op childops bump the global kcov edge counter but contribute
	 * to no per-strategy total, so their coverage value is invisible to
	 * the operator and the gap between KCOV total and strategy totals
	 * is unexplained.  RELAXED add-fetch: a cumulative diagnostic, not
	 * an event log. */
	unsigned long edges_discovered[NR_CHILD_OP_TYPES];

	/* Per-childop NEW-EDGE-CALL count, indexed by enum child_op_type.
	 * Bumped by 1 (NOT by delta) in child_process()'s post-call
	 * have_kcov block whenever an alt-op invocation observed
	 * edges_after > edges_before, i.e. "this call found at least one
	 * new edge".  Parallel to bandit_pool_edges_discovered and
	 * explorer_pool_edges_discovered on the syscall path, which are
	 * also call-count counters (one bump per productive call,
	 * regardless of how many edges that call surfaced).
	 *
	 * Kept separate from childop_edges_discovered[] above so the
	 * stats panels keep showing the true edge total per alt-op while
	 * the plateau classifier's Rule 2 has an apples-to-apples
	 * comparator against the syscall-path call counters.  Without
	 * this split a single alt-op invocation that surfaces 10 edges
	 * moves the edge counter by 10 while the syscall path moves its
	 * counter by 1, and Rule 2's 2:1 ratio over-fires
	 * CHILDOP_DOMINANT on any plateau with a chatty alt-op.
	 * CHILD_OP_SYSCALL is skipped for the same reason as the edges
	 * counter.  RELAXED add-fetch: a cumulative diagnostic, not an
	 * event log. */
	unsigned long calls_with_edges[NR_CHILD_OP_TYPES];

	/* Per-childop clean edge count, indexed by enum child_op_type.
	 * Populated in child_process()'s post-call have_kcov block from
	 * the outer KCOV bracket's per-call delta (kcov_bracket_end's
	 * return value), so each bump reflects only the edges
	 * attributable to that single op's dispatch -- no sibling
	 * traffic mixed in.  Bracketed under the
	 * --childop-kcov-attribution=dual default and the equivalent on
	 * mode; stays at zero under mode=off (the documented opt-out).
	 *
	 * This is the steering signal: adapt_budget() consumes the
	 * per-call delta to drive the budget multiplier ratchet, and the
	 * canary queue's edges_for_op() reads the cumulative counter to
	 * size promote/demote decisions over a window.  The noisier
	 * childop_edges_discovered[] above is kept tracked as a
	 * diagnostic comparator so the operator can validate bracket
	 * coverage by diffing the two per op.  RELAXED add-fetch: a
	 * cumulative diagnostic, not an event log. */
	unsigned long edges_clean[NR_CHILD_OP_TYPES];

	/* Per-op invocation count: incremented once per alt-op iteration
	 * in child_process()'s post-call block, parallel to
	 * childop_edges_discovered[].  Indexed by child_op_type.
	 * CHILD_OP_SYSCALL is skipped for the same reason as the edges
	 * counter -- the syscall path attributes invocations through
	 * parent_stats.op_count / per-strategy totals already.
	 *
	 * Read by the canary queue to size its window in invocations of
	 * the currently-active canary op rather than fleet-wide op count.
	 * A canary slot in a large fleet otherwise saw its 10k 'iters'
	 * window close after only ~10000/(max_children/canary_slots) of
	 * its own invocations, so edge / crash thresholds were calibrated
	 * against a much smaller canary sample than the CLI help and the
	 * log labels imply.  RELAXED add-fetch: a cumulative diagnostic,
	 * not an event log. */
	unsigned long invocations[NR_CHILD_OP_TYPES];

	/* Per-childop "last successful dispatch" logical timestamp, indexed
	 * by enum child_op_type.  Stored as shm_published->fleet_op_count
	 * sampled at the moment the alt-op dispatch returned success (ret
	 * != FAIL), i.e. the same fleet-clock source the syscalls_todo
	 * termination check already reads inside child_process().  Set to
	 * 0 by the create_shm() memset; 0 is the "never succeeded" sentinel
	 * that dump_stats() interprets as a never-fired op (and so omits
	 * from the ranked table -- never-zero rows are skipped, matching
	 * the surrounding childop_edges_discovered[] / childop_calls_with_
	 * edges[] dumps).
	 *
	 * Read-only signal for dormancy detection: the operator (or a
	 * downstream reader) computes (current_fleet_op_count - ts) to see
	 * how long an op has been quiet.  No threshold / TTL / picker
	 * gating happens here -- this slot only records the timestamp
	 * and consumers decide what "dormant" means.  Multiple
	 * siblings dispatching the same op race on this slot; the last
	 * RELAXED store wins, which is exactly the "most recent observed
	 * success across the fleet" semantics dump_stats wants. */
	unsigned long last_success_ts[NR_CHILD_OP_TYPES];

	/* Per-childop "setup reached its accepted point" counter, indexed
	 * by enum child_op_type.  Bumped once per alt-op invocation that
	 * passed its one-shot setup / capability / namespace probe and
	 * reached the point where the childop considers itself ready to
	 * exercise the kernel under test.  Parallel to childop_invocations[]
	 * (which counts the dispatch entry) so the operator can read the
	 * setup-yield ratio per op:  setup_accepted / invocations.  A low
	 * ratio means the op is being dispatched but bouncing on early
	 * checks (missing config, denied capability, hostile netns) before
	 * any kernel-facing work.
	 *
	 * Producers are wired per-childop in a follow-on step; until then
	 * the array stays at 0 and the per-op dump simply omits the row
	 * (skip-zero convention, matching childop_edges_discovered[] et al).
	 * CHILD_OP_SYSCALL is skipped at the dump site for the same reason
	 * as the surrounding per-childop arrays.  RELAXED add-fetch: a
	 * cumulative diagnostic, not an event log. */
	unsigned long setup_accepted[NR_CHILD_OP_TYPES];

	/* Per-childop "data-path entry reached" counter, indexed by enum
	 * child_op_type.  Bumped once per alt-op invocation that crossed
	 * from the childop's setup/probe phase into the data-path region
	 * that actually issues kernel work (syscall / ioctl / write / etc.).
	 * Pairs with childop_setup_accepted[] above to factor the yield:
	 * setup_accepted - data_path is the count of invocations that
	 * accepted setup but bailed before exercising the data path (e.g.
	 * a fd-open succeeded but a later guard rejected the per-iter
	 * argument shape).  Together with childop_calls_with_edges[] /
	 * childop_edges_discovered[] this lets the operator separate
	 * "setup-bound" ops from "data-path-bound" ops.
	 *
	 * Producers are wired per-childop in a follow-on step; until then
	 * the array stays at 0.  CHILD_OP_SYSCALL is skipped at the dump
	 * site for the same reason as the surrounding per-childop arrays.
	 * RELAXED add-fetch: a cumulative diagnostic, not an event log. */
	unsigned long data_path[NR_CHILD_OP_TYPES];

	/* Per-childop one-shot latch reason, indexed by enum child_op_type.
	 * Set once (by the childop itself) at the moment the op disables
	 * itself for the remainder of the run.  Value is a compact code
	 * from enum childop_latch_reason (see include/child.h); rendered as
	 * the integer in the per-op dump.  0 (CHILDOP_LATCH_NONE) means
	 * "never latched off" and is the skip-zero default that matches
	 * create_shm()'s memset.
	 *
	 * Storage is per-op (NOT per-child) so the parent's dump shows a
	 * single global "this op gave up because X" reason for each
	 * latched-off op rather than a per-child reason ring.  Multiple
	 * siblings racing to latch the same op race on this slot; the
	 * last RELAXED store wins, which is fine -- the reasons are by
	 * construction permanent (an op that latched UNSUPPORTED in one
	 * child will latch UNSUPPORTED in its siblings on the same kernel),
	 * so any winner is correct.
	 *
	 * Producers are wired per-childop in a follow-on step; until then
	 * the array stays at 0 and the per-op dump simply omits the row. */
	unsigned long latch_reason[NR_CHILD_OP_TYPES];

	/* SHADOW recommendation counters, indexed by enum child_op_type.
	 * Bumped from close_window_and_decide() in child-canary.c whenever
	 * the score-driven recommended-state computation would respectively
	 * demote (THROTTLED / QUARANTINED / NO_OUTER_BRACKET) or promote
	 * (PROMOTED_CLEAN / PROMOTED_INTERFERENCE) the just-closed canary
	 * window.  The live promote/demote decision is byte-identical to the
	 * pre-shadow baseline: these counters only record what the new
	 * score-driven policy WOULD do, alongside whatever the live
	 * heuristic actually did.  Divergence between the two (e.g. live
	 * "zero_edges" demote vs shadow PROMOTED_INTERFERENCE because noisy
	 * edges accrued during the window) is the signal the 75.2.B
	 * enforcement work needs before it can take over the picker.
	 * CHILD_OP_SYSCALL is skipped at the bump site for the same reason
	 * as the surrounding per-childop arrays.  Single-writer (the canary
	 * tick runs in parent context); RELAXED add-fetch matches the
	 * surrounding per-childop counters' contract -- a cumulative
	 * diagnostic, not an event log. */
	unsigned long would_demote[NR_CHILD_OP_TYPES];
	unsigned long would_promote[NR_CHILD_OP_TYPES];

	/* Per-childop adaptive-budget multiplier, indexed by enum
	 * child_op_type.  Q8.8 fixed point: 256 == 1.0x.  Updated post-
	 * invocation by adapt_budget() based on the kcov_shm->edges_found
	 * delta observed during dispatch.  Read by the BUDGETED() macro
	 * inside opt-in childops so productive ops get more inner-loop
	 * iterations and dud ops shrink toward the floor.  Values clamp to
	 * [ADAPT_BUDGET_MIN, ADAPT_BUDGET_MAX]; a 0 entry means "uninit,
	 * fall back to 1.0x" so a wild-write to this region degrades to
	 * the existing fixed-budget behaviour rather than zeroing the loop. */
	uint16_t budget_mult[NR_CHILD_OP_TYPES];

	/* Consecutive invocations of an op_type whose edge delta did not
	 * clear ADAPT_BUDGET_THRESHOLD.  Reset to 0 on a productive
	 * invocation; once the streak hits ADAPT_BUDGET_ZERO_STREAK the
	 * shrink ratchet fires and the streak resets.  The hysteresis
	 * keeps a single noise dip from immediately halving the budget. */
	uint16_t zero_streak[NR_CHILD_OP_TYPES];

	/* Phase 2 plateau intervention (childop_dominant): count of
	 * pick_op_type() calls observed by non-dedicated children
	 * while shm->plateau_current_hypothesis ==
	 * PLATEAU_HYPOTHESIS_CHILDOP_DOMINANT, where the 25% alt-op
	 * burst threshold was applied in place of the default 5%
	 * rate.  Counts predicate-active picker invocations rather
	 * than picks that resolved to an alt-op -- cross-reference
	 * with the childop_invocations[] delta over plateau windows
	 * for the realised alt-op yield.  Bumped RELAXED for the same
	 * reason plateau_forced_windows is. */
	unsigned long burst_alt_picks_window;

	/* ---- Childop vs random-syscall effort split ----
	 *
	 * Three independent buckets so the periodic stats dump can show
	 * where the child loop actually spends effort: wall-clock time,
	 * dispatched syscalls, and outer-loop iterations.  Rendered as one
	 * childop_split block (raw numerators+denominators + percentages)
	 * by periodic_counter_rates_dump().
	 *
	 * Wall-time and the random-syscall dispatch denominator are written
	 * from child_process()'s per-op bracket in child.c.  The per-syscall
	 * counters are written from random_syscall_step()'s call-complete
	 * site, gated by the per-child in_childop flag the bracket sets for
	 * the duration of an alt-op op_fn.  All RELAXED add-fetch: cumulative
	 * diagnostic, multi-producer (one writer per child), lost-update
	 * races are tolerated and bounded by per-tick child counts.
	 *
	 * syscalls_in_childops counts only random_syscall-mediated calls
	 * issued from inside an alt-op bracket (e.g. sched_cycler's tight
	 * random_syscall() loop).  Childops that call libc / raw syscall()
	 * directly do not flow through the call-complete enqueue site and
	 * so are not counted here -- the wall-time and iteration metrics
	 * cover them. */
	unsigned long walltime_ns;
	unsigned long wall_ns[NR_CHILD_OP_TYPES];

	/* Per-op SIGALRM-timeout counters for the 1-second alt-op stall
	 * watchdog (arm at child.c is_alt_op `alarm(1)`, fire in the
	 * sigalrm_pending block at the top of the next iter, disarm at
	 * the post-dispatch `alarm(0)`).  childop_timeout_observed[op]
	 * is bumped when the alarm fired before the op returned;
	 * childop_timeout_missed[op] is bumped when the op returned
	 * before the alarm fired.  Bump-only at the existing arm/fire/
	 * disarm sites: no change to whether the alarm fires or to the
	 * reap path.  Both populate struct childop_outcome's
	 * timeout_observed / timeout_missed slots. */
	unsigned long timeout_observed[NR_CHILD_OP_TYPES];
	unsigned long timeout_missed[NR_CHILD_OP_TYPES];

	/* Per-op fd-delta instrumentation for leak triage.  Wraps each
	 * dispatched alt-op with a cheap "lowest free fd" probe
	 * (open("/dev/null", O_RDONLY|O_CLOEXEC); close()); the kernel
	 * returns the smallest unused fd number, so the delta between
	 * before/after is a monotonic proxy for net fd-table growth across
	 * the op.  A childop that opens fds and forgets to close some on
	 * an error path accumulates a positive delta; the leaker is the
	 * op whose fd_delta_positive_sum climbs unboundedly across a run.
	 * fd_delta_positive_ops counts distinct invocations where the
	 * delta was > 0 (so an averaged per-invocation growth is derivable
	 * from _sum / _ops). */
	unsigned long fd_delta_positive_sum[NR_CHILD_OP_TYPES];
	unsigned long fd_delta_positive_ops[NR_CHILD_OP_TYPES];

	/* SHADOW-ONLY per-childop stuck-child accounting.  Sister of the
	 * syscall_wedge_* pair above but keyed by enum child_op_type
	 * (childdata.op_type captured at latch time) instead of by syscall
	 * nr.  Wedging on this fleet is dominated by long-lived non-syscall
	 * childops (flock_thrash, futex_storm, memory_pressure, ...) whose
	 * inner sites cycle through many syscalls; the per-syscall top-N
	 * names whichever syscall happened to be in flight at detection,
	 * which mis-attributes the wedge cost to that syscall instead of to
	 * the childop that is actually parked.  This array gives the
	 * shutdown render a second top-N keyed by the childop, so the
	 * dominant wedgers surface by name.
	 *
	 *  childop_wedge_count[op]
	 *      Bumped once per stuck-child detection event, alongside
	 *      syscall_wedge_count[] in is_child_making_progress().  RELAXED
	 *      add-fetch -- diagnostic, not an event log.
	 *  childop_wedge_total_us[op]
	 *      Cumulative microseconds of unreusable-slot time across all
	 *      wedge events for this childop, added in reap_child() using
	 *      the same (now - wedge_start_tp) interval that feeds
	 *      syscall_wedge_total_us[] -- the two arrays share ONE duration
	 *      definition (full unreusable-slot time, watchdog grace
	 *      included; CLOCK_MONOTONIC; clamped >= 0 at the read site so a
	 *      reordered start-timestamp read cannot underflow).  RELAXED
	 *      add-fetch.
	 *
	 * Surfaced via dump_stats_top_wedging_childops() at shutdown only;
	 * not on the JSON path, matching the syscall_wedge_* siblings. */
	unsigned long wedge_count[NR_CHILD_OP_TYPES];
	unsigned long long wedge_total_us[NR_CHILD_OP_TYPES];

	/* SHADOW-ONLY per-childop decaying edge+wall recency ring.  Sister
	 * shape to the per-syscall frontier_history[][] / frontier_recent_
	 * count_cached[] pair (include/shm.h) but keyed by enum child_op_type
	 * and with SEPARATE storage -- the syscall ring is not aliased.  The
	 * ring is a fixed-width window of CHILDOP_DECAY_WINDOWS slots per op;
	 * the slot currently being filled is (childop_decay_slot &
	 * (CHILDOP_DECAY_WINDOWS - 1)).  Producers (child_process()'s per-
	 * dispatch wall and clean-edge accumulation sites in child.c) bump
	 * the active slot with the same delta they feed into
	 * childop_wall_ns[] / childop_edges_clean[], and bump the matching
	 * recent_cached counter in lockstep.  Window advance is driven by
	 * childop_window_advance() (child-altop.c) from the same periodic
	 * tick that runs the operator-visibility dumps; the rotator clears
	 * the next slot before publishing the new index, subtracts the just-
	 * cleared slot's contribution from the cached sum under a CAS retry
	 * (saturating-subtract guard against a racing producer fetch-add),
	 * and bumps the cursor only after every per-op clear has landed --
	 * matches frontier_window_advance()'s clear-then-publish discipline.
	 *
	 * SHADOW: no scheduler / picker / canary code reads either array;
	 * the only reader is stats/childop/local.c's
	 * dump_stats_childop_decay_recency() at shutdown.  RELAXED add-fetch
	 * on the per-slot bumps and cached counter -- multi-producer (one
	 * writer per child), lost-update races are tolerated and bounded by
	 * per-window child counts.
	 * Sum across the ring is the op's "recent" edge or wall total over
	 * the last CHILDOP_DECAY_WINDOWS rotations -- the input the future
	 * util-table reader (spec row C2's recent-ratio extension) will
	 * prefer over the cumulative childop_wall_ns[] / childop_edges_
	 * clean[] when the ring has signal. */
	unsigned long edge_history[NR_CHILD_OP_TYPES][CHILDOP_DECAY_WINDOWS];
	unsigned long wall_history[NR_CHILD_OP_TYPES][CHILDOP_DECAY_WINDOWS];
	unsigned long edge_recent_cached[NR_CHILD_OP_TYPES];
	unsigned long wall_recent_cached[NR_CHILD_OP_TYPES];
	unsigned int decay_slot;
};

#endif	/* _TRINITY_STATS_SUBSYS_CHILDOP_H */
