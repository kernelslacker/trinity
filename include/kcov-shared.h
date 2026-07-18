#pragma once

/* struct kcov_shared, its extern pointer, and per-nr accessors.
 * Split out of include/kcov.h.  Storage layout of struct kcov_shared
 * is offset-sensitive: consumers snapshot fields via __atomic_load_n
 * and stats/kcov_cmp.c indexes into fixed-length arrays here.  Do not
 * add alignment attributes, reorder fields, or insert nested structs
 * without matching updates in every consumer. */

#include <stddef.h>	/* offsetof */

#include "kcov-types.h"

/* Shared coverage state, allocated in shared memory. */
struct kcov_shared {
	/* Per-edge bucket-seen mask.  See KCOV_NUM_BUCKETS comment above for
	 * the bucket layout.  A child's atomic-OR on this byte that flips a
	 * never-seen bucket bit is the "new coverage" signal that drives the
	 * minicorpus and mutator-attribution feedback loops. */
	unsigned char bucket_seen[KCOV_NUM_EDGES];
	/* Count of (edge, bucket) bit-flips ever observed.  Since the
	 * bucket-seen table was introduced this is NOT the count of distinct
	 * edges -- a re-hit of a known edge that lands in a previously-unseen
	 * hit-count bucket bumps this counter, so it conflates "new code
	 * reached" with "known code reached at a new iteration depth".  Kept
	 * as the fine-grained feedback signal for the minicorpus / mutator-
	 * attribution consumers that want every novel bucket
	 * transition to register.  For the cardinality of edges ever reached
	 * -- the signal the coverage-plateau detector needs -- read
	 * distinct_edges below instead. */
	unsigned long edges_found;
	/* Count of distinct edges ever seen in any bucket: incremented exactly
	 * once per edge, on the bucket_seen[edge] == 0 -> first-bit transition
	 * in kcov_collect().  This is the true "new code reached" signal and
	 * the one the plateau detector samples; edges_found above grows with
	 * bucket churn on already-known edges and so its delta never falls to
	 * zero even when no new code is being reached. */
	unsigned long distinct_edges;
	/* Count of edges seeded into bucket_seen[] / edges_found by the
	 * warm-start cache loader at startup.  Zero on a cold-start run
	 * (no cache file, version/fingerprint mismatch, CRC failure, etc.).
	 * Set once after the cache-load loop completes and never mutated
	 * thereafter, so cold = edges_found - edges_warm_loaded is the
	 * subset of coverage actually discovered by this process — the
	 * operator-facing split that distinguishes "plateau near the prior
	 * corpus ceiling" from "plateau after genuinely exhausting easy
	 * edges this run". */
	unsigned long edges_warm_loaded;
	/* Mirror of edges_warm_loaded for the distinct_edges counter.
	 * Snapshotted to distinct_edges at warm-start load so a later
	 * (distinct_edges - distinct_edges_warm_loaded) subtraction is the
	 * count of truly new edges this process has discovered itself.
	 * Zero on a cold-start run. */
	unsigned long distinct_edges_warm_loaded;
	unsigned long total_pcs;
	unsigned long total_calls;
	unsigned long remote_calls;	/* calls using KCOV_REMOTE_ENABLE */
	/* Number of kcov_collect() calls where the kernel filled the entire
	 * trace buffer.  When non-zero a non-trivial fraction of syscalls
	 * are losing tail coverage and KCOV_TRACE_SIZE should be raised. */
	unsigned long trace_truncated;
	/* Total CMP records pulled out of per-child KCOV_TRACE_CMP buffers
	 * across all syscalls.  Diagnostic — confirms the second-fd CMP
	 * collection plumbing is producing records, and gauges how much
	 * raw signal reaches the future mutator consumer. */
	unsigned long cmp_records_collected;
	/* Number of kcov_collect_cmp() calls where the cmp buffer filled
	 * up.  Mirror of trace_truncated, sized off KCOV_CMP_BUFFER_SIZE. */
	unsigned long cmp_trace_truncated;
	/* Total number of dedup_inc() calls that walked the full probe chain
	 * without finding either an empty slot or the matching edge.  When
	 * this happens, the call's bucket fidelity collapses to old any-hit
	 * semantics (count forced to 1).  Non-zero suggests KCOV_DEDUP_SIZE
	 * may need to grow. */
	unsigned long dedup_probe_overflow;
	/* Largest probe distance observed by dedup_inc() so far.  Monotonic
	 * across the run; useful for sizing KCOV_DEDUP_SIZE relative to the
	 * fattest single-call edge load actually seen. */
	unsigned long dedup_max_probe_seen;
	/* Per-record CMP hints skipped because the calling child's seen-bloom
	 * indicated the (cmp_ip, value, size) tuple had already been pushed
	 * to the per-syscall pool within the recent window.  Each skip avoids
	 * a pool_lock + linear-scan dedup-refresh round-trip; the per-record
	 * granularity (vs per-cmp_hints_collect-call) makes the saved work
	 * directly comparable to cmp_records_collected. */
	unsigned long cmp_hints_bloom_skipped;
	/* Per-record CMP hints skipped because cmp_hints_strip[nr] is set
	 * for the calling syscall -- the entire trace buffer is short-
	 * circuited at cmp_hints_collect() entry, bypassing both the bloom
	 * lookup and the pool_add_locked path.  Targets are syscalls whose
	 * comparisons fire on task_struct / cred / ucounts / aio-table
	 * internal state set by prior syscalls or kernel init, not on
	 * values driven by the current syscall's argument surface; the
	 * resulting pool entries are unreachable from any consumer and
	 * only displace useful constants via LRU eviction.  Bumped at the
	 * per-record granularity (same units as cmp_hints_bloom_skipped
	 * and cmp_records_collected) so the avoided work is directly
	 * comparable across the three counters. */
	unsigned long cmp_hints_strip_skipped;
	/* Per-record CMP hints that produced an actual content change in a
	 * per-syscall pool — either a fresh insert into a non-full pool or an
	 * evict-replace once the pool was saturated.  Dedup-refresh hits (the
	 * tuple was already in the pool, only its last_used stamp was bumped)
	 * are NOT counted.  This is the right denominator for "how much unique
	 * signal did KCOV_TRACE_CMP actually contribute": cmp_records_collected
	 * counts every raw record the kernel emitted (hugely inflated by
	 * repetition on hot syscalls), bloom_skipped counts the per-child
	 * short-circuits, and unique_inserts is what's left — the records that
	 * survived bloom + pool dedup and changed pool state. */
	unsigned long cmp_hints_unique_inserts;
	/* cmp_hints_try_get() return values that the calling argument
	 * generator actually committed to the produced syscall argument
	 * (returned the hint directly, or OR'd it into a flags mask).
	 * Aggregated across all callsites -- granularity is per-counter,
	 * not per-callsite, because the operator question this answers
	 * ("does the hint pipeline reach syscall args at all?") doesn't yet
	 * need the per-callsite split.  Subset of cmp_hints_try_get_returned:
	 * the gap between the two is callsites that pulled a hint but then
	 * discarded it (none today, but the slot exists for future
	 * branchier consumers). */
	unsigned long cmp_hints_injected;
	/* Bumped by gen_undefined_arg when prop_ring_try_get returns
	 * a value the per-child propagation ring captured from an
	 * earlier syscall return.  Sibling counter to cmp_hints_injected:
	 * same callsite, different value source (trinity-observed return
	 * vs kernel KCOV_TRACE_CMP).  Cumulative; stats.c reports the
	 * per-window delta alongside the cmp_hints counters. */
	unsigned long propagation_injected;
	/* Per-callsite split of the flat propagation_injected scalar above,
	 * indexed by enum prop_injected_callsite.  Bumped in lock-step with
	 * the flat counter at each of the two producer sites in
	 * generate-args.c (handle_arg_op -> ARG_OP, gen_undefined_arg ->
	 * ARG_UNDEFINED).  Aggregated across all syscalls; the "which
	 * argtype-handler is responsible for the bulk of prop_ring
	 * deliveries" question is callsite-shaped, not syscall-shaped, so
	 * the flat scalar above answers the rate question and this array
	 * answers the attribution question.  Shape mirrors
	 * cmp_hint_callsite_injected[] below. */
	unsigned long propagation_injected_callsite[PROP_INJECTED_CALLSITE_NR];
	/* cmp_hints_try_get() calls that the chaos-mode gate forced to
	 * return false.  Bumped after the shm/nr guard, before the pool
	 * lookup, when cmp_hints_chaos_active() is true for the current
	 * rotation window.  Subtracted from the apparent attempt->returned
	 * funnel: a window where chaos is active inflates attempts without
	 * a matching returned bump and the difference shows up here.
	 * Cumulative -- chaos windows fire on a fixed modulo of the bandit
	 * window rotation, so the delta over a stats interval is roughly
	 * try_get_attempts * (1 / CHAOS_WINDOW_MODULO) in steady state. */
	unsigned long cmp_hints_chaos_suppressed;
	/* Chaos-mode state.  Window count + active flag both live in shm
	 * so all children see the same chaos schedule -- the CAS-winning
	 * child in maybe_rotate_strategy updates them, every child reads
	 * the flag in cmp_hints_try_get.  When these were file-scope
	 * statics in cmp_hints.c each child had its own copy and the
	 * schedule never crossed a fork: cmp_hints_chaos_suppressed
	 * stayed at 0 across long multi-child runs. */
	unsigned long cmp_hints_chaos_window_count;
	unsigned int  cmp_hints_chaos_active;
	/* Flat per-event WARN-fires counter, bumped from kmsg_monitor_thread
	 * each time classify_kmsg_event() returns a non-UNKNOWN kind --
	 * every classified WARN / BUG / OOPS / RCU / lockdep splat counts
	 * once regardless of flavour.  Cohort attribution against
	 * cmp_hints_chaos_active happens at bandit window close in
	 * maybe_rotate_strategy: a delta over the window is bucketed into
	 * the chaos-on or chaos-off slot per arm, so the operator can see
	 * whether chaos-suppressed cmp-hint generation actually produces
	 * more kernel diagnostic fires than the baseline.  Flat (no
	 * per-flavour split) for V2 -- per-flavour breakdown is V2.1 once
	 * any signal exists to slice. */
	unsigned long kmsg_warn_fires;
	/* Wild-write detection in the cmp_hints SHM pool.  Bumped when a
	 * read path (cmp_hints_try_get / pool_add_locked) observes a
	 * pool->count value above the CMP_HINTS_PER_SYSCALL hard cap --
	 * the only way that can happen is a kernel-side store through a
	 * fuzzed syscall arg pointer landing on the count field.  Without
	 * this gate the bogus count drives rnd_modulo_u32 to a wild index
	 * and the entries[].value load walks off the 1.1 MB SHM mapping. */
	unsigned long cmp_hints_count_oob;
	/* Companion canary-channel counters bumped from the same gate.
	 * Probed only on a count_oob hit, so the cost is paid only when
	 * a stomp has already happened; in steady state these stay at 0
	 * and the canary loads never run.  A direct stomp that lands
	 * exactly on the count field (4 bytes at the cap-violating
	 * offset) trips NONE of these -- only cmp_hints_count_oob -- so
	 * a real wild-write event commonly surfaces as count_oob > 0
	 * with all three canary counters at 0.  Non-zero canary deltas
	 * narrow the stomp's width and direction:
	 *  - canary_lock_post: write overshot the lock or undershot
	 *    the count area, landing between offset 24 and 32 in the
	 *    pool (gap between lock_t and count).
	 *  - canary_pre: write reached entries[] from the header side
	 *    (overshot last_used_stamp into entries).
	 *  - canary_post: write reached entries[] from the tail side
	 *    (overran entries[] from beyond the last slot). */
	unsigned long cmp_hints_canary_lock_post_corrupt;
	unsigned long cmp_hints_canary_pre_corrupt;
	unsigned long cmp_hints_canary_post_corrupt;
	/* A/B cohort split + per-arm baseline-injection fire counts +
	 * per-call divergence counter for the cmp-hint baseline inject denom
	 * A/B (Arm A = 1-in-16, Arm B = 1-in-12).  cmp_inject_arm_{a,b}_
	 * children is bumped once per child in init_child_runtime_config so
	 * the operator can normalise the per-arm fire rate against the
	 * realised population split (the ONE_IN(2) stamp has fleet-scale
	 * variance and a small fleet can land lopsided).  cmp_inject_arm_b_
	 * baseline_fires counts the baseline-callsite ONE_IN that fired on an
	 * Arm B child; the matching Arm A count is the existing
	 * cmp_hint_callsite_injected[] baseline buckets minus this delta, but
	 * a flat sibling counter is provided here too for read-ergonomics.
	 * cmp_inject_denom_diverged is bumped once per baseline-callsite call
	 * on an Arm B child when the same uniform sample would have produced
	 * a different fire/skip decision for Arm A than for Arm B (the
	 * helper rolls one sample in [0, lcm(16,12)) and tests both denoms).
	 * Bumping only on Arm B children leaves Arm A's per-call RNG
	 * sequence byte-identical to before this row -- the divergence
	 * counter is a lower bound on the per-call decision delta but
	 * preserves the A-arm-purity invariant the A/B row demands. */
	unsigned int  cmp_inject_arm_a_children;
	unsigned int  cmp_inject_arm_b_children;
	unsigned long cmp_inject_arm_a_baseline_fires;
	unsigned long cmp_inject_arm_b_baseline_fires;
	unsigned long cmp_inject_denom_diverged;
	/* A/B cohort split + per-arm fire count for the prop_ring injection at
	 * handle_arg_op's ARG_OP callsite.  prop_ring_argop_arm_{a,b}_children
	 * is bumped once per child in init_child_runtime_config so the operator
	 * can normalise the Arm B fire rate against the realised population
	 * split (the ONE_IN(2) stamp has fleet-scale variance and a small fleet
	 * can land lopsided).  prop_ring_argop_arm_b_fires counts the Arm B
	 * pulls that returned a recent kernel-handed-back scalar and committed
	 * it as the ARG_OP command code; Arm A never pulls so the symmetric
	 * arm_a counter does not exist by design.  Fires are also reflected in
	 * the existing flat propagation_injected counter so the operator can
	 * read the combined prop_ring contribution across both consumer sites
	 * (gen_undefined_arg + handle_arg_op) without re-summing. */
	unsigned int  prop_ring_argop_arm_a_children;
	unsigned int  prop_ring_argop_arm_b_children;
	unsigned long prop_ring_argop_arm_b_fires;
	/* A/B cohort split + per-kind consume counters for the typed
	 * prop_ring consumer rows at the gen_arg_* callsites
	 * (prop_ring_typed_arm_b).  prop_ring_typed_arm_{a,b}_children
	 * is bumped once per child in init_child_runtime_config so the
	 * operator can normalise the per-kind fire rate against the
	 * realised population split (the ONE_IN(2) stamp has fleet-scale
	 * variance and a small fleet can land lopsided).  Arm A never
	 * pulls at these callsites so the symmetric arm_a fire counter
	 * does not exist by design.
	 *
	 * prop_ring_kind_consumed[K] counts Arm B same-kind pulls that
	 * returned a recent kernel-handed-back scalar tagged K from the
	 * ring; slot 0 (SCALAR_UNTYPED) stays at zero by construction
	 * since the typed entry point rejects it on the caller side.
	 * prop_ring_kind_escape_fires counts the chaos-escape lane
	 * (a typed callsite that took an any-kind slot via the 1-in-N
	 * escape hatch), kept out of the per-kind buckets so the kind-
	 * discipline signal is not polluted by escape-hatch traffic.
	 * Sum across non-zero buckets + escape_fires is the total Arm B
	 * typed-pull commit count; it is NOT mirrored into
	 * propagation_injected because that counter is the
	 * gen_undefined_arg / handle_arg_op (untyped consumer) total
	 * and the typed sites are a separate channel by design. */
	unsigned int  prop_ring_typed_arm_a_children;
	unsigned int  prop_ring_typed_arm_b_children;
	unsigned long prop_ring_kind_consumed[SCALAR_NR_KINDS];
	unsigned long prop_ring_kind_escape_fires;
	/* A/B cohort split for the frontier_cold_weight blend promotion
	 * stamp (frontier_blend_arm_b).  frontier_blend_arm_{a,b}_children
	 * is bumped once per child in init_child_runtime_config so the
	 * operator can normalise the realised population split against the
	 * fleet-scale variance of the ONE_IN(2) stamp (a small fleet can
	 * land lopsided).  Observation-only -- the counters do not
	 * influence the blend weight or the picker; they are the
	 * denominator the existing frontier_blend_samples /
	 * frontier_blend_new_{lower,higher,equal} totals (in shm->stats,
	 * fed from both arms in lock-step) and the live Arm B promotion
	 * delta are normalised against. */
	unsigned int  frontier_blend_arm_a_children;
	unsigned int  frontier_blend_arm_b_children;
	/* A/B cohort split for the errno-plateau decay stamp
	 * (frontier_errno_decay_arm_b).  frontier_errno_decay_arm_{a,b}_
	 * children is bumped once per child in init_child_runtime_config so
	 * the operator can normalise the realised population split against
	 * the fleet-scale variance of the ONE_IN(2) stamp (a small fleet can
	 * land lopsided).  Companion to the frontier_errno_decay_* shm->stats
	 * counters bumped at the picker site: the latter measure the would-be
	 * and actual demote rates; the cohort split is the denominator the
	 * Arm-B-only live reject rate is normalised against. */
	unsigned int  frontier_errno_decay_arm_a_children;
	unsigned int  frontier_errno_decay_arm_b_children;
	/* A/B cohort split for the silent-streak decay stamp
	 * (frontier_silent_decay_arm_b).  frontier_silent_decay_arm_{a,b}_
	 * children is bumped once per child in init_child_runtime_config so
	 * the operator can normalise the realised population split against the
	 * fleet-scale variance of the ONE_IN(2) stamp (a small fleet can land
	 * lopsided).  Companion to the frontier_silent_decay_live_rejects
	 * shm->stats counter bumped at the picker site and to the symmetric
	 * frontier_decay_would_skip shadow counter that bumps for both arms:
	 * the cohort split is the denominator the Arm-B-only live reject rate
	 * is normalised against.  Shape matches frontier_errno_decay_arm_{a,b}
	 * _children above so the population-normalisation pattern stays
	 * uniform across the A/B rows. */
	unsigned int  frontier_silent_decay_arm_a_children;
	unsigned int  frontier_silent_decay_arm_b_children;
	/* A/B cohort split for the adaptive remote-KCOV mode stamp
	 * (remote_adaptive_arm_b).  remote_adaptive_arm_{a,b}_children is
	 * bumped once per child in init_child_runtime_config so the operator
	 * can normalise the realised population split against the fleet-
	 * scale variance of the ONE_IN(2) stamp (a small fleet can land
	 * lopsided).  Companion to the remote_adaptive_* shm->stats counters
	 * bumped at the dispatch_step site: the latter measure the would-be
	 * demote / promote dispositions across BOTH arms in lock-step; the
	 * cohort split is the denominator the Arm-B-only live mode flip is
	 * normalised against.  Shape matches frontier_blend_arm_{a,b}_
	 * children above so the population-normalisation pattern stays
	 * uniform across the A/B rows. */
	unsigned int  remote_adaptive_arm_a_children;
	unsigned int  remote_adaptive_arm_b_children;
	/* See struct kcov_cmp_diag — child-context writes are routed here
	 * because the child's stdout has already been dup2'd to /dev/null
	 * by the time KCOV_TRACE_CMP setup runs. */
	struct kcov_cmp_diag cmp_diag;
	struct kcov_pc_diag pc_diag;
	/* Per-mode child population counters, bumped once per child in
	 * kcov_init_child after the cmp_capable probe.  Surfaced through
	 * print_kcov_cmp_diag so the operator can confirm the realised
	 * mode mix matches KCOV_CMP_CHILD_RECIPROCAL.  Diagnostic only —
	 * nothing depends on these for control flow. */
	unsigned int pc_mode_children;
	unsigned int cmp_mode_children;
	/* Childop bracket attempt + skip-reason counters.  Every gated
	 * kcov_bracket_begin() call from child.c bumps childop_kcov_attempts
	 * once; the begin then either fires (childop_kcov_bracketed) or
	 * short-circuits at one of the three reject arms (skipped_cmp /
	 * skipped_nested / skipped_inactive — see kcov_bracket_begin in
	 * kcov.c for the reject contract).  The arms are mutually exclusive
	 * per attempt, so the invariant
	 *   attempts == bracketed + skipped_cmp + skipped_nested
	 *             + skipped_inactive
	 * holds at run end (and is the smoke-test gate on this row).
	 * Prereq for the childop-dual default flip: without the
	 * per-reason split a low childop_edges_clean / attempts ratio can't
	 * be told apart from "bracket never fired because of a known
	 * short-circuit" vs "bracket fired but found nothing". */
	unsigned long childop_kcov_attempts;
	unsigned long childop_kcov_bracketed;
	unsigned long childop_kcov_skipped_cmp;
	unsigned long childop_kcov_skipped_nested;
	unsigned long childop_kcov_skipped_inactive;
	/* Per-childop mirrors of the aggregate childop_kcov_* counters above,
	 * indexed by enum child_op_type.  Sized to KCOV_CHILDOP_NR_MAX (same
	 * bound as childop_kcov_trace_truncated[] below); kcov.c's build-time
	 * assertion on NR_CHILD_OP_TYPES applies to this shape as well.
	 *
	 * The aggregate counters answer "did any childop's outer bracket get
	 * declined for reason X?", but cannot say WHICH ops were affected.
	 * That distinction matters for the canary queue: a childop_edges_
	 * clean[op] == 0 window is indistinguishable from "signal unavailable
	 * (MODE ARTIFACT of the CMP-mode PC-bracket rejection)" without a
	 * per-op reason attribution.  These slots let close_window_and_
	 * decide() detect the confounded shape and route it to the
	 * unattributed_edges recommendation instead of silently promoting on
	 * discovered-only traffic or demoting a still-productive op.
	 *
	 * Producers are in child_process() (child/child.c), mirroring the
	 * decision tree kcov_bracket_begin() runs.  Kept in sync with that
	 * function; if a new reject arm is added there, add the matching
	 * per-op counter here and a bump in the caller.
	 *
	 * Invariant per op:
	 *   childop_kcov_op_attempts[op] ==
	 *       childop_kcov_op_bracketed[op]
	 *     + childop_kcov_op_skipped_cmp[op]
	 *     + childop_kcov_op_skipped_nested[op]
	 *     + childop_kcov_op_skipped_inactive[op]
	 * (the smoke-test gate on this row, parallel to the aggregate one). */
	unsigned long childop_kcov_op_attempts[KCOV_CHILDOP_NR_MAX];
	unsigned long childop_kcov_op_bracketed[KCOV_CHILDOP_NR_MAX];
	unsigned long childop_kcov_op_skipped_cmp[KCOV_CHILDOP_NR_MAX];
	unsigned long childop_kcov_op_skipped_nested[KCOV_CHILDOP_NR_MAX];
	unsigned long childop_kcov_op_skipped_inactive[KCOV_CHILDOP_NR_MAX];
	/* Per-childop trace-truncation count, indexed by enum child_op_type
	 * (op = nr - CHILDOP_KCOV_NR_BASE inside kcov_collect()).  Mirrors
	 * per_syscall_diag[].trace_truncated for the childop bracket path:
	 * bumped when the kernel filled the entire trace buffer for a
	 * bracketed childop call so the tail of the trace was dropped.
	 * Sized to KCOV_CHILDOP_NR_MAX; a build-time assertion in kcov.c
	 * pins NR_CHILD_OP_TYPES below the bound. */
	unsigned long childop_kcov_trace_truncated[KCOV_CHILDOP_NR_MAX];
	/* Per-syscall count of CALLS that produced at least one new edge.
	 * NOT a real edge bucket count — a syscall that uncovers 50 distinct
	 * new edges in one call bumps this by 1, not by 50.  The real
	 * bucket-edge count is the kcov_collect() new_edge_count out-param,
	 * accumulated into per-strategy and per-pool fields elsewhere.  The
	 * field name predates the call-count vs edge-count distinction; kept
	 * for ABI compatibility with the cold-skip heuristic and the
	 * top-syscalls dump in stats.c. */
	/* [nr][do32 ? 1 : 0] -- 32-bit and 64-bit paths bump their own
	 * slot so IA32 compat entries no longer merge with the 64-bit
	 * total; readers that want the pre-split per-nr value sum both
	 * dims via per_syscall_edges_total() / _calls_total() below. */
	unsigned long per_syscall_edges[MAX_NR_SYSCALL][2];
	unsigned long per_syscall_calls[MAX_NR_SYSCALL][2];
	/* EXTRA_FORK dispatches (execve, execveat, vfork) run their real
	 * syscall in a throwaway grandchild that do_extrafork() spawns
	 * OUTSIDE the parent worker's kcov_enable / syscall / kcov_disable
	 * bracket, so kcov_collect() never fires for them and both
	 * per_syscall_calls[nr] and per_syscall_edges[nr] stay at zero
	 * for the life of the run.  Without a dedicated denominator these
	 * syscalls read as permanently dead in edges/calls productivity
	 * ratios (0 edges out of 0 tracked calls) even though the fuzzer
	 * IS dispatching them thousands of times.  Bumped once per
	 * EXTRA_FORK bypass from kcov_note_extrafork() below so consumers
	 * (stats.c JSON emit, downstream analysis) can distinguish "dead
	 * syscall" from "coverage-inherently-unmeasurable via kcov". */
	unsigned long per_syscall_extrafork_calls[MAX_NR_SYSCALL];
	unsigned long last_edge_at[MAX_NR_SYSCALL];
	/* Snapshot of per_syscall_edges at the previous stats interval.
	 * Used to compute per-interval growth rate of the call-count signal
	 * above. */
	unsigned long per_syscall_edges_previous[MAX_NR_SYSCALL][2];
	/* Warm-loaded priors from the previous session's bitmap save.
	 * Never bumped during this run -- frozen at warm-start.  Empty
	 * (all-zero) on cold-start or when the priors blob in the bitmap
	 * file failed its CRC check.  Consumers treat these as soft
	 * priors -- current-run evidence in per_syscall_edges[] /
	 * per_syscall_calls[] overrides them as soon as it accumulates. */
	unsigned long per_syscall_edges_prior[MAX_NR_SYSCALL][2];
	unsigned long per_syscall_calls_prior[MAX_NR_SYSCALL][2];
	/* Per-syscall warm-known hit counter.  Bumped from kcov_collect()
	 * when the kernel emitted PCs into the trace buffer for this
	 * call (count > 0) but no new bucket bit flipped (found_new ==
	 * false) -- i.e. the syscall is exercising kernel code that's
	 * already in bucket_seen[].  Useful both as a liveness signal
	 * (the syscall is doing real work even if no new coverage) and
	 * as a divisor for productivity ratios.  Conflates "warm from
	 * prior session" with "already-seen this run"; the loss matters
	 * less than the cold-skip gate's need to distinguish dead
	 * syscalls from quietly-exercised ones. */
	unsigned long per_syscall_warm_known_hits[MAX_NR_SYSCALL];
	/* Sum of per_syscall_warm_known_hits[] across all nr.  Run-wide
	 * counter for the periodic stats dump so the warm-known signal
	 * is visible without iterating MAX_NR_SYSCALL slots.  Write-dead:
	 * migrated to the per-child stats_ring drain into
	 * parent_stats.total_warm_known_hits; the field is retained so
	 * the shared-mapping ABI does not shift. */
	unsigned long total_warm_known_hits;
	/* Per-syscall SHADOW-ONLY clean-vs-noisy attribution counters.  The
	 * existing per_syscall_edges[] is a per-thread, per-call, trace-
	 * isolated "clean" signal (kcov_collect() bumps it only on the
	 * found_new branch, from this task's own trace walk).  What was
	 * missing was a per-syscall analogue of the global-delta counter the
	 * childop path already carries in childop_edges_discovered[]: how
	 * many new edges accrued to the shared bucket_seen[] hash across all
	 * children during this syscall's enable/disable window, regardless
	 * of which child was the dedup-race winner.  The ratio of the two
	 * (clean numerator, sampled global-delta denominator) is the
	 * attribution-confidence signal Phase 2 will consume; Phase 1
	 * records it alongside the existing counters and NO selection or
	 * scoring code reads it.
	 *
	 *   per_syscall_edges_noisy[nr]     Sum of edges_found deltas across
	 *                                   the sampled windows for this nr.
	 *                                   Bumped from dispatch/syscall.c
	 *                                   around the syscall's enable/
	 *                                   disable pair only on the 1-in-N
	 *                                   sampled call (see
	 *                                   frontier_noise_sample in
	 *                                   include/params.h).
	 *   per_syscall_noisy_samples[nr]   Count of windows actually
	 *                                   sampled for this nr; the
	 *                                   denominator that lets a reader
	 *                                   scale per_syscall_edges_noisy
	 *                                   back up by N to estimate the
	 *                                   full-population delta.
	 *   per_syscall_edges_clean_remote[nr]
	 *                                   Subset of the per_syscall_edges
	 *                                   found_new bumps that fired under
	 *                                   kc->remote_mode -- the remote-
	 *                                   context cross-attribution split
	 *                                   (kernel copies coverage from
	 *                                   remote contexts into this task's
	 *                                   trace_buf, so the credited edge
	 *                                   may not be causally tied to this
	 *                                   syscall's own kernel work).
	 *                                   (per_syscall_edges - this) is
	 *                                   the local-only clean signal.
	 *
	 * Sampling default: frontier_noise_sample==0 (feature fully off);
	 * the sampled edges_found loads are the only new hot-path cost, so
	 * the default build issues zero new loads and stays byte-identical
	 * on selection to the pre-row baseline.  SHADOW-ONLY: no live
	 * picker or accept-gate reads any of these three counters. */
	unsigned long per_syscall_edges_noisy[MAX_NR_SYSCALL];
	unsigned long per_syscall_noisy_samples[MAX_NR_SYSCALL];
	unsigned long per_syscall_edges_clean_remote[MAX_NR_SYSCALL];
	/* Per-syscall split of kcov_collect() activity by collection mode.
	 * A remote-sampled syscall lands in a DIFFERENT mode (the kernel
	 * puts the task in KCOV_MODE_REMOTE and drops synchronous local
	 * PC), so a static remote-sampling policy can spend half a
	 * syscall's samples on a mode with no annotated producer --
	 * invisible today behind the single global remote_calls counter.
	 * local_pc_calls / remote_pc_calls count every kcov_collect()
	 * invocation in that mode (apples-to-apples against
	 * per_syscall_calls[] which still tracks both modes summed).
	 * local_pc_edge_calls / remote_pc_edge_calls count calls that
	 * produced >= 1 fresh edge (call-count semantics matching
	 * per_syscall_edges[]).  local_pc_edge_count / remote_pc_edge_count
	 * carry the raw fresh-edge tally so a single big call is not
	 * flattened to the same weight as a tiny one.  All bumped in
	 * kcov_collect() keyed on kc->remote_mode. */
	unsigned long local_pc_calls[MAX_NR_SYSCALL];
	unsigned long remote_pc_calls[MAX_NR_SYSCALL];
	unsigned long local_pc_edge_calls[MAX_NR_SYSCALL];
	unsigned long remote_pc_edge_calls[MAX_NR_SYSCALL];
	unsigned long local_pc_edge_count[MAX_NR_SYSCALL];
	unsigned long remote_pc_edge_count[MAX_NR_SYSCALL];
	/* Per-childop mirror of the local/remote PC split above, sized
	 * to KCOV_CHILDOP_NR_MAX and indexed by op = nr -
	 * CHILDOP_KCOV_NR_BASE inside kcov_collect().  Same semantics as
	 * the per-syscall arrays; same bump keyed on kc->remote_mode. */
	unsigned long childop_local_pc_calls[KCOV_CHILDOP_NR_MAX];
	unsigned long childop_remote_pc_calls[KCOV_CHILDOP_NR_MAX];
	unsigned long childop_local_pc_edge_calls[KCOV_CHILDOP_NR_MAX];
	unsigned long childop_remote_pc_edge_calls[KCOV_CHILDOP_NR_MAX];
	unsigned long childop_local_pc_edge_count[KCOV_CHILDOP_NR_MAX];
	unsigned long childop_remote_pc_edge_count[KCOV_CHILDOP_NR_MAX];
	/* Per-syscall accounting of the KCOV_REMOTE_ENABLE attempt path.
	 * The local_pc_calls / remote_pc_calls split above attributes calls
	 * by the mode the kernel ultimately produced coverage in, which
	 * folds "remote was attempted and the kernel refused" into the
	 * local-mode column -- a HEAVY-flagged syscall whose
	 * KCOV_REMOTE_ENABLE consistently returns EBADF reads as "zero
	 * remote yield" through the yield-side counters, indistinguishable
	 * from "remote was sampled and the kernel actually ran the work on
	 * the calling task".  These four counters partition the enable path
	 * itself so a genuinely zero-yield remote syscall (kernel ran
	 * remote, found nothing) can be told apart from one where remote
	 * was never actually enabled (EBADF losses, EINVAL, etc.):
	 *   remote_enable_requested  -- entered kcov_enable_remote() and
	 *                               about to attempt the ioctl.
	 *   remote_enable_succeeded  -- the KCOV_REMOTE_ENABLE ioctl
	 *                               returned 0; the call genuinely
	 *                               sampled remote coverage.
	 *   remote_enable_failed     -- the KCOV_REMOTE_ENABLE ioctl
	 *                               exhausted its EINTR retries or
	 *                               returned a non-EINTR error and
	 *                               flipped remote_capable=false.
	 *   remote_fallback_to_local -- after a failed remote enable, the
	 *                               PC-mode fallback ioctl in turn
	 *                               succeeded, so the child finished
	 *                               the syscall in local mode.
	 * All bumped inside kcov_enable_remote() keyed on the nr it now
	 * takes as a parameter; childop callers (nr >= CHILDOP_KCOV_NR_BASE)
	 * bypass the bumps via the standard nr < MAX_NR_SYSCALL gate. */
	unsigned long remote_enable_requested[MAX_NR_SYSCALL];
	unsigned long remote_enable_succeeded[MAX_NR_SYSCALL];
	unsigned long remote_enable_failed[MAX_NR_SYSCALL];
	unsigned long remote_fallback_to_local[MAX_NR_SYSCALL];
	/* Per-syscall 8-bucket errno histogram.  Sibling to the
	 * per_syscall_edges/calls counters above: those track coverage-side
	 * activity per syscall; this tracks the shape of what the kernel
	 * returned.  Bumped from handle_syscall_ret() once per completed
	 * syscall (state == AFTER), bucket index selected by the
	 * ERRNO_BUCKET_* enum below.  Surfaced via dump_stats() as a
	 * sibling block to the top-edges / cold-syscalls tables so the
	 * operator can tell at a glance which syscalls are EFAULT-heavy
	 * vs EINVAL-heavy.  Per-syscall entry->errnos[] already exists but
	 * is sized NR_ERRNOS (133) per syscall and is the per-syscallentry
	 * tally consumed by dump_entry(); this is the kcov_shm-resident
	 * compact view that pairs with the coverage tables above and lives
	 * in the same dump section. */
	unsigned long per_syscall_errno[MAX_NR_SYSCALL][ERRNO_BUCKET_NR];
	/* Per-syscall errno-bucket "seen at least once in this run" bitmask.
	 * Bit `bucket` set iff a call with errno bucket `bucket` has been
	 * classified for syscall slot nr.  Set via __atomic_fetch_or by the
	 * errno-gradient-save trigger in handle_syscall_ret() to detect
	 * "first non-EFAULT bucket per syscall per window" events; the EFAULT
	 * bit is deliberately never set (the trigger excludes EFAULT, the
	 * userspace-pointer noise floor, so its seen-state is uninteresting).
	 * SHADOW-ONLY: no live selection or scoring code consumes this; only
	 * the errno-gradient save predicate reads it.  RELAXED atomics --
	 * concurrent writers across children can race a bit-set with no harm
	 * (the loser's first-seen test fails, the winner's succeeds; either
	 * way the bit lands set). */
	unsigned int errno_bucket_seen[MAX_NR_SYSCALL];
	/* Sibling of last_edge_at: stamps total_calls at the moment the
	 * most recent EFAULT return was observed for this syscall slot.
	 * Lets a future picker pass bias selection away from syscalls
	 * stuck in pure-EFAULT regimes (no recent edges + a recent EFAULT
	 * stamp is the diagnostic signature).  Stored as the same
	 * total_calls counter last_edge_at uses so the two fields are
	 * directly comparable (delta = last_edge_at[nr] - last_efault_at[nr]
	 * is a signed "has progress outrun the fault?" signal). */
	unsigned long last_efault_at[MAX_NR_SYSCALL];
	/* Per-syscall counterpart of cmp_hints_unique_inserts: every fresh
	 * insert or evict-replace in pools[nr] bumps slot nr.  Dedup-refresh
	 * hits are NOT counted, matching the global counter's semantics.
	 * Drives the "Top syscalls by CMP unique inserts" sibling block in
	 * dump_stats() that pairs with "Top syscalls by recent edge growth"
	 * -- a syscall whose CMP insert rate is high while its edge-growth
	 * rate is flat is generating CMP signal that is not translating into
	 * coverage, the diagnostic signature of the CMP-rising-PC-flat
	 * plateau pattern. */
	unsigned long per_syscall_cmp_inserts[MAX_NR_SYSCALL];
	/* Snapshot of per_syscall_cmp_inserts at the previous dump_stats()
	 * call, matching the per_syscall_edges_previous pattern above so the
	 * sibling top-N block can compute the same kind of delta. */
	unsigned long per_syscall_cmp_inserts_previous[MAX_NR_SYSCALL];
	/* See struct kcov_per_syscall_diag.  Indexed by [nr][do32 ? 1 : 0]
	 * so the 32-bit-record vs 64-bit-record arch dimension is preserved
	 * alongside the syscall slot.  ~96 KiB of shm. */
	struct kcov_per_syscall_diag per_syscall_diag[MAX_NR_SYSCALL][2];
	/* Sliding-window edge-rate plateau detector state.  Sampled at the
	 * 600s parent stats tick: each tick, delta = edges_found -
	 * plateau_prev_edges is the count of new edges discovered in the
	 * most recent KCOV_PLATEAU_WINDOW_SEC window.  When the delta drops
	 * below KCOV_PLATEAU_ENTER_THRESHOLD (rate < 1 edge per 60s sustained
	 * over the 10-minute window) the parent enters PLATEAU state and
	 * emits a one-line warning to stats.log; a matching CLEARED line is
	 * emitted when the rate climbs back above threshold.  Entry into
	 * PLATEAU also fires strategy_plateau_response(), which forces an
	 * immediate strategy rotation into the plateau-intervention layer.
	 * That layer is a flat round-robin among RRC-biased replay, anti-
	 * prior accept gating, and uniform random; the rotation does not
	 * pin a mode based on the hypothesis classifier.  The published
	 * hypothesis is consumed separately at per-call gates in child.c
	 * (CHILDOP_DOMINANT raises the alt-op burst threshold) and in
	 * minicorpus.c (CMP_RISING_PC_FLAT doubles the replay rate and
	 * narrows the slot picker) -- see the strategy.h header for the
	 * full consumer contract.  Interventions unwind automatically on
	 * the matching CLEARED edge. */
	time_t plateau_window_start;
	unsigned long plateau_prev_edges;
	unsigned long plateau_last_window_delta;
	time_t plateau_entered_at;
	bool plateau_armed;
	bool plateau_active;

	/*
	 * Coverage-jump breadcrumb state.  See KCOV_COVJUMP_* constants at
	 * the top of this header for the detector contract.  Pure
	 * diagnostic; no runtime path reads these.  The snapshot block is
	 * sampled by the CAS winner at each window boundary and replayed
	 * against the live counters at the next boundary to compute the
	 * per-window deltas that populate the breadcrumb.
	 *
	 * covjump_snap_childop_invocations[] mirrors the indexing of the
	 * surrounding childop_* arrays (sized to KCOV_CHILDOP_NR_MAX with
	 * the in-tree _Static_assert on NR_CHILD_OP_TYPES pinning the
	 * tail).  RELAXED atomics throughout.
	 */
	unsigned long covjump_window_start_call_nr;
	unsigned long covjump_window_start_distinct_edges;
	unsigned long covjump_snap_saves_pc;
	unsigned long covjump_snap_saves_cmp;
	unsigned long covjump_snap_chain_saves;
	unsigned long covjump_snap_chain_replays;
	unsigned long covjump_snap_childop_invocations[KCOV_CHILDOP_NR_MAX];
	unsigned long covjump_last_emit_call_nr;
	bool covjump_window_armed;

	/* Greedy CMP RedQueen re-exec stats.  A CMP-mode child records
	 * attributable (cmp_ip, arg_slot, value) tuples from the parent
	 * call's KCOV_TRACE_CMP records; when the gate fires, these counters
	 * track the re-exec funnel.  Each counter is bumped once per re-exec
	 * dispatch (or once per gated skip) so the funnel
	 *   attribution_found -> attempts -> new_cmps_total
	 *                                 -> skipped_destructive
	 *                                 -> skipped_validate_silent
	 *                                 -> window_cap_hit
	 * is directly observable.  attribution_ambiguous is bumped once per
	 * (cmp_ip, value) where more than one arg slot matched, before
	 * first-match-wins picked one.
	 *
	 * reexec_attribution_width_match is the width-aware fallback
	 * tally: counted SEPARATELY from reexec_attribution_found so the
	 * exact full-width predicate's low-noise numerator stays clean.
	 * Bumped from cmp_hints_collect() when the exact-pass arg vs arg2
	 * compare misses, the comparison size is narrower than a long, and
	 * a width-masked rescan finds EXACTLY one matching slot (any
	 * masked ambiguity is dropped rather than guessed -- the masked
	 * predicate's higher hit rate makes first-match-wins unreliable
	 * here).  Total successful attributions ingested into
	 * reexec_pending[] is therefore (reexec_attribution_found +
	 * reexec_attribution_width_match). */
	unsigned long reexec_attempts;
	/*
	 * Discrete count of re-exec attempts that produced
	 * inner_new_cmp > 0.  Sibling of reexec_attempts (denominator)
	 * and reexec_new_cmps_total (the SUM of inner_new_cmp across
	 * winning attempts).  Bumped from redqueen_reexec_step() inside
	 * the existing inner_new_cmp > 0 success block, once per winning
	 * attempt.  Lets a Phase-0 funnel read pair the two ratios:
	 *   - hit-rate           = reexec_attempts_with_new_cmp / reexec_attempts
	 *   - mean novelty/win   = reexec_new_cmps_total / reexec_attempts_with_new_cmp
	 * the existing pair (sum / attempts) conflates them.
	 */
	unsigned long reexec_attempts_with_new_cmp;
	unsigned long reexec_attribution_found;
	unsigned long reexec_attribution_ambiguous;
	unsigned long reexec_attribution_width_match;
	unsigned long reexec_new_cmps_total;
	unsigned long reexec_skipped_destructive;
	unsigned long reexec_skipped_validate_silent;
	unsigned long reexec_window_cap_hit;

	/* Per-syscall new_cmp total attributed to re-exec dispatches.
	 * Sibling of per_syscall_cmp_inserts for the re-exec lift signal:
	 * lift_ratio_per_syscall = reexec_per_call_new_cmps /
	 *                          baseline_per_call_new_cmps
	 * is the per-syscall version of the run-wide primary lift metric:
	 * new CMP novelty per call gained from re-exec over baseline. */
	unsigned long per_syscall_cmp_novelty_reexec[MAX_NR_SYSCALL];

	/* Shadow transition-coverage map and counters.  See
	 * KCOV_NUM_TRANSITIONS and the kcov_transition_coverage_mode enum
	 * at the top of this header for the design.  All four counters and
	 * the map stay at zero when the mode is OFF; the map and per-
	 * syscall arrays are still allocated (the size is fixed at compile
	 * time and the byte cost is fleet-acceptable, ~16 MB).
	 *
	 *  transition_seen[]
	 *      One byte per (prev_canon_pc, cur_canon_pc) hash slot.  Bit 0
	 *      is the seen flag bumped from kcov_collect(); the upper seven
	 *      bits are reserved for a future bucket layer that would
	 *      parallel bucket_seen[]'s 8-bucket hit-count semantics.
	 *  transition_edges_found
	 *      Count of slot bits ever flipped 0 -> 1.  Today this tracks
	 *      distinct slot occupancy (one bit per slot); the name keeps
	 *      the PC-side edges_found / distinct_edges naming pattern so a
	 *      future bucket layer can split the two cleanly.
	 *  transition_distinct_edges
	 *      Distinct first-sighting count of new transition slots —
	 *      identical to transition_edges_found until a bucket layer is
	 *      added.  Kept separate now so the published counter API is
	 *      stable when the split lands.
	 *  per_syscall_transition_edges[nr]
	 *      Call-count semantics: bumped once per kcov_collect() call
	 *      that flipped at least one new transition slot.  Mirrors the
	 *      per_syscall_edges[] semantics noted in the comment above it.
	 *  per_syscall_transition_edges_previous[nr]
	 *      Snapshot of the above at the previous dump_stats() interval.
	 *      Drives the "top syscalls by recent transition growth" delta
	 *      block in the stats dump.
	 *  per_syscall_transition_edges_real[nr]
	 *      Real edge-flip count: sum across all calls of the number of
	 *      new transition slots flipped in that call.  A single call
	 *      that opens an entirely new control-flow region bumps this by
	 *      the size of the region, not by 1 — pair with the call-count
	 *      counter above to read transitions-per-productive-call.
	 *  per_syscall_transition_edges_real_local[nr]
	 *      Local-mode-only mirror of per_syscall_transition_edges_real.
	 *      Bumped only when the collecting kcov child is NOT in remote
	 *      mode AND kcov_transition_reward_mode != OFF.  Consumed by
	 *      the frontier_cold_weight() blend as the transition-yield
	 *      term so the live picker (under COMBINED) sees a transition
	 *      signal restricted to traces whose PC ordering Trinity can
	 *      trust.  See the kcov_transition_reward_mode enum at the
	 *      top of this header for the remote-mode contract. */
	unsigned long transition_edges_found;
	unsigned long transition_distinct_edges;
	unsigned long per_syscall_transition_edges[MAX_NR_SYSCALL];
	unsigned long per_syscall_transition_edges_previous[MAX_NR_SYSCALL];
	unsigned long per_syscall_transition_edges_real[MAX_NR_SYSCALL];
	unsigned long per_syscall_transition_edges_real_local[MAX_NR_SYSCALL];
	unsigned char transition_seen[KCOV_NUM_TRANSITIONS];

	/* CMP-hint / RedQueen pipeline observability.
	 *
	 * The two per-syscall counters below partition the existing flat
	 * cmp_hints_injected funnel by syscall slot.  Without the per-nr
	 * split, the question "is this syscall producing the bulk of cmp-hint
	 * deliveries and eventual PC-edge wins, or are the totals dominated
	 * by a noisy few unrelated to the syscall whose tuning we're judging"
	 * is unanswerable from the periodic stats log.  Both arrays are
	 * MAX_NR_SYSCALL-indexed (matching per_syscall_edges[]) and gated on
	 * nr < bound at each bump site.  Relaxed atomics; cumulative across
	 * the run.
	 *
	 * The consumer-side demand/pool-hit partitions
	 * (per_syscall_cmp_attempts/_returned) live in parent_stats and are
	 * fed via STATS_FIELD_PER_SYSCALL_CMP_ATTEMPTS / _RETURNED on the
	 * per-child stats_ring -- write-only-by-child, no cross-child reader,
	 * so the migration off kernel-visible shm purely shrinks the wild-
	 * write attack surface.
	 *
	 *  per_syscall_cmp_injected[nr]
	 *      Bumped from each of the four generate-args.c callsites that
	 *      commit a cmp_hints_try_get() hint to a produced syscall arg,
	 *      alongside the existing flat cmp_hints_injected counter.
	 *      Strictly <= parent_stats.per_syscall_cmp_returned[nr]; the
	 *      gap is callsites that pulled a hint but discarded it (none
	 *      today).
	 *  per_syscall_cmp_hint_pc_wins[nr]
	 *      Bumped from kcov_collect()'s found_new branch when the calling
	 *      child had cmp_hint_injected_this_call set for the call being
	 *      collected.  The per-syscall version of "did the injected hint
	 *      drive new PC-edge coverage on this call".  Pair with
	 *      per_syscall_cmp_injected to read per-syscall hint-edge yield;
	 *      a syscall with high injected and zero pc-wins is the
	 *      diagnostic signature for an unproductive cmp-hint regime. */
	unsigned long per_syscall_cmp_injected[MAX_NR_SYSCALL];
	unsigned long per_syscall_cmp_hint_pc_wins[MAX_NR_SYSCALL];

	/* Per-syscall typed-hyp outcome partition.  Pairs with the
	 * per_syscall_cmp_injected/_pc_wins counters above so the
	 * cmp-frontier weight can route on real conversion rate rather
	 * than insert volume alone.  Bumped from cmp_hyp_credit_outcome()
	 * under the same nr-bounds guard as the sibling per-syscall
	 * counters; only the typed-hyp outcome channels that can fire
	 * today are partitioned. */
	unsigned long per_syscall_cmp_hint_transition_wins[MAX_NR_SYSCALL];
	unsigned long per_syscall_cmp_hint_misses[MAX_NR_SYSCALL];
	unsigned long per_syscall_cmp_hint_corpus_saves[MAX_NR_SYSCALL];
	unsigned long per_syscall_cmp_hint_destructive_skips[MAX_NR_SYSCALL];
	unsigned long per_syscall_cmp_hint_cmp_novelty_wins[MAX_NR_SYSCALL];

	/* Per-callsite total cmp-hint injections, indexed by enum
	 * cmp_hint_callsite.  Aggregated across all syscalls; the "which
	 * argtype-handler is responsible for the bulk of injections" question
	 * is callsite-shaped, not syscall-shaped, so the per-nr split lives
	 * in per_syscall_cmp_injected above and this array stays flat.  7
	 * buckets: ARG_OP, ARG_LIST, ARG_UNDEFINED, ARG_STRUCT_SIZE,
	 * STRUCT_FIELD (reserved -- no call site today), OTHER, ARG_RANGE. */
	unsigned long cmp_hint_callsite_injected[CMP_HINT_CALLSITE_NR];

	/* PC-mode outcome partition by callsite -- WIN numerator per
	 * callsite bucket.  Sibling of cmp_hint_callsite_injected[] above
	 * (which is the per-callsite denominator: how many pulls were
	 * committed to a produced arg) and of cmp_hint_pc_wins_by_pool[]
	 * (which partitions the same PC-mode win credit by pool-kind).
	 * Bumped from cmp_hints_feedback_credit_pc() once per stashed entry
	 * whose credit lands on a win, using the callsite the stash was
	 * stamped with at consume time in cmp_hints_stash_consumed().
	 * Existing splits: callsite-INJECTED-only + pool-WIN-only; this
	 * closes the callsite-WIN hole so a typed-eligible baseline
	 * (ARG_STRUCT_SIZE + ARG_RANGE) can be projected out of the raw
	 * pool wins rather than compared against the aggregate.  Stash
	 * entries with an unset / out-of-range callsite (field-pool pulls
	 * from cmp_hints_field_try_get, which have no argtype-handler
	 * callsite) are not attributed here, so sum(_by_callsite) can be
	 * less than the flat cmp_hint_wins / cmp_hint_misses. */
	unsigned long cmp_hint_callsite_pc_wins[CMP_HINT_CALLSITE_NR];
	unsigned long cmp_hint_callsite_misses[CMP_HINT_CALLSITE_NR];

	/* SHADOW feedback scoring counters ([11-feedback-loop] PHASE 4).
	 *
	 * These are SHADOW / measurement-only: cmp_hints_try_get pool
	 * selection stays uniform.  A future live-pick path is intended to
	 * read these counters and gate a weighted live pick
	 * (`weight = floor + wins*4 - misses`, clamped, keeping random
	 * exploration) once a real signal is visible.
	 *
	 *  cmp_hints_consumed
	 *      Bumped from cmp_hints_try_get_ex right before the true return,
	 *      next to the existing cmp_hints_try_get_returned bump.  Counts
	 *      successful pulls that produced a stashed (nr, arch, cmp_ip,
	 *      value, size, transform) tuple for credit at dispatch tail.
	 *      Same conceptual counter as cmp_hints_try_get_returned --
	 *      tracked SEPARATELY so a future change to the stash discipline
	 *      (overflow-drop, narrowing to a subset of consumers) is visible
	 *      against the unchanged try_get_returned baseline.
	 *  cmp_hint_wins
	 *      PC-mode dispatch produced new_edges == true AND the per-child
	 *      stash for the call was non-empty.  Bumped once per such
	 *      dispatch from cmp_hints_feedback_credit_pc(true).  Each
	 *      stashed entry's matching pool entry's saturating uint16_t
	 *      wins counter is bumped at the same site -- the per-entry
	 *      counters feed the follow-up live-pick weight; this flat
	 *      counter is the cohort-level rollup for the periodic dump.
	 *  cmp_hint_misses
	 *      PC-mode dispatch produced no new edges AND the per-child
	 *      stash was non-empty.  Bumped once per such dispatch from
	 *      cmp_hints_feedback_credit_pc(false), with the per-entry
	 *      pool misses bumped at the same site.
	 *  cmp_hint_cmp_novelty_wins
	 *      CMP-mode dispatch produced new_cmp > 0 AND the per-child
	 *      stash was non-empty.  Bumped once per such dispatch from
	 *      cmp_hints_feedback_credit_cmp_novelty().  Kept SEPARATE
	 *      from cmp_hint_wins per the spec's "CMP novelty credit must
	 *      not masquerade as PC-edge conversion" discipline: the
	 *      follow-up live-pick weight is PC-edge-only and this counter
	 *      is the visibility channel for the CMP-mode novelty signal
	 *      that the PC-mode score does not include.
	 *  cmp_hint_stash_overflow
	 *      cmp_hints_try_get_ex tried to push onto a full stash
	 *      (cmp_hints_consumed_count == CMP_HINT_CONSUMED_STASH_MAX).
	 *      Records the dropped tail.  Operator gate on resizing the
	 *      stash; a non-trivial delta means a hot syscall regularly
	 *      pulls more hints per call than the buffer holds and the
	 *      tail credit is lost to truncation.
	 *  cmp_hint_credit_entry_evicted
	 *      Credit-drain scan walked the matching pool entries[] and
	 *      did NOT find the stashed (cmp_ip, value, size) tuple --
	 *      the entry was evicted between consume and credit.  The
	 *      flat wins/misses counter still bumps (the call-level
	 *      outcome is unambiguous); only the per-entry score is lost
	 *      to the eviction.  Diagnostic gate on pool churn vs the
	 *      consume-to-credit gap. */
	unsigned long cmp_hints_consumed;
	unsigned long cmp_hint_wins;
	unsigned long cmp_hint_misses;
	unsigned long cmp_hint_cmp_novelty_wins;
	unsigned long cmp_hint_stash_overflow;
	unsigned long cmp_hint_credit_entry_evicted;

	/* RedQueen re-exec observability counters, sibling of the flat
	 * reexec_* family above.  Same callsite/attribution funnel, but
	 * partitioned by syscall slot or by attribution arg-slot so the
	 * operator can ask "which syscalls are driving the re-exec attempt
	 * volume, and once attributed, which arg slot did the kernel CMP
	 * fire on" without having to grep child logs.
	 *
	 *  reexec_attempts_by_syscall[nr]
	 *      Per-nr partition of reexec_attempts: bumped from
	 *      redqueen_reexec_step() alongside the flat counter.
	 *  reexec_ambiguous_by_syscall[nr]
	 *      Per-nr partition of reexec_attribution_ambiguous: bumped from
	 *      cmp_hints_collect() alongside the flat counter when >1 arg
	 *      slot matched the same kernel CMP constant.
	 *  reexec_attribution_slot_hist[CMP_REDQUEEN_SLOT_HIST_NR]
	 *      6-slot histogram (a1..a6) of which arg slot won the first-
	 *      match-wins attribution scan.  Bumped from cmp_hints_collect()
	 *      next to the reexec_attribution_found bump.  Index = slot - 1.
	 *  reexec_success_by_slot[CMP_REDQUEEN_SLOT_HIST_NR]
	 *      6-slot success counter: bumped from redqueen_reexec_step()
	 *      when the inner dispatch returned inner_new_cmp > 0.  Pair
	 *      with reexec_attribution_slot_hist to read per-slot success
	 *      rate -- a slot that gets the bulk of attributions but no
	 *      successes is wasted re-exec budget.
	 *  typed_inject_fill_slot_hist[CMP_REDQUEEN_SLOT_HIST_NR]
	 *      Sibling of reexec_attribution_slot_hist: same 6-slot
	 *      histogram (index = argnum - 1) but counting the arg slot the
	 *      typed-hypothesis LIVE inject arm actually FILLED, threaded
	 *      through from the caller's argnum on the two typed-eligible
	 *      call sites (ARG_RANGE, ARG_STRUCT_SIZE) and bumped inside
	 *      the accept-gated commit block in cmp_try_get_durable_tier()
	 *      only when hyp_injected -- so an accept-rejected derived
	 *      value cannot contaminate the fill distribution.  Placement-
	 *      proof observability: reexec_attribution_slot_hist reports
	 *      which arg slot the kernel-side CMP fired ON (source slot);
	 *      this counter reports which arg slot the typed inject
	 *      landed IN (fill slot).  A divergence between the two
	 *      distributions means the derived value is being placed on a
	 *      different arg slot than the one it was learned from --
	 *      placement is confirmed as the CMP-conversion killer.
	 *      Value-neutral shadow: no rnd draw is added and no derived
	 *      value is changed by the plumbing; the counter is bumped by
	 *      __atomic_fetch_add only.
	 *  reexec_pending_dropped
	 *      Per-call counter: bumped once per parent call from
	 *      cmp_hints_collect() when the per-child reexec_pending[] buffer
	 *      fills (count reaches MAX_REEXEC_PENDING) and the per-record
	 *      attribution scan is force-disabled for the remainder of that
	 *      call.  Non-zero means a parent call surfaced more attribution
	 *      candidates than MAX_REEXEC_PENDING can hold -- the
	 *      attribution census is truncated, and (cmp_ip, value, size,
	 *      slot) tuples beyond the cap are silently dropped.
	 *  reexec_pending_pick_success[REEXEC_PENDING_PICK_HIST_NR]
	 *      Per-pending-buffer-index success counter.  The
	 *      dispatch_step-tail RedQueen consumer drains every staged
	 *      reexec_pending[] entry per parent dispatch
	 *      (--redqueen-pending-pick is a no-op); this counter bumps the
	 *      entry's true index (0..reexec_pending_count) inside
	 *      redqueen_reexec_step() when the inner re-exec dispatch
	 *      returned inner_new_cmp > 0 (i.e., the re-exec produced
	 *      bloom-novel CMP records), so per-slot / per-index re-exec
	 *      lift remains directly readable.  Bumped from
	 *      redqueen_reexec_step() inside the existing inner_new_cmp > 0
	 *      success block; the entry index is clamped to
	 *      REEXEC_PENDING_PICK_HIST_NR before use. */
	unsigned long reexec_attempts_by_syscall[MAX_NR_SYSCALL];
	unsigned long reexec_ambiguous_by_syscall[MAX_NR_SYSCALL];
	unsigned long reexec_attribution_slot_hist[CMP_REDQUEEN_SLOT_HIST_NR];
	unsigned long reexec_success_by_slot[CMP_REDQUEEN_SLOT_HIST_NR];
	unsigned long typed_inject_fill_slot_hist[CMP_REDQUEEN_SLOT_HIST_NR];
	unsigned long reexec_pending_dropped;
	/*
	 * Vestigial wastage counter.  Always zero: the dispatch_step tail
	 * drains every staged reexec_pending[] entry per parent dispatch,
	 * so no gate-pass entry is ever left behind.  Field retained only
	 * for shm-ABI stability so existing stats consumers keep parsing
	 * the layout unchanged.
	 */
	unsigned long reexec_pending_drain_unused;
	unsigned long reexec_pending_pick_success[REEXEC_PENDING_PICK_HIST_NR];

	/* RedQueen A/B cohort denominators.  The existing reexec_* family
	 * counts enabled-arm ACTIVITY (attempts, new_cmps, attribution wins
	 * etc.) but provides no denominator -- so the fleet-level question
	 * "did re-exec actually lift CMP novelty per parent call versus the
	 * control arm" is unanswerable: reexec_new_cmps_total is the enabled
	 * cohort's numerator with no matching denominator, and the control
	 * cohort's parent-call population is invisible to the dump.
	 *
	 * Bumped from the kcov_collect_cmp() callsite in dispatch_step,
	 * gated on child->redqueen_enabled to pick the cohort.  Every
	 * CMP-mode parent call counts: validator-rejected calls (which
	 * cannot trigger re-exec because their new_cmp is forced to zero)
	 * are still part of the population the re-exec gate samples from,
	 * so excluding them would bias the denominator.
	 *
	 *  cmp_parent_calls_enabled
	 *      Count of CMP-mode parent calls in the redqueen-enabled
	 *      cohort.  Pair with reexec_attempts (and the rest of the
	 *      reexec_* numerator family) to read per-parent-call re-exec
	 *      yield in the enabled arm.
	 *  cmp_parent_calls_control
	 *      Count of CMP-mode parent calls in the control cohort.  No
	 *      re-exec ever fires here (the redqueen_enabled gate at
	 *      dispatch_step's tail short-circuits) so this is purely the
	 *      A/B baseline denominator.
	 *  cmp_parent_new_cmps_enabled
	 *      Sum of kcov_collect_cmp()'s per-call new_cmp return value
	 *      across all enabled-cohort parent calls.  Together with
	 *      cmp_parent_calls_enabled, gives baseline per-parent-call
	 *      bloom-novel CMP yield in the enabled cohort BEFORE the
	 *      re-exec lift is layered on top.
	 *  cmp_parent_new_cmps_control
	 *      Same, for the control cohort.  The two cohorts should
	 *      produce statistically equivalent per-parent-call novelty in
	 *      the absence of selection bias: a sustained drift between
	 *      cmp_parent_new_cmps_enabled / cmp_parent_calls_enabled and
	 *      cmp_parent_new_cmps_control / cmp_parent_calls_control is
	 *      itself a sanity-check failure that says the A/B stamp is
	 *      not actually balanced.  With the two arms confirmed
	 *      balanced, the lift signal is
	 *        reexec_new_cmps_total / cmp_parent_calls_enabled
	 *      measured against either cohort's per-call novelty baseline.
	 *
	 * Relaxed atomics; cumulative across the run; mirror the storage
	 * and discipline of the reexec_* family above.  Measurement-only
	 * counters -- nothing in the picker, gates, or selection policy
	 * reads them. */
	unsigned long cmp_parent_calls_enabled;
	unsigned long cmp_parent_calls_control;
	unsigned long cmp_parent_new_cmps_enabled;
	unsigned long cmp_parent_new_cmps_control;
	/* Per-reason granular counters for the cmp-hint save/persist
	 * funnel.  The pre-existing cmp_hints_bloom_skipped and
	 * cmp_hints_strip_skipped reach hundreds of millions per run and
	 * are kept unchanged for historical comparability, but neither
	 * explains why the per-syscall pool plateaus at a few thousand
	 * entries despite a torrent of bloom-novel records.  These five
	 * count the per-record drops that survive bloom + strip and still
	 * fail to grow the pool, bucketed by the branch the code actually
	 * distinguishes at the site -- so the operator can read which
	 * reason dominates the gap between "collected" and "unique_inserts"
	 * instead of inferring it from a single coarse aggregate.
	 *
	 * Bumped with __atomic_fetch_add RELAXED at the site of each
	 * reject branch in cmp_hints_collect() / pool_add_locked();
	 * counter-only -- no save/evict/strip DECISION change rides
	 * alongside.  Reasons are mutually exclusive per record: the
	 * value-filter pair (uninteresting / sentinel) short-circuits
	 * BEFORE the bloom + pool path, so a record can land in at most
	 * one bucket per call.  cap and dup are pool-add-time outcomes
	 * (the bloom miss reached pool_add_locked() and either found a
	 * matching entry -> dup, or did not and the pool was full ->
	 * cap evict-replace).  nonconst is the type-bit gate at the head
	 * of the per-record loop -- KCOV_CMP_CONST records are the only
	 * ones whose arg1 is a kernel compile-time constant worth
	 * pooling; non-CONST records are dropped wholesale.
	 *
	 * Append-only at the tail of the struct so existing offsets
	 * (and any consumer that has memorised them) stay stable. */
	unsigned long cmp_hints_save_reject_nonconst;
	unsigned long cmp_hints_save_reject_uninteresting;
	unsigned long cmp_hints_save_reject_sentinel;
	unsigned long cmp_hints_save_reject_dup;
	unsigned long cmp_hints_save_reject_cap;

	/* Measurement-correctness counters for the RedQueen attribution +
	 * re-exec funnel.  Counter-only -- nothing in the picker, gates, or
	 * selection policy reads them.  Relaxed atomics; cumulative across
	 * the run; append-only at struct tail per the comment above.
	 *
	 * The pre-existing reexec_* family covers the flat aggregates and
	 * the per-syscall partitions of attempts + ambiguity; the per-call
	 * gate disposition (why a parent call with staged attributions
	 * did or did not fire a re-exec) was a single un-partitioned gap
	 * between reexec_attribution_found and reexec_attempts, and the
	 * per-childop dimension of the same funnel was invisible (a
	 * childop-driven OP_SYSCALL flow was indistinguishable from a
	 * top-level random-syscall dispatch in the per-syscall arrays).
	 *
	 * The split below mirrors the existing reexec_*_by_syscall pattern
	 * for the per-syscall HEAD of the funnel and adds the matching
	 * per-childop arrays + the gate-cause bucketing.  Snapshot health
	 * is the consumer-side counterpart of dispatch_args_valid: a
	 * non-zero cmp_attribution_snapshot_unavailable means the
	 * [11-snapshot] dispatch_args[] feed is not reaching attribution.
	 *
	 *  reexec_attribution_found_by_syscall[nr]
	 *      Per-nr partition of reexec_attribution_found: bumped from
	 *      cmp_hints_collect() alongside the flat counter on every
	 *      record where the attribution scan staged a (slot, value)
	 *      tuple into reexec_pending[].
	 *  reexec_attribution_dropped_pending_by_syscall[nr]
	 *      Per-nr partition of reexec_pending_dropped: bumped once per
	 *      parent call from cmp_hints_collect() when the reexec_pending
	 *      buffer fills mid-scan.  Non-zero per-nr identifies the hot
	 *      attributing syscalls whose attribution census is truncated.
	 *  reexec_attribution_found_by_childop[op]
	 *      Per-childop partition of reexec_attribution_found, indexed
	 *      by enum child_op_type bounded to KCOV_CHILDOP_NR_MAX.
	 *      Bumped alongside the per-syscall sibling so an attribution
	 *      driven through a non-OP_SYSCALL childop (e.g. recipe runner,
	 *      io_uring flood) is countable separately from the same nr
	 *      dispatched from the default OP_SYSCALL flow.
	 *  reexec_attribution_ambiguous_by_childop[op]
	 *      Per-childop partition of reexec_attribution_ambiguous.
	 *  reexec_attempts_by_childop[op]
	 *      Per-childop partition of reexec_attempts.  Bumped from
	 *      redqueen_reexec_step() alongside the per-syscall sibling.
	 *  per_childop_cmp_novelty_reexec[op]
	 *      Per-childop partition of reexec_new_cmps_total.  Bumped
	 *      from redqueen_reexec_step() with the inner-dispatch
	 *      new_cmp value, alongside the per-syscall sibling.
	 *
	 *  reexec_gate_skip_in_reexec
	 *  reexec_gate_skip_disabled
	 *  reexec_gate_skip_mode
	 *  reexec_gate_skip_chain_mid
	 *  reexec_gate_skip_no_new_cmp
	 *  reexec_gate_skip_no_pending
	 *  reexec_gate_skip_rate
	 *  reexec_gate_pass
	 *      Per-parent-call gate disposition at dispatch_step's re-exec
	 *      tail.  Mutually exclusive: each dispatch_step that reaches
	 *      the tail bumps EXACTLY ONE of these (the first gate to
	 *      fail in evaluation order, or _pass when all gates cleared
	 *      and redqueen_reexec_step ran).  Sum across the eight
	 *      counters == total dispatch_step calls that reached the
	 *      tail, which is the parent-call population the gate samples
	 *      from.  Skip-reasons in evaluation order:
	 *        - in_reexec      recursion guard (the inner dispatch_step
	 *                         the re-exec helper itself invoked)
	 *        - disabled       child not in the A/B redqueen-enabled
	 *                         cohort (control arm)
	 *        - mode           PC-mode child; CMP-mode is required to
	 *                         produce attribution at all
	 *        - chain_mid      in_chain_mid_step set; a chain replay's
	 *                         saved step sequence cannot accommodate
	 *                         an intermediate re-exec
	 *        - no_new_cmp     parent call produced no bloom-novel CMP
	 *                         records (only re-harvested known ones)
	 *        - no_pending     attribution scan staged zero matches
	 *                         (no rec->aN value tied to the kernel's
	 *                         compared operand)
	 *        - rate           rate gate (ONE_IN(N)) did not fire and
	 *                         plateau-burst was not active
	 *      The gap reexec_attribution_found - reexec_attempts is now
	 *      bucketed by this counter family rather than inferred from
	 *      a single global delta.
	 *
	 *  cmp_attribution_calls_eligible
	 *      Count of cmp_hints_collect() calls where every attribution
	 *      precondition cleared (child != NULL, redqueen_enabled,
	 *      !in_reexec, reexec_pending_count < MAX_REEXEC_PENDING,
	 *      entry != NULL, entry->num_args > 0, dispatch_args_valid).
	 *      Denominator for the per-eligible-call attribution win
	 *      rate -- pair with reexec_attribution_found to read what
	 *      fraction of eligible parent calls staged at least one
	 *      match across the call's CMP trace.
	 *  cmp_attribution_snapshot_unavailable
	 *      Count of cmp_hints_collect() calls where the redqueen
	 *      cohort gate cleared and entry->num_args > 0, but
	 *      rec->dispatch_args_valid was false -- i.e. the per-call
	 *      arg snapshot the [11-snapshot] feed promised was missing.
	 *      A healthy run holds this at zero; non-zero means a
	 *      regression somewhere between __do_syscall's snapshot
	 *      populate and the cmp_hints_collect consumer (or a
	 *      parent-context caller reaching cmp_hints_collect that
	 *      shouldn't).  Attribution correctly skips the call; the
	 *      counter exposes the rate so the snapshot-feed health is
	 *      not silently zeroed-out into the eligible cohort. */
	unsigned long reexec_attribution_found_by_syscall[MAX_NR_SYSCALL];
	unsigned long reexec_attribution_dropped_pending_by_syscall[MAX_NR_SYSCALL];
	unsigned long reexec_attribution_found_by_childop[KCOV_CHILDOP_NR_MAX];
	unsigned long reexec_attribution_ambiguous_by_childop[KCOV_CHILDOP_NR_MAX];
	unsigned long reexec_attempts_by_childop[KCOV_CHILDOP_NR_MAX];
	unsigned long per_childop_cmp_novelty_reexec[KCOV_CHILDOP_NR_MAX];
	unsigned long reexec_gate_skip_in_reexec;
	unsigned long reexec_gate_skip_disabled;
	unsigned long reexec_gate_skip_mode;
	unsigned long reexec_gate_skip_chain_mid;
	unsigned long reexec_gate_skip_no_new_cmp;
	unsigned long reexec_gate_skip_no_pending;
	unsigned long reexec_gate_skip_rate;
	unsigned long reexec_gate_pass;
	unsigned long cmp_attribution_calls_eligible;
	unsigned long cmp_attribution_snapshot_unavailable;

	/*
	 * Field-scoped CMP attribution counters (PHASE 3 narrow MVP).
	 * Scalar attribution (reexec_attribution_found above) maps the kernel
	 * constant to a syscall slot; field attribution scans the cataloged
	 * struct sitting at that slot's pointer and -- on a runtime field
	 * value matching arg2 -- records the constant into a field pool keyed
	 * (nr, do32, arg_idx, desc, field_idx, size).  Counted separately
	 * from the scalar tally so the new path's signal-to-noise can be read
	 * without polluting the existing low-noise scalar numerator.
	 *
	 *  cmp_field_attribution_scanned
	 *      Bumped once per (CMP record, cataloged INPUT struct arg) the
	 *      field scan walked.  Denominator for the scan's hit rate.
	 *  cmp_field_attribution_found
	 *      Bumped once per (CMP record, struct arg, field) where the
	 *      field's runtime value matched arg2 and the recording-path
	 *      insert was attempted.  Numerator for the scan's hit rate.
	 *  cmp_field_attribution_pool_full
	 *      Bumped when every probe position in field_pools[] was occupied
	 *      by an unrelated key, so the record was dropped.  A sustained
	 *      non-zero rate flags a saturated table -- raise
	 *      CMP_FIELD_POOL_BUCKETS or sharpen the key.
	 *  cmp_field_attribution_arg_skipped_bad_ptr
	 *      Bumped when the struct arg's snapshotted pointer failed the
	 *      is_corrupt_ptr_shape() gate (NULL, non-canonical, or
	 *      misaligned) so the field scan was suppressed for that slot --
	 *      the kernel did not crash on the same address, so a non-zero
	 *      rate signals a sanitiser that hands a non-shared-region
	 *      pointer through and the field scan can't safely deref.
	 *  cmp_field_attribution_arg_skipped_short_alloc
	 *      Bumped when alloc_track_lookup_size() returned 0 for the
	 *      snapshotted pointer (untracked / consumed / rotated out of
	 *      the alloc-track ring) so the scan could not prove the
	 *      buffer's real extent and refused to bound the field walk by
	 *      desc->struct_size alone -- variable-length / over-large
	 *      catalog rows can claim more bytes than the runtime alloc
	 *      owns and the read would otherwise spill past the chunk
	 *      (heap-buffer-overflow).  A sustained non-zero rate flags a
	 *      sanitiser that fills a cataloged struct from an untracked
	 *      allocation; rebase the alloc onto zmalloc_tracked() so the
	 *      scan can recover the extent.
	 *  cmp_field_timespec_skipped_bad_ptr
	 *      Bumped when the field-scoped ARG_TIMESPEC fallback in
	 *      cmp_hints_collect() could not safely deref the saved
	 *      timespec pointer.  Two pathways feed the same counter --
	 *      both are "shape-valid (>= 4096) but not safe to read"
	 *      skips and have the same root cause (the dispatched
	 *      syscall, or a sibling, freed/munmapped the original
	 *      timespec between dispatch and CMP collection):
	 *        (a) range_readable_user() proved the cached VMA state
	 *            had no mapping for the pointer -- gate fired and
	 *            the deref was skipped without faulting; or
	 *        (b) range_readable_user() returned yes (cached VMA
	 *            state still claimed the mapping) but a sibling raw
	 *            munmap/mremap bypassed untrack_shared_region() and
	 *            staled the cache, so the tv_sec/tv_nsec load
	 *            actually faulted -- the sigsetjmp guard around the
	 *            reads caught the SIGSEGV/SIGBUS and longjmp'd back
	 *            to bump this counter and continue with the next
	 *            field.
	 *      A non-zero rate is expected churn (both gates prevented
	 *      a child-killing SIGSEGV); a sustained high rate against
	 *      cmp_field_attribution_scanned flags an arg-gen path that
	 *      hands the kernel a non-shared-region timespec the
	 *      harvest can't safely deref.
	 */
	unsigned long cmp_field_attribution_scanned;
	unsigned long cmp_field_attribution_found;
	unsigned long cmp_field_attribution_pool_full;
	unsigned long cmp_field_attribution_arg_skipped_bad_ptr;
	unsigned long cmp_field_attribution_arg_skipped_short_alloc;
	unsigned long cmp_field_timespec_skipped_bad_ptr;

	/* A/B-comparison counter for the substitution-pool "uninteresting
	 * constant" drop mask.  Each CMP-mode child is stamped at fork into
	 * one of two arms (boring_filter_arm in childdata): Arm A uses the
	 * historical ~3UL mask (drop 0/1/2/3); Arm B widens to ~7UL (also
	 * drop 4/5/6/7).  The widened band straddles common meaningful
	 * bounds (struct sizes, low flag bits), so the per-arm pool-novelty
	 * delta tells whether the dropped values were carrying actual
	 * signal.  Counter-only -- no decision rides on it.  Bumped from
	 * cmp_hints_collect() once per record where arg1 is in [4,7] (i.e.
	 * Arm A would keep the record and Arm B would drop it); this is
	 * the only band where the two arms diverge.  Append-only at the
	 * struct tail per the existing convention so consumer offsets stay
	 * stable. */
	unsigned long cmp_hints_boring_arm_b_drops;

	/*
	 * Observability counters for the run-local CMP "recent" pool
	 * tier.  The recent ring sits next to the durable per-syscall
	 * pool and absorbs every fresh insert / evict-replace
	 * pool_add_locked() observes -- a small lossy window over
	 * constants the kernel has produced recently that the
	 * saturated durable pool would otherwise drop on the eviction
	 * floor.  cmp_hints_try_get_ex() samples the recent ring first
	 * during a CMP_RISING_PC_FLAT plateau (the unconditional rule).
	 * Every counter below is RELAXED + flat.
	 *
	 *  cmp_recent_inserts
	 *      Bumped once per pool_add_locked() success that also
	 *      landed an entry in the per-syscall recent ring.  Pairs
	 *      with cmp_hints_unique_inserts -- the durable counter --
	 *      so the relative volume of "recent absorbed" vs
	 *      "durable accepted" is observable.
	 *  cmp_recent_evicts
	 *      Bumped once per recent-ring insert that displaced an
	 *      existing entry (the ring head wrapped over a populated
	 *      slot).  The ring is small (CMP_RECENT_PER_SYSCALL) so
	 *      this saturates quickly on a hot syscall; the rate is
	 *      the recent tier's churn signal.
	 *  cmp_recent_would_pick
	 *      Bumped once per cmp_hints_try_get_ex() call where the
	 *      recent ring was non-empty AND the current plateau
	 *      hypothesis is CMP_RISING_PC_FLAT -- i.e. the recent-tier
	 *      opportunity count.  Pairs with cmp_recent_live_picks for
	 *      the served-vs-opportunity ratio.
	 *  cmp_recent_would_miss
	 *      Bumped once per cmp_hints_try_get_ex() call where the
	 *      plateau hypothesis is CMP_RISING_PC_FLAT but the recent
	 *      ring is empty (the consumer falls through to the durable
	 *      pool).  would_pick + would_miss is the plateau-window
	 *      try_get population.
	 *  cmp_recent_live_picks
	 *      Bumped once per cmp_hints_try_get_ex() return that was
	 *      actually served from the recent ring.
	 *
	 * Append-only at the tail per the existing convention so
	 * consumer offsets stay stable. */
	unsigned long cmp_recent_inserts;
	unsigned long cmp_recent_evicts;
	unsigned long cmp_recent_would_pick;
	unsigned long cmp_recent_would_miss;
	unsigned long cmp_recent_live_picks;

	/*
	 * SHADOW counters for the field-scoped CMP hint consumer.
	 *
	 * cmp_hints_field_try_get() is wired end-to-end at the
	 * gen_arg_timespec() callsite (tv_sec / tv_nsec) but the LIVE
	 * arm is gated off by default so the pool stays observation-
	 * only.  Every counter below is RELAXED + flat per the SHADOW-
	 * first discipline that the per-syscall recent-ring tier
	 * follows: recording active in BOTH arms so an A/B run reads
	 * the same shadow rates the live arm will eventually consume.
	 *
	 *  cmp_field_consumer_would_pick
	 *      Bumped once per cmp_hints_field_try_get() call where the
	 *      keyed bucket was found AND its entries[] pool was non-
	 *      empty AND uncorrupted AND the generator-invariant guard
	 *      classified the (desc, field_idx) as eligible -- i.e. the
	 *      call where the live arm would have served a value.  Guard-
	 *      skipped keys are excluded from this counter and land in the
	 *      per-reason cmp_field_consumer_guard_* counters below
	 *      instead.  Active in BOTH arms.
	 *  cmp_field_consumer_would_miss
	 *      Bumped once per cmp_hints_field_try_get() call where the
	 *      keyed bucket was found but its entries[] pool was empty.
	 *      Active in BOTH arms.  would_pick + would_miss bounds the
	 *      sites where the consumer found a matching bucket.
	 *  cmp_field_consumer_key_absent
	 *      Bumped once per cmp_hints_field_try_get() call where the
	 *      probe loop exhausted CMP_FIELD_POOL_PROBE_MAX without a
	 *      matching key (no recorder has populated a bucket for
	 *      this (desc, nr, do32, arg_idx, field_idx, size) tuple
	 *      yet).  Active in BOTH arms; a steady non-zero rate just
	 *      means the consumer is asking for keys the recorder has
	 *      not produced.
	 *  cmp_field_consumer_pool_corrupted
	 *      Bumped once per cmp_hints_field_try_get() call where the
	 *      keyed bucket was found but cmp_field_pool_corrupted()
	 *      latched corruption on it (wild-write evidence).  Folds
	 *      into the existing cmp_hints_count_oob / canary counters;
	 *      called out here so the consumer-side fraction of
	 *      corruption-bucket skips is directly observable.
	 *  cmp_field_consumer_live_picks
	 *      Bumped once per cmp_hints_field_try_get() return that
	 *      actually served a value (i.e. would_pick AND the LIVE
	 *      arm flag is on).  Stays at zero under the default SHADOW
	 *      arm; non-zero once a follow-up flips the live gate.
	 *
	 * Append-only at the tail per the existing convention so
	 * consumer offsets stay stable.
	 */
	unsigned long cmp_field_consumer_would_pick;
	unsigned long cmp_field_consumer_would_miss;
	unsigned long cmp_field_consumer_key_absent;
	unsigned long cmp_field_consumer_pool_corrupted;
	unsigned long cmp_field_consumer_live_picks;

	/*
	 * Generator-invariant guard skip counters (per rejection reason).
	 * The would_pick counter above measures raw eligibility: the pool
	 * had a key and non-empty entries[].  A subset of those keys, if
	 * their value were ever injected into the generated struct, would
	 * damage a generator invariant and turn a real syscall into a
	 * guaranteed reject (union arm corruption, length/buffer desync,
	 * pointer-shaped fields overwritten with data, tagged-union
	 * discriminator picking a wrong variant, and so on).  The classifier
	 * fires BEFORE the would_pick bump so the counter now reflects
	 * post-guard eligibility -- what the live arm would actually
	 * inject -- and each skip lands in exactly one of the reasons below.
	 * All observation-only; no live behaviour changes with the arm off.
	 *
	 *  cmp_field_consumer_guard_variant_layout
	 *      Struct descriptor carries syscall-arg tagged-union variants
	 *      (desc->variants / num_variants).  Overwriting one arm's field
	 *      corrupts whichever arm the fill path chose at generation.
	 *  cmp_field_consumer_guard_buffer_discrim
	 *      Struct descriptor selects its variant off an in-buffer byte
	 *      (desc->buffer_discrim_size != 0), so any field overwrite risks
	 *      steering the discriminator (or a sibling variant field) to a
	 *      wrong arm -- includes sockaddr_storage / ioctl-request shapes.
	 *  cmp_field_consumer_guard_len_pair
	 *      Field is FT_LEN_BYTES / FT_LEN_COUNT: its value is the paired
	 *      buffer's chosen length.  Injecting a kernel-observed CMP
	 *      constant here desyncs the (ptr, len) pair.
	 *  cmp_field_consumer_guard_nested_pointer
	 *      Field is a pointer / embedded-struct / eBPF-buffer container
	 *      (FT_PTR_BYTES, FT_PTR_ARRAY, FT_PTR_STRUCT, FT_EMBEDDED_STRUCT,
	 *      FT_BPF_PROGRAM).  The stored value is an address / structural
	 *      handle, not data; injecting a scalar hint mints a garbage
	 *      pointer.
	 *  cmp_field_consumer_guard_dependent
	 *      Field carries structural state whose meaning is relative to
	 *      another field (FT_TAGGED_UNION per-arm subset selector,
	 *      FT_VOCAB NUL-padded curated-string slot).  A raw scalar hint
	 *      doesn't honour the coupling and injecting it desyncs the pair.
	 *
	 * Append-only at the tail per the existing convention so consumer
	 * offsets stay stable.
	 */
	unsigned long cmp_field_consumer_guard_variant_layout;
	unsigned long cmp_field_consumer_guard_buffer_discrim;
	unsigned long cmp_field_consumer_guard_len_pair;
	unsigned long cmp_field_consumer_guard_nested_pointer;
	unsigned long cmp_field_consumer_guard_dependent;

	/*
	 * Prove-overlay metric for the field-scoped SHADOW consumer.
	 *
	 * The would_pick counter above proves the pool has post-guard hits.
	 * It does NOT prove that routing the entry's value into the field
	 * would produce new edge / cmp progress, nor that it would raise
	 * the rejected-struct rate.  The counters below capture the
	 * fleet-wide baseline state at each eligible would-pick sample so
	 * a later live-arm flip can diff shadow-window vs live-window
	 * rates: eligible_pick_count is the sample denominator, and the
	 * three "_at_pick" sums are the numerators the live counterpart
	 * (bumped from the same site with the arm on) will be measured
	 * against.
	 *
	 * All bumps are keyed to the field-pool identity (struct type /
	 * arg slot / offset+width): each snapshot fires exactly at the
	 * point where the live arm would have injected that specific
	 * pool's value.  The counters accumulate flat totals -- precision
	 * comes from the tight sampling condition, not per-key storage --
	 * so a run whose eligible pick population is dominated by one
	 * pool cannot bias a later broader flip's read.
	 *
	 *  cmp_field_consumer_prove_eligible
	 *      Bumped once per eligible (post-guard) would-pick.  The
	 *      denominator for the three sums below.  Numerically equal
	 *      to cmp_field_consumer_would_pick under the current wiring
	 *      -- kept as an independently named counter so downstream
	 *      readers of the prove overlay do not have to memorise the
	 *      identity.
	 *  cmp_field_consumer_prove_edges_at_pick
	 *      Sum of kcov_shm->distinct_edges captured at each eligible
	 *      would-pick.  Grows linearly with prove_eligible while
	 *      distinct_edges is stable; a live-arm counterpart summed
	 *      the same way (post-arm-flip) plus the corresponding
	 *      prove_eligible delta answers "did routing this value in
	 *      produce new edges".
	 *  cmp_field_consumer_prove_cmp_records_at_pick
	 *      Sum of kcov_shm->cmp_records_collected captured at each
	 *      eligible would-pick.  Same shape as the edges baseline but
	 *      the CMP-progress axis: a live-arm delta on this sum tells
	 *      whether injection unlocked more kernel-side CMPs, not just
	 *      more PC coverage.
	 *  cmp_field_consumer_prove_einval_at_pick
	 *      Sum of kcov_shm->per_syscall_errno[nr][ERRNO_BUCKET_EINVAL]
	 *      captured at each eligible would-pick, keyed to the pick's
	 *      own syscall nr.  Answers "did it raise the rejected-struct
	 *      rate": a live-arm counterpart sum divided by its
	 *      prove_eligible delta, compared to the shadow ratio here,
	 *      is the injection's contribution to the EINVAL floor for
	 *      the population of syscalls where the arm actually fired.
	 *
	 * Append-only at the tail per the existing convention so consumer
	 * offsets stay stable.
	 */
	unsigned long cmp_field_consumer_prove_eligible;
	unsigned long cmp_field_consumer_prove_edges_at_pick;
	unsigned long cmp_field_consumer_prove_cmp_records_at_pick;
	unsigned long cmp_field_consumer_prove_einval_at_pick;

	/*
	 * Number of age-bucket slots for the CMP-hint staleness histogram
	 * below.  Buckets are coarse-spaced log2 ranges of the durable
	 * pool's LRU-clock delta at pick time (see cmp_hint_age_bucket()
	 * in cmp_hints.c); 7 slots gives bucket-0 == hottest (delta == 0,
	 * just-refreshed entry) through bucket-6 == staid tail (delta >=
	 * 2048 pool mutations since refresh).  Defined here rather than in
	 * cmp_hints.h because kcov.h must not include cmp_hints.h (see the
	 * MAX_REEXEC_PENDING comment above for the dependency rationale).
	 */
#define CMP_HINT_AGE_BUCKETS	7U

	/*
	 * CMP-hint freshness / tier observability counters.
	 *
	 * A fuzz run that injects tens of thousands of unique hints but
	 * credits only a handful of PC-wins suggests the durable pool is
	 * saturated and its hot entries are stale -- the hints being
	 * pulled at substitution time predate the kernel state the
	 * current call is actually probing.  These counters expose the
	 * per-call tier of the hint that was consumed (durable per-syscall
	 * pool vs run-local recent ring) and the staleness of the durable
	 * entry as measured by the gap between the pool's LRU clock at
	 * pick time and the entry's last_used stamp at pick time, then
	 * partition the PC-win / PC-miss credit drain by the same axes
	 * so the conversion rate per (tier, age-bucket) is directly
	 * observable.
	 *
	 * All counters RELAXED + flat per the SHADOW-first discipline:
	 * the recording is active in every run regardless of consumer
	 * arm so the freshness signal is legible from a default run with
	 * no behaviour change.  Append-only at the struct tail per the
	 * existing convention so consumer offsets stay stable.
	 *
	 *  cmp_hint_tier_recent_wins / cmp_hint_tier_recent_misses
	 *      Bumped from cmp_hints_feedback_credit_pc(): for each
	 *      stashed entry served from the recent ring, the outcome of
	 *      the parent dispatch (new_edges true/false) bumps the
	 *      matching wins/misses counter once per stash entry.
	 *      Sibling of the existing flat cmp_hint_wins / cmp_hint_misses
	 *      which count per parent dispatch (once); the per-stash
	 *      partition here is what isolates the tier signal: a single
	 *      parent dispatch may have stashed multiple hints from
	 *      different tiers, and the conversion attribution lands on
	 *      whichever tier sourced each individual stash entry.
	 *  cmp_hint_tier_durable_wins / cmp_hint_tier_durable_misses
	 *      Mirror of the recent tier above, bumped on stash entries
	 *      served from the durable per-syscall pool or the field-
	 *      scoped pool (both share the durable / saturating-LRU
	 *      lineage).  recent_wins + durable_wins is the total per-
	 *      stash-entry wins count, drained at the same site as the
	 *      flat per-parent-dispatch counter.
	 *  cmp_hint_durable_consumed_age[CMP_HINT_AGE_BUCKETS]
	 *      Bumped once per cmp_hints_try_get_ex() / cmp_hints_field_try_get()
	 *      return served from the durable per-syscall pool / field
	 *      pool: indexed by cmp_hint_age_bucket() of the LRU clock
	 *      delta (pool->last_used_stamp - picked->last_used) measured
	 *      lock-free at pick time.  Bucket 0 == picked entry is the
	 *      most recently refreshed in the pool; higher buckets ==
	 *      the entry has been carried over many pool mutations
	 *      without being refreshed.  Recent-ring picks bypass this
	 *      counter (their freshness story is the tier itself; the
	 *      ring has no per-entry LRU stamp).
	 *  cmp_hint_durable_age_wins[CMP_HINT_AGE_BUCKETS]
	 *  cmp_hint_durable_age_misses[CMP_HINT_AGE_BUCKETS]
	 *      Outcome partition of cmp_hint_durable_consumed_age:
	 *      bumped from cmp_hints_feedback_credit_pc() on each stashed
	 *      durable-served entry, indexed by the same age bucket the
	 *      pick path stored on the stash entry.  Per-bucket
	 *      conversion rate = age_wins[b] / (age_wins[b] +
	 *      age_misses[b]) and proves directly whether fresh entries
	 *      (bucket 0..2) convert at higher rates than the stale tail
	 *      (bucket 5..6).
	 *  per_syscall_cmp_reject_cap[MAX_NR_SYSCALL]
	 *      Per-syscall partition of the existing flat
	 *      cmp_hints_save_reject_cap: every evict-replace in
	 *      pools[nr] (durable pool saturated at CMP_HINTS_PER_SYSCALL,
	 *      a fresh insert displaced an existing entry) bumps slot nr.
	 *      Pair with the existing per_syscall_cmp_inserts[nr] to
	 *      read per-syscall pool pressure: a syscall whose
	 *      reject_cap rate dominates its inserts rate has a
	 *      saturated pool churning the same 16 slots; the durable
	 *      hints it produces drop to the recent ring (and decay
	 *      from there) instead of carrying forward.
	 */
	unsigned long cmp_hint_tier_recent_wins;
	unsigned long cmp_hint_tier_recent_misses;
	unsigned long cmp_hint_tier_durable_wins;
	unsigned long cmp_hint_tier_durable_misses;
	unsigned long cmp_hint_durable_consumed_age[CMP_HINT_AGE_BUCKETS];
	unsigned long cmp_hint_durable_age_wins[CMP_HINT_AGE_BUCKETS];
	unsigned long cmp_hint_durable_age_misses[CMP_HINT_AGE_BUCKETS];
	unsigned long per_syscall_cmp_reject_cap[MAX_NR_SYSCALL];

	/*
	 * SHADOW typed-CMP-hypothesis store counters.  Append-only at the
	 * struct tail per the existing convention.
	 *
	 *  cmp_hyp_observations    -- one bump per cmp_hyp_observe() call.
	 *  cmp_hyp_inserted        -- typed hypothesis added to the store.
	 *  cmp_hyp_pool_full       -- hyp_pool saturated (per-syscall cap).
	 *                             Bumped only from cmp_hyp_alloc()'s
	 *                             pool->count >= CMP_HYP_PER_SYSCALL
	 *                             reject; the cmp_hyp_observe() corruption
	 *                             bail (count > cap) bumps the sibling
	 *                             cmp_hyp_pool_overflow counter instead.
	 *  cmp_hyp_kind_full       -- per-kind sub-cap exhausted for a kind.
	 *  cmp_hyp_consumed        -- typed hypothesis selected for injection
	 *                             (shadow: counts would-have-been picks).
	 *                             Zero until the consumer unit lands.
	 *  cmp_hyp_pc_wins / cmp_hyp_transition_wins / cmp_hyp_cmp_novelty_wins
	 *                          -- per-outcome credit drained against the
	 *                             matching hypothesis.  Kept SEPARATE so
	 *                             CMP novelty cannot masquerade as a
	 *                             PC-edge conversion (same discipline as
	 *                             the raw-hint cmp_hint_* counters above).
	 *                             Zero until the feedback unit lands.
	 *  cmp_hyp_misses / cmp_hyp_disabled_skips
	 *                          -- drained against the matching hypothesis
	 *                             on a no-outcome / chaos-suppressed pick.
	 *                             Zero until the feedback unit lands.
	 *  cmp_hyp_corpus_save / cmp_hyp_destructive / cmp_hyp_context_skip
	 *                          -- flat mirrors of the matching per-
	 *                             hypothesis corpus_save_wins /
	 *                             destructive_skips / context_skips
	 *                             fields so the fleet rollup sees the
	 *                             same partition the per-hyp struct
	 *                             already records.  Zero until the
	 *                             feedback unit lands.
	 */
	unsigned long cmp_hyp_observations;
	unsigned long cmp_hyp_inserted;
	unsigned long cmp_hyp_pool_full;
	unsigned long cmp_hyp_kind_full;
	unsigned long cmp_hyp_consumed;
	unsigned long cmp_hyp_pc_wins;
	unsigned long cmp_hyp_transition_wins;
	unsigned long cmp_hyp_cmp_novelty_wins;
	unsigned long cmp_hyp_misses;
	unsigned long cmp_hyp_disabled_skips;
	unsigned long cmp_hyp_corpus_save;
	unsigned long cmp_hyp_destructive;
	unsigned long cmp_hyp_context_skip;

	/* Per-entry early-FAIL skip counters inside redqueen_reexec_step.
	 * Sibling family to the per-call reexec_gate_skip_* buckets, but
	 * scoped to the entry-resolution bails that fire AFTER the per-call
	 * gate has already passed.  Closes the per-entry skip partition so
	 * the gap between reexec_gate_pass and (reexec_attempts +
	 * reexec_skipped_destructive + reexec_skipped_validate_silent +
	 * reexec_window_cap_hit) is fully attributed.
	 *
	 *  reexec_step_skip_entry_null
	 *      get_syscall_entry(rec->nr, rec->do32bit) returned NULL --
	 *      parent rec carried a syscall nr the table cannot resolve.
	 *  reexec_step_skip_bad_slot
	 *      Pending slot is zero or past entry->num_args -- attribution
	 *      staged a slot that the resolved entry's arg count cannot
	 *      accommodate (stale pending vs current entry resolution). */
	unsigned long reexec_step_skip_entry_null;
	unsigned long reexec_step_skip_bad_slot;

	/* Per-kind flat census of typed CMP hypothesis insertions.
	 * Bumped in lock-step with the scalar cmp_hyp_inserted above
	 * from the cmp_hyp_alloc() success path, so the sum across
	 * kinds equals cmp_hyp_inserted modulo concurrent sampling.
	 * The per-syscall pool->per_kind_count[] is ephemeral (reset
	 * with the pool); this flat array is the persistent fleet
	 * mirror.  SHADOW telemetry only -- no consumer reads it. */
	unsigned long cmp_hyp_inserted_by_kind[CMP_HYP_KIND_NR];

	/* Per-kind flat census of typed CMP hypothesis insert rejections
	 * caused by the per-kind sub-cap (CMP_HYP_PER_KIND).  Bumped in
	 * lock-step with the scalar cmp_hyp_kind_full from cmp_hyp_alloc()'s
	 * per-kind-exhausted branch, so the sum across kinds equals
	 * cmp_hyp_kind_full modulo concurrent sampling.  Paired with
	 * cmp_hyp_inserted_by_kind above this shows, per kind, the
	 * accepted-vs-dropped split -- i.e. which kind is eating the cap
	 * when cmp_hyp_kind_full dominates.  SHADOW telemetry only -- no
	 * consumer reads it. */
	unsigned long cmp_hyp_kind_full_by_kind[CMP_HYP_KIND_NR];

	/* Per-kind flat census of typed CMP hypothesis consumes.
	 * Bumped in lock-step with the scalar cmp_hyp_consumed above
	 * from the cmp_hyp_credit_consume() hit path, so the sum across
	 * kinds equals cmp_hyp_consumed modulo concurrent sampling.
	 * The per-hypothesis consumed_count is per-entry; this flat
	 * array is the persistent fleet mirror.  Paired with
	 * cmp_hyp_inserted_by_kind this shows, per kind, the share of
	 * insertions the typed consumer is actually pulling.  SHADOW
	 * telemetry only -- no consumer reads it. */
	unsigned long cmp_hyp_consumed_by_kind[CMP_HYP_KIND_NR];

	/*
	 * SHADOW would-pick telemetry resolved alongside each successful
	 * raw cmp_hints_try_get_ex() return.  For the same (nr, do32,
	 * cmp_ip, width) the raw pool just served, the typed hypothesis
	 * store is walked through the same EXACT > ENUM_FAMILY > BITMASK >
	 * RANGE specificity ladder cmp_hyp_credit_outcome() uses; the
	 * resulting "what would the store have picked" is then bumped into
	 * the counters below.  Pure observation -- the live pick is the
	 * raw pool value, byte-for-byte unchanged; nothing here is gated
	 * by a CLI knob.
	 *
	 *  cmp_hyp_would_pick_by_kind[k]
	 *      Bumped at index k = picked->kind when the ladder resolves
	 *      to a hypothesis for (cmp_ip, width).  Sum across kinds is
	 *      the per-pick rate at which the typed store has SOMETHING
	 *      to say about the comparison sites the raw pool is serving.
	 *      Only the four ladder kinds (EXACT, ENUM_FAMILY, BITMASK,
	 *      RANGE) ever populate; the other CMP_HYP_KIND_NR slots stay
	 *      zero by construction.
	 *  cmp_hyp_would_miss_by_kind[k]
	 *      Bumped at index k for each ladder kind absent from
	 *      (cmp_ip, width) on this pick.  Per raw pick: 0..4 bumps,
	 *      one per missing ladder kind, so the per-kind ratio
	 *      pick[k] / (pick[k] + miss[k]) reports the typed store's
	 *      per-kind coverage of the served comparison sites.  Same
	 *      four-slot population rule as the pick counter.
	 *  cmp_hyp_would_value_differs
	 *      Bumped when the ladder resolves to a hypothesis whose
	 *      exemplar is not equal to the raw pool's picked value --
	 *      the store would have suggested a different concrete value
	 *      for the same site.  Scalar headline; the per-kind drilldown
	 *      lives in cmp_hyp_would_value_differs_by_kind below.
	 *  cmp_hyp_would_value_differs_by_kind[k]
	 *      Per-kind partition of cmp_hyp_would_value_differs, bumped
	 *      at index k = picked->kind in lock-step with the scalar from
	 *      the same cmp_hyp_would_pick() site.  Sum across kinds equals
	 *      the scalar modulo concurrent sampling.  Only the kinds that
	 *      the ladder can resolve to (EXACT, ENUM_FAMILY, BITMASK,
	 *      RANGE, BOUNDARY) ever populate; the remaining CMP_HYP_KIND_NR
	 *      slots stay zero by construction.  Paired with
	 *      cmp_hyp_would_pick_by_kind the ratio
	 *      value_differs_by_kind[k] / would_pick_by_kind[k] is the
	 *      per-kind rate at which the typed store's exemplar disagrees
	 *      with the raw-pool pick -- surfaces which hypothesis kind is
	 *      most often carrying a value the live path would not have
	 *      served.  SHADOW telemetry only -- no consumer reads it.
	 */
	unsigned long cmp_hyp_would_pick_by_kind[CMP_HYP_KIND_NR];
	unsigned long cmp_hyp_would_miss_by_kind[CMP_HYP_KIND_NR];
	unsigned long cmp_hyp_would_value_differs;
	unsigned long cmp_hyp_would_value_differs_by_kind[CMP_HYP_KIND_NR];

	/*
	 * LIVE typed-hypothesis inject counters.  Bumped from the inject
	 * arm in cmp_hints_try_get_ex() so the inject rate is legible
	 * alongside the would-pick / would-value-differs shadow rates
	 * above.  Pure observability -- the inject arm's gate
	 * (plateau == CMP_RISING_PC_FLAT AND ONE_IN(32)) and the
	 * typed-safe caller opt-in are what actually scope the rate.
	 *
	 *  cmp_hyp_live_injected
	 *      Total stash entries the live inject arm produced.  The
	 *      ratio cmp_hyp_live_injected / cmp_hints_consumed is the
	 *      fleet-level fraction of consumed hints whose value came
	 *      from a typed hypothesis rather than the raw pool.
	 *  cmp_hyp_live_injected_by_kind[k]
	 *      Per-kind partition of the above.  Sum across kinds
	 *      equals cmp_hyp_live_injected modulo concurrent sampling.
	 *      Only the four ladder kinds (EXACT, ENUM_FAMILY, BITMASK,
	 *      RANGE) ever populate; the other CMP_HYP_KIND_NR slots
	 *      stay zero by construction.
	 *  cmp_hyp_live_inject_gate_passed
	 *      Total times the conservative gate (plateau AND ONE_IN(32))
	 *      passed.  Paired with cmp_hyp_live_injected gives the
	 *      gate-passed-but-no-hypothesis rate (gate_passed minus
	 *      injected = empty-resolver bails), separating "the arm
	 *      did not fire" from "the arm fired but the store had
	 *      nothing to say at the served site".
	 */
	unsigned long cmp_hyp_live_injected;
	unsigned long cmp_hyp_live_injected_by_kind[CMP_HYP_KIND_NR];
	unsigned long cmp_hyp_live_inject_gate_passed;

	/*
	 * Per-reason close counters for the LIVE inject path.  Indexed by
	 * enum cmp_hyp_live_inject_reason (include/cmp_hints.h).  Each
	 * early-return / reject site on the inject path bumps exactly one
	 * slot, so the sum across slots + cmp_hyp_live_injected equals the
	 * total times the inject arm was entered with a typed-eligible
	 * caller.  Disambiguates "gate_passed=0" between "plateau never
	 * sat at CMP_RISING_PC_FLAT", "dice never won", "no hypothesis at
	 * the served site", "derive bailed", and "accept range rejected
	 * the derived value".  Pure observability; the gate logic itself
	 * is unchanged.
	 */
	unsigned long cmp_hyp_live_inject_reason[CMP_HYP_LIVE_INJECT_REASON_NR];

	/* Per-kind flat census of typed CMP hypothesis insert rejections
	 * caused by the per-syscall total cap (CMP_HYP_PER_SYSCALL).  Bumped
	 * in lock-step with the scalar cmp_hyp_pool_full from cmp_hyp_alloc()'s
	 * per-syscall-exhausted branch -- the sole bumper of cmp_hyp_pool_full.
	 * The cmp_hyp_observe() corruption bail bumps the sibling
	 * cmp_hyp_pool_overflow counter, so the sum across kinds equals
	 * cmp_hyp_pool_full modulo concurrent sampling.  Paired with
	 * cmp_hyp_inserted_by_kind this shows, per kind, which kind is
	 * consuming the per-syscall budget when cmp_hyp_pool_full dominates.
	 * SHADOW telemetry only -- no consumer reads it. */
	unsigned long cmp_hyp_pool_full_by_kind[CMP_HYP_KIND_NR];

	/*
	 * SHADOW old-flat-pool conversion baseline counters, partitioned by
	 * pool kind so the per-syscall pool and the field-scoped pool are
	 * directly comparable to each other and to the typed-hypothesis store
	 * above.  Together with the per-syscall cmp_hint_* arrays already in
	 * this struct, this is the proof side of the t75 row: "does the typed
	 * store predict better-converting picks than the flat pool".  Live
	 * inject path is unchanged -- these counters bump alongside the
	 * existing flat cmp_hint_* / cmp_hints_consumed credit drains using
	 * the pool_kind already carried on each stash entry.
	 *
	 * Semantics differ from the flat cmp_hint_wins / cmp_hint_misses by
	 * design: the flat counters bump ONCE per parent dispatch (the
	 * call-level outcome); the by-pool partitions bump ONCE PER STASHED
	 * ENTRY, mirroring the per-tier cmp_hint_tier_* discipline.  A
	 * dispatch that stashed two hints from different pool kinds bumps
	 * both kinds' counters once each, so SUM(by_pool[*]) for a given
	 * outcome can exceed the matching flat counter.  Consumers compute
	 * conversion as
	 *     pc_wins_by_pool[k] / (pc_wins_by_pool[k] + misses_by_pool[k])
	 * which is per-pool-kind and per-stash-entry, the cohort the
	 * follow-up live-pick weight would actually score.
	 *
	 *  cmp_hint_consumed_by_pool[k]
	 *      Per-pool-kind partition of cmp_hints_consumed.  Bumped from
	 *      cmp_hints_stash_consumed() once per successful try_get pull
	 *      using the pool_kind argument the caller already provides.
	 *      Denominator for the per-pool conversion ratio above.
	 *  cmp_hint_pc_wins_by_pool[k] / cmp_hint_misses_by_pool[k]
	 *      Per-pool-kind partition of cmp_hint_wins / cmp_hint_misses,
	 *      bumped per stashed entry from cmp_hints_feedback_credit_pc()
	 *      using the stashed entry's pool_kind.  PC-edge only.
	 *  cmp_hint_cmp_novelty_wins_by_pool[k]
	 *      Per-pool-kind partition of cmp_hint_cmp_novelty_wins, bumped
	 *      per stashed entry from cmp_hints_feedback_credit_cmp_novelty().
	 *      Kept SEPARATE from the PC partition so CMP novelty cannot
	 *      masquerade as PC-edge conversion (same discipline as the flat
	 *      cmp_hint_cmp_novelty_wins counter and the typed
	 *      cmp_hyp_cmp_novelty_wins counter).
	 */
	unsigned long cmp_hint_consumed_by_pool[CMP_HINT_POOL_KIND_NR];
	unsigned long cmp_hint_pc_wins_by_pool[CMP_HINT_POOL_KIND_NR];
	unsigned long cmp_hint_misses_by_pool[CMP_HINT_POOL_KIND_NR];
	unsigned long cmp_hint_cmp_novelty_wins_by_pool[CMP_HINT_POOL_KIND_NR];

	/*
	 * SHADOW zero-PC-win hard-cool budget census for the old-flat
	 * per-syscall pool.  The by-pool counters above quantify per-pool
	 * conversion but say nothing about how many injections a
	 * consecutive-miss cooling policy would have prevented.  Together
	 * these two counters answer that question at the fixed budget
	 * CMP_HINT_ZERO_WIN_BUDGET_T (see include/cmp_hints.h) so the
	 * follow-up live-cool switchover can be sized against real data
	 * rather than a guess.
	 *
	 * Bumped from cmp_hints_feedback_credit_pc()'s per-syscall arm
	 * using the per-pool zero_win_streak state on struct cmp_hint_pool.
	 * Only the CMP_HINT_POOL_PER_SYSCALL pool_kind participates -- the
	 * field-scoped pool is a different structural cohort (hash-keyed
	 * open-addressed buckets, not the flat pools[nr][do32] grid the
	 * "old-flat" language refers to) and would need its own budget
	 * shadow before it can be counted here.
	 *
	 *  cmp_hint_pool_zero_win_would_retire
	 *      Bumped once per per-syscall pool crossing the streak from
	 *      T-1 to T after a PC-outcome MISS credit -- the moment the
	 *      hypothetical hard-cool would first fire on that pool.  A
	 *      pool that gets a subsequent WIN resets its streak and can
	 *      cross again on a later run of misses, contributing a
	 *      second bump.  Interpret as "retire decisions the shadow
	 *      would have made", not "distinct pools retired".
	 *  cmp_hint_pool_zero_win_would_save
	 *      Bumped once per PC-outcome credit whose per-pool streak
	 *      (observed before this credit's update) was already >= T,
	 *      counting both MISS credits past the retirement threshold
	 *      and the WIN credits that would have been forfeit under a
	 *      permanent hard-cool.  Interpret as "injections a cool at
	 *      budget T would have prevented", spanning the saved-miss
	 *      lane the retirement is designed to avoid and the lost-win
	 *      lane it pays for.
	 *
	 * Live behaviour is byte-identical -- zero_win_streak is written
	 * and read but never consulted by any injection / eviction /
	 * ranking path; the shadow is measurement-only until the paired
	 * live-cool hypothesis-gate switchover lands.
	 */
	unsigned long cmp_hint_pool_zero_win_would_retire;
	unsigned long cmp_hint_pool_zero_win_would_save;

	/* Corruption-channel sibling of cmp_hyp_pool_full, split out so the
	 * legitimate per-syscall saturation lane and the wild-write bail
	 * become independently countable.  Bumped only from
	 * cmp_hyp_observe()'s pool->count > CMP_HYP_PER_SYSCALL guard --
	 * a value past the cap is a stomp signal, not back-pressure, and
	 * any non-zero delta here means a writer scribbled the per-syscall
	 * pool out of bounds.  cmp_hyp_pool_full now bumps ONLY from the
	 * cmp_hyp_alloc() per-syscall-exhausted branch (legit saturation).
	 * SHADOW telemetry only -- no consumer reads it. */
	unsigned long cmp_hyp_pool_overflow;

	/*
	 * SHADOW promotion-rule eval per cmp_hyp_credit_outcome() landing.
	 * After the per-hyp outcome counter and its kcov_shm flat twin are
	 * bumped, the credited hypothesis is evaluated against a fixed rule
	 * and one of the two arrays is bumped at index h->kind:
	 *
	 *  cmp_hyp_would_promote_by_kind[k]
	 *      Bumped when (pc_wins || transition_wins || corpus_save_wins)
	 *      on the credited hyp -- the hyp has produced at least one
	 *      attributable conversion and the live promotion path would
	 *      mark it CMP_HYP_STATE_PROMOTED.
	 *  cmp_hyp_would_demote_by_kind[k]
	 *      Bumped when (misses >= 8) AND none of the three win counters
	 *      above are set -- repeated consumption with no payoff, which
	 *      the live demotion path would mark CMP_HYP_STATE_DEMOTED.
	 *      The K=8 threshold matches the per-kind sub-cap order of
	 *      magnitude (CMP_HYP_PER_KIND==16); high enough to ignore a
	 *      handful of noise misses, low enough to fire inside a single
	 *      fuzz window on a genuinely dead hyp.
	 *
	 * Per credit landing at most one of the two arrays bumps (the two
	 * predicates are mutually exclusive); a hyp credited with neither
	 * (e.g. a single MISS, or a SKIP family outcome with no wins yet)
	 * bumps nothing.  Only the four ladder kinds (EXACT, ENUM_FAMILY,
	 * BITMASK, RANGE) ever populate, mirroring the existing _by_kind
	 * shadow arrays; the other CMP_HYP_KIND_NR slots stay zero by
	 * construction.  SHADOW telemetry only -- the h->state field is
	 * NOT mutated; no consumer reads either the array or the state.
	 */
	unsigned long cmp_hyp_would_promote_by_kind[CMP_HYP_KIND_NR];
	unsigned long cmp_hyp_would_demote_by_kind[CMP_HYP_KIND_NR];

	/*
	 * Picker decision census, indexed by the h->state of the
	 * hypothesis the picker returned.  Bumped once per non-NULL
	 * return from cmp_hyp_would_pick_locked().  The post-deploy
	 * confirmation that the state-aware picker is doing what it
	 * should: PROMOTED should dominate once the state machine has
	 * warmed up, OBSERVED holds steady on cold sites, and the
	 * DEMOTED slot reflects the rare re-roll surfacing.  Sized at
	 * the enum's NR cap; only the actually-returnable states
	 * (PROMOTED / OBSERVED / DEMOTED -- TESTING is treated as
	 * OBSERVED) ever populate. */
	unsigned long cmp_hyp_picked_by_state[CMP_HYP_STATE_NR];

	/* Pair counters for the RETIRED / DEMOTED re-roll arms of the
	 * picker.  cmp_hyp_skipped_retired_by_kind[k] bumps once per
	 * RETIRED slot of kind k the picker walked past in
	 * cmp_hyp_would_pick_locked();
	 * cmp_hyp_demoted_reroll_picked_by_kind[k] bumps when the
	 * demoted re-roll gate (1 / CMP_HYP_DEMOTED_RETRY_DENOM)
	 * actually fires for a kind-k hypothesis.  Together with
	 * cmp_hyp_picked_by_state[DEMOTED] this is the
	 * directly-measurable channel for "is RETIRED earning its
	 * keep" and "is the re-roll rate sane".  The kind partition
	 * lets the periodic dump answer "which hypothesis kind is
	 * hoarding RETIRED slots" and "which kind wins the demoted
	 * re-roll" without a separate hyp-pool walk. */
	unsigned long cmp_hyp_skipped_retired_by_kind[CMP_HYP_KIND_NR];
	unsigned long cmp_hyp_demoted_reroll_picked_by_kind[CMP_HYP_KIND_NR];

	/*
	 * Live h->state transition census.  Bumped once per state
	 * mutation from cmp_hyp_credit_outcome() at index
	 * [old_state][new_state].  Diagonal slots stay zero (no-op
	 * transitions are not bumped).  Pairs with the would_promote /
	 * would_demote shadow counters above: the shadow counters
	 * report "would the live state machine fire if it existed",
	 * the transitions array reports "did the live state machine
	 * actually fire".  Sized at the enum's NR cap; entries past
	 * the real five-state ladder stay zero by construction. */
	unsigned long cmp_hyp_state_transitions[CMP_HYP_STATE_NR][CMP_HYP_STATE_NR];

	/* Per-kind outcome partition for the typed-hyp credit channels.
	 * Bumped alongside the flat cmp_hyp_pc_wins / _transition_wins /
	 * etc.  Lets the periodic dump answer "which hypothesis kind is
	 * actually converting" without a separate hyp-pool walk.  SHADOW
	 * telemetry only -- no consumer reads it. */
	unsigned long cmp_hyp_pc_wins_by_kind[CMP_HYP_KIND_NR];
	unsigned long cmp_hyp_transition_wins_by_kind[CMP_HYP_KIND_NR];
	unsigned long cmp_hyp_misses_by_kind[CMP_HYP_KIND_NR];
	unsigned long cmp_hyp_corpus_save_by_kind[CMP_HYP_KIND_NR];
	unsigned long cmp_hyp_destructive_by_kind[CMP_HYP_KIND_NR];
	unsigned long cmp_hyp_context_skip_by_kind[CMP_HYP_KIND_NR];
	unsigned long cmp_hyp_cmp_novelty_wins_by_kind[CMP_HYP_KIND_NR];

	/*
	 * SHADOW histogram of the 8-band score_bucket value computed in
	 * cmp_hyp_credit_outcome().  Bumped once per credit landing, in
	 * lock-step with the h->score_bucket store, using the SAME bucket
	 * value just written.  Index k corresponds to band k:
	 *
	 *   0 idle (wins == 0 && pen == 0)
	 *   1 penalty-only       (wins == 0, pen >= 1)
	 *   2 heavy net-negative (pen >= wins + 4)
	 *   3 slight net-negative (wins < pen < wins + 4)
	 *   4 break-even         (wins == pen, both >= 1)
	 *   5 small net-positive  (1 <= wins - pen < 4)
	 *   6 moderate net-positive (4 <= wins - pen < 16)
	 *   7 strong net-positive   (wins - pen >= 16)
	 *
	 * The if/else ladder above the store is exhaustive over 0..7, so
	 * the index is bounded by construction; no clamp is needed.  Pure
	 * observability: the bucket value is unchanged, h->state is NOT
	 * mutated.
	 */
	unsigned long cmp_hyp_score_bucket_census[8];

	/*
	 * SHADOW census of which probe class cmp_hyp_derive_value() emits
	 * each time it converts a resolved hypothesis to a concrete value
	 * for the LIVE typed-inject arm.  Bumped once per successful
	 * derivation, at the branch the function ACTUALLY takes today --
	 * boundary probes (lo-1, hi+1) are deliberately not emitted by the
	 * derive ladder (see the comment above cmp_hyp_derive_value) and
	 * have no class here; adding them would lie about the producer.
	 *
	 *  EXACT_EXEMPLAR            -- CMP_HYP_EXACT path
	 *  ENUM_EXEMPLAR/LO/HI       -- CMP_HYP_ENUM_FAMILY 3-way pick
	 *  BITMASK_SINGLE_BIT        -- CMP_HYP_BITMASK popcount-walk hit
	 *  EXEMPLAR_FALLBACK         -- BITMASK conservative fallback
	 *                               (mask == 0, and the popcount-walk
	 *                               post-loop guard).  Counted as its
	 *                               own class rather than folded into
	 *                               BITMASK_SINGLE_BIT so the share of
	 *                               derivations that degrade to the
	 *                               exemplar is directly visible.
	 *  RANGE_LO/HI/MIDPOINT      -- CMP_HYP_RANGE 3-way pick
	 *
	 * The hi < lo reject and the default-kind reject return false
	 * without emitting a value, so nothing bumps for those.
	 *
	 * Write-only telemetry: no consumer reads this array yet, no CLI
	 * knob gates the derivation, and the derived value the live inject
	 * arm receives is byte-identical to the pre-census path.
	 */
	unsigned long cmp_hyp_probe_class_hist[CMP_HYP_PROBE_CLASS_NR];

	/*
	 * SHADOW BOUNDARY-lane counters for the inequality-gate angle.
	 * EXACT-inject is dead because strict inequalities (x < N, x >= N)
	 * cannot pass on the const N itself; the passing value is N+/-1,
	 * which neither EXACT nor RANGE will derive.  CMP_HYP_BOUNDARY
	 * populates from a SINGLE const observation (no RANGE-style
	 * seen>=3 / span<=32 gate) and derives a neighbourhood ladder
	 * {N-1, N+1, N, N+/-2} so the boundary-adjacent values reach the
	 * kernel.  Pure observability here -- the existing live inject
	 * arm's would_pick_locked precedence is unchanged, so BOUNDARY
	 * only sees live air when nothing else explains the served site;
	 * the counters below are how we measure whether that ever fires.
	 *
	 *  cmp_hyp_boundary_inserted
	 *      Bumped once per fresh CMP_HYP_BOUNDARY allocation in
	 *      cmp_hyp_observe().  Proves the population path fires for
	 *      single-const inequality sites; staying zero means the lane
	 *      is dead before it starts and there is nothing to measure.
	 *  cmp_hyp_boundary_candidate_available
	 *      Bumped at each successful raw cmp_hints_try_get_ex() pick
	 *      where a CMP_HYP_BOUNDARY entry exists at the served
	 *      (cmp_ip, width) AND the derive arm would not bail.
	 *      Decoupled from the value-keyed would_pick / find_for_credit
	 *      resolvers per the spec's Q3 analysis -- a counter that just
	 *      counted "BOUNDARY won the precedence ladder" would stay
	 *      structurally near zero (EXACT is populated at every
	 *      observation and always outranks).  This is the headline
	 *      shadow metric: it estimates how often the boundary arm
	 *      WOULD have something to inject if precedence let it.
	 *  cmp_hyp_boundary_credit_window_hits
	 *      Bumped in cmp_hyp_find_for_credit()'s BOUNDARY arm each
	 *      time a credited value resolves to BOUNDARY via the
	 *      |v - exemplar| <= 2 window (EXACT / ENUM / BITMASK / RANGE
	 *      having all missed first).  This is the conversion proof
	 *      for the lane: a credited PC / transition win at a value
	 *      nothing else explains is a boundary-adjacent neighbour the
	 *      derive ladder produced.
	 *
	 * Kill criterion (same bar that killed exact-inject): if a
	 * representative run shows cmp_hyp_live_injected_by_kind[BOUNDARY]
	 * in the hundreds with cmp_hyp_pc_wins / cmp_hyp_transition_wins
	 * credited to BOUNDARY ~= 0, the lane is dead -- strip it.
	 */
	unsigned long cmp_hyp_boundary_inserted;
	unsigned long cmp_hyp_boundary_candidate_available;
	unsigned long cmp_hyp_boundary_credit_window_hits;

	/*
	 * Childop CMP harvest shadow counters.  Populated only when
	 * --childop-cmp-harvest=on opens the kcov_cmp_bracket on a
	 * CMP-mode child at the child.c childop dispatch gate; the OFF
	 * default leaves every counter below at zero so the row is
	 * directly observable as "harvest path is dormant on this build".
	 *
	 * Per the design (projects/trinity/childop-cmp-integration-design.md
	 * sections 3.1 / 3.2 / 4):
	 *   - Inserts feed the QUARANTINED childop lane
	 *     (cmp_hints_shared.childop_recent_pools[nr][do32]), not the
	 *     durable per-syscall pool, so no childop constant can evict a
	 *     random-syscall constant out of the 16-entry LRU until a
	 *     promotion phase (C6) is earned per-nr by the conversion-chain
	 *     metrics that land alongside the consume side (C2/C4).
	 *   - All bumps key on the real __NR_X carried by the wrapped
	 *     childop syscall (do32=false; childops issue native 64-bit
	 *     syscalls only) so the consumer-side resolver (when it lands)
	 *     can look constants up under the same (nr, do32) coordinate
	 *     the random-syscall picker uses.
	 *   - window_contaminated[nr] is the §3.2 "all-routed invariant"
	 *     debug counter: best-effort signal that a wrapped collect saw
	 *     records when the kernel was not expected to run (some
	 *     unwrapped helper syscall landed inside the reset/syscall/
	 *     collect window and was misattributed to nr).  Pure
	 *     observability -- the cap arms below are the actual
	 *     domination defence.
	 */
	unsigned long childop_cmp_brackets_opened;
	unsigned long childop_cmp_brackets_skipped_pc_mode;
	unsigned long childop_cmp_brackets_skipped_incapable;
	unsigned long childop_cmp_brackets_skipped_nested;
	unsigned long childop_cmp_brackets_skipped_inactive;
	unsigned long childop_cmp_record_cap_hits;
	unsigned long childop_cmp_insert_cap_hits;
	unsigned long childop_cmp_syscalls_sampled[MAX_NR_SYSCALL];
	unsigned long childop_cmp_records_collected[MAX_NR_SYSCALL];
	unsigned long childop_cmp_pool_inserts[MAX_NR_SYSCALL];
	unsigned long childop_cmp_pool_evicts[MAX_NR_SYSCALL];
	unsigned long childop_cmp_trace_truncated[MAX_NR_SYSCALL];
	unsigned long childop_cmp_window_contaminated[MAX_NR_SYSCALL];
	/* Per-childop syscall-sample census, indexed by enum child_op_type.
	 * Lets the operator see which childop is dominating the lane before
	 * the §3.2 noisy-syscall skip-list would need tuning.  Same
	 * KCOV_CHILDOP_NR_MAX bound the PC-side childop_kcov_* arrays use. */
	unsigned long childop_cmp_syscalls_sampled_per_op[KCOV_CHILDOP_NR_MAX];

	/*
	 * SHADOW counters for the fleet-wide shared cmp_ip tier
	 * (cmp_hints_shared.shared_tier[]).  All six are RELAXED + flat.
	 * The tier's data model, entry-path filter, and rollout gate live
	 * in include/cmp_hints.h -- see the CMP_SHARED_TIER_* /
	 * cmp_shared_tier_mode comments there for the shape.  A default
	 * OFF-mode build never touches any of these counters (the collect-
	 * side insert and the get-side probe both short-circuit before
	 * any shm access), so an OFF vs pre-tier-baseline byte-for-byte
	 * pick stream reads all six as zero on either side of the diff.
	 *
	 *  cmp_shared_tier_ips
	 *      Cumulative: bumped once per first-time bucket claim in
	 *      cmp_shared_tier_insert().  Monotonically non-decreasing --
	 *      the tier has no eviction path (fallback pool; drops on
	 *      probe exhaustion are silent).  Reads the OCCUPANCY size of
	 *      the tier at any given moment.  Sibling denominator for
	 *      cmp_shared_tier_entry_path_excluded_ips below; the non-
	 *      entry-path IP population is (ips - excluded) and is what
	 *      the shadow probe consults on every cold per-nr miss.
	 *  cmp_shared_tier_entries
	 *      Cumulative: bumped once per fresh (value, size) pair
	 *      appended into a bucket's values[] array.  Sibling of
	 *      cmp_shared_tier_ips: total entries / total IPs is the
	 *      average value-set density per bucket, one of the section
	 *      6 overlap-mine deltas the shadow validates.
	 *  cmp_shared_tier_entry_path_excluded_ips
	 *      Cumulative: bumped once per bucket that crosses the
	 *      CMP_SHARED_TIER_ENTRY_PATH_NR_MAX distinct-nr threshold and
	 *      latches entry_path_excluded=1.  Entry-path IPs (do_syscall_
	 *      64 / seccomp gate / kcov entry / copy_from_user length
	 *      probes / ...) are noise as a warm-start seed and this
	 *      counter measures how much of the tier population is
	 *      filtered by the entry-path rule.
	 *  cmp_shared_tier_shadow_warmstart_eligible
	 *      Cumulative: bumped once per cmp_hints_try_get_ex() cold-
	 *      miss return (durable pool empty on the requested (nr, do32),
	 *      recent-tier pre-pass returned MISS) where the shared tier
	 *      had at least one non-entry-path IP available to seed from
	 *      (cmp_shared_tier_ips > cmp_shared_tier_entry_path_excluded_
	 *      ips at probe time).  This is the OPPORTUNITY size the
	 *      Phase 2 live warm-start would consume -- the follow-up
	 *      commit converts this shadow eligibility into a live seed
	 *      served from the tier, at which point the counter becomes
	 *      the denominator for actual warm-start yield.
	 *  cmp_shared_tier_shadow_dedup_supplied
	 *      Cumulative: bumped once per cmp_shared_tier_insert() call
	 *      where THIS nr is a NEW contributor for the bucket AND the
	 *      (value, size) pair was already present from a prior nr's
	 *      contribution.  The tier could have SUPPLIED this cross-nr
	 *      redundant learn via warm-start instead of us learning it
	 *      here -- the exact section 6 overlap-mine signal (~87% of
	 *      learned entries are cross-nr duplicates) that motivates
	 *      the shared tier at all.  Ratio to cmp_shared_tier_entries
	 *      is the cross-nr redundancy rate on live commits.
	 *
	 * Append-only at the tail per the existing convention so consumer
	 * offsets stay stable.
	 */
	unsigned long cmp_shared_tier_ips;
	unsigned long cmp_shared_tier_entries;
	unsigned long cmp_shared_tier_entry_path_excluded_ips;
	unsigned long cmp_shared_tier_shadow_warmstart_eligible;
	unsigned long cmp_shared_tier_shadow_dedup_supplied;

	/*
	 * COMBINED-mode QUARANTINED serve counters for the shared
	 * cmp_ip tier -- the credit-partitioned live wire-up of the
	 * shadow eligibility rate above.  Fire only when
	 * cmp_shared_tier_mode == CMP_SHARED_TIER_MODE_COMBINED;
	 * SHADOW_ONLY and OFF leave all four at zero and a fixed-seed
	 * pick stream stays bit-for-bit identical to the pre-serve
	 * baseline.
	 *
	 *  cmp_shared_tier_serves
	 *      Bumped once per cmp_shared_tier_try_serve_cold_miss()
	 *      return that actually served a value to the get-path
	 *      (dice passed, non-excluded bucket elected, transform
	 *      applied, accept range not violated).  Ratio against
	 *      cmp_shared_tier_shadow_warmstart_eligible is the serve
	 *      fraction of the opportunity rate the shadow probe
	 *      already measures -- capped at 1/CMP_SHARED_TIER_SERVE_
	 *      DICE by the per-eligible-miss dice.
	 *  cmp_shared_tier_serve_accept_reject
	 *      Bumped once per served value the caller's accept range
	 *      subsequently rejected (dice + bucket election passed,
	 *      but the shared-tier value fell outside [lo, hi]).  The
	 *      invalid-rate half of the "what fraction of shared-
	 *      served values yield progress OR induce an out-of-range
	 *      draw" question this lane is being measured on.
	 *      Mirrors the CMP_HYP_LIVE_INJECT_REASON_ACCEPT_REJECT
	 *      discipline the typed inject arm uses.
	 *  cmp_hint_tier_shared_wins
	 *  cmp_hint_tier_shared_misses
	 *      Per-stash-entry PC outcome partition for shared-served
	 *      entries, drained from cmp_hints_feedback_credit_pc().
	 *      This is the ONLY credit lane a stash entry stamped
	 *      served_from_shared reaches -- the drain skips the
	 *      cmp_hint_credit_entry_per_syscall / _field per-entry
	 *      bump, the cmp_hint_pc_wins_by_pool / _misses_by_pool
	 *      partition, the cmp_hint_callsite_pc_wins / _misses
	 *      partition, the cmp_hint_pool_zero_win_would_save /
	 *      _retire zero-win-budget census, the
	 *      cmp_hint_tier_recent / _durable / _durable_age wins /
	 *      misses splits, and the typed-hyp cmp_hyp_credit_
	 *      outcome / cmp_hyp_credit_consume / cmp_hyp_would_pick
	 *      taps for every shared-served entry.  This is the load-
	 *      bearing quarantine invariant: a cross-syscall shared-
	 *      served value cannot masquerade as native durable /
	 *      recent evidence in any operator-facing conversion rate
	 *      or per-entry weight.  cmp_hint_tier_shared_wins /
	 *      (cmp_hint_tier_shared_wins + cmp_hint_tier_shared_
	 *      misses) is the shared-tier bootstrap's conversion rate;
	 *      the go-live decision (promote shared-served constants
	 *      into native pool evidence, or drop the serve path) is
	 *      gated on this ratio + the accept-reject rate above,
	 *      and lands in a follow-up commit off this measurement.
	 *
	 * Append-only at the tail per the existing convention so
	 * consumer offsets stay stable.
	 */
	unsigned long cmp_shared_tier_serves;
	unsigned long cmp_shared_tier_serve_accept_reject;
	unsigned long cmp_hint_tier_shared_wins;
	unsigned long cmp_hint_tier_shared_misses;

	/*
	 * SHADOW consume-side counters for the childop CMP path -- the
	 * consumer half of the harvest counters above.  All per-nr and
	 * RELAXED; keyed by the real __NR_X the childop passed at its
	 * field site (nr-only, no cmd/field split -- pilot single-
	 * semantic).  Bumped from childop_cmp_value() when
	 * --childop-cmp-consume=on; the OFF default short-circuits
	 * before any shm access, so every counter reads as zero on the
	 * default build and a fixed-seed pick stream is byte-identical
	 * either way.
	 *
	 * Consume-side names mirror the CMP-hyp shadow counters
	 * (cmp_hyp_would_pick_by_kind / would_miss_by_kind /
	 * would_value_differs) with per-nr partitioning replacing the
	 * per-kind partition; the two lanes are independent and can be
	 * summed for a fleet-wide would-pull rate.  Any counter here
	 * SIZES what a future C3/C4 live consume WOULD do at this site
	 * -- no arg is changed, no outcome is changed, and the pick
	 * stream stays byte-for-byte identical to a build without the
	 * knob.
	 *
	 *  childop_cmp_consume_would_pick[nr]
	 *      Bumped once per childop_cmp_value() call where the
	 *      cmp_hints_try_get_ex() shadow probe returned a hint (a
	 *      pool value exists at this (nr, do32=false, use, cmp_ip
	 *      family) and the transform succeeded).  The hint is NOT
	 *      applied -- the caller still writes its rng-drawn
	 *      fallback -- but the counter records the OPPORTUNITY:
	 *      how many field-site draws could have been replaced by a
	 *      learned constant on a run with the same seed.  Sibling
	 *      denominator for _would_value_differs below.
	 *
	 *  childop_cmp_consume_would_miss[nr]
	 *      Bumped once per childop_cmp_value() call where the
	 *      cmp_hints_try_get_ex() probe returned FALSE (pool empty
	 *      on this (nr, do32=false), chaos suppression, or the
	 *      accept-range gate rejected).  Sum with _would_pick is
	 *      the field-site draw volume the resolver saw; the ratio
	 *      is the raw pool-populated rate at these sites.
	 *
	 *  childop_cmp_consume_would_value_differs[nr]
	 *      Bumped once per _would_pick where the returned hint
	 *      value differed from the caller's rng-drawn fallback (a
	 *      LIVE consume at this site would have actually changed
	 *      the arg the syscall received).  Ratio to _would_pick is
	 *      the "arg would have changed" rate -- the C3/C4 decision
	 *      gate for whether a live consume at this site has any
	 *      hope of moving downstream metrics at all.
	 *
	 *  childop_cmp_consume_candidate_accepted[nr]
	 *  childop_cmp_consume_arg_changed[nr]
	 *  childop_cmp_consume_outcome_changed[nr]
	 *  childop_cmp_consume_new_cov[nr]
	 *      Conversion-chain counters MEASURED-ONLY in this build --
	 *      they are declared here so the shm layout settles before
	 *      the follow-up C3/C4 slices, but NO bump site exists in
	 *      the shadow-only tree.  A default run reads all four as
	 *      zero, always.  When the live-consume slice lands, each
	 *      stage of the chain (candidate accepted by the resolver
	 *      transform -> arg written differs from the rng fallback
	 *      -> the syscall's dispatch outcome differs from a
	 *      recorded shadow-off outcome -> the call produced fresh
	 *      PC coverage) bumps its counter, giving the C4 A/B
	 *      readout a single per-nr yield ratio to size the win at.
	 *
	 * Append-only at the tail per the existing convention so
	 * consumer offsets stay stable.
	 */
	unsigned long childop_cmp_consume_would_pick[MAX_NR_SYSCALL];
	unsigned long childop_cmp_consume_would_miss[MAX_NR_SYSCALL];
	unsigned long childop_cmp_consume_would_value_differs[MAX_NR_SYSCALL];
	unsigned long childop_cmp_consume_candidate_accepted[MAX_NR_SYSCALL];
	unsigned long childop_cmp_consume_arg_changed[MAX_NR_SYSCALL];
	unsigned long childop_cmp_consume_outcome_changed[MAX_NR_SYSCALL];
	unsigned long childop_cmp_consume_new_cov[MAX_NR_SYSCALL];

	/* Shadow measurement of the non-const relational CMP drop-site.
	 * The per-record loop in cmp_hints_collect() drops every
	 * !KCOV_CMP_CONST record (both operands runtime) into
	 * cmp_hints_save_reject_nonconst.  These five counters measure
	 * how much of that dropped stream WOULD be actionable if a
	 * future "relational" attribution lane were built -- purely a
	 * headroom sizing readout, no live path reads them.  Gated on
	 * rec_num_args > 0 (dispatch-time arg snapshot present); NOT
	 * gated on attribute_enabled (that flips off under
	 * reexec_pending back-pressure, a live-resource throttle the
	 * shadow lane must not inherit).  Append-only at the tail per
	 * the existing convention so consumer offsets stay stable. */
	unsigned long cmp_nonconst_arg1_unique;      /* rec_args has exactly one slot == arg1 */
	unsigned long cmp_nonconst_arg2_unique;      /* rec_args has exactly one slot == arg2 */
	unsigned long cmp_nonconst_both_match;       /* both operands appear in rec_args (>=1 each) */
	unsigned long cmp_nonconst_would_attribute;  /* exactly one side uniquely ours, other absent */
	unsigned long cmp_nonconst_measured;         /* addressable denominator: non-const records
						      * where rec_num_args>0 (the population the
						      * shadow measurement actually evaluated).
						      * reject_nonconst is strictly larger -- it
						      * counts every non-const drop incl. child==
						      * NULL / redqueen disabled / in_reexec /
						      * dispatch_args invalid / reexec_pending
						      * full-at-entry, all cases where rec_num_args
						      * is 0 and the per-slot loop never runs. */

	/* Shadow measurement of a high-bit-preserving replacement for the
	 * width-masked CMP RedQueen pin.  On a unique width match the live
	 * consumer overwrites the WHOLE 64-bit arg slot with arg1 (the
	 * kernel constant), clobbering the slot's high bits; an
	 * alternative splice -- replacement = (orig & ~width_mask) |
	 * (arg1 & width_mask) -- which matters when the high bits feed a
	 * separate validation path.  These two counters size how often
	 * that splice would produce a byte-different pin from today's
	 * whole-slot overwrite, so the headroom of a future preserving
	 * lever can be judged before building it.  Nothing in the collect /
	 * save / re-exec paths reads them; live pin is unchanged.  Append-
	 * only at the tail per convention so consumer offsets stay stable. */
	unsigned long cmp_width_pin_total;           /* unique width-match stamps executed */
	unsigned long cmp_width_pin_would_differ;    /* subset where the matched slot has non-zero
						      * bits outside width_mask, so a high-bit-
						      * preserving splice would produce a value
						      * different from today's whole-slot overwrite */

	/* Shadow measurement of a POW2 / alignment probe class in the
	 * typed-hypothesis derive.  Fires only on picks whose callsite
	 * is a size / offset-class argtype (ARG_RANGE / ARG_STRUCT_SIZE
	 * today) AND whose picked exemplar C is at or near a power of
	 * two: the class would emit candidates from {C>>1, C, C<<1,
	 * round-to-512, round-to-4096, round-to-page-size}.  The live
	 * derive path (cmp_hyp_derive_value's *out and probe-class
	 * histogram bump) is byte-for-byte unchanged; these two counters
	 * size the coverage headroom of promoting the class:
	 * would_fire counts every eligible pick (argtype gate AND bit-
	 * pattern gate both open); would_win counts the subset where at
	 * least one pow2 / align candidate differs from the value the
	 * live derive lane just emitted -- i.e. the class would have
	 * contributed a value the existing lanes did not.  Nothing on
	 * the live pick / inject / credit path reads these; ratio in
	 * per-mille sizes the delta a live promotion would open up.
	 * Append-only at the tail per convention so consumer offsets
	 * stay stable. */
	unsigned long cmp_hyp_pow2_derive_would_fire;
	unsigned long cmp_hyp_pow2_derive_would_win;

	/* Shadow measurement of BITMASK combination probe classes in the
	 * typed-hypothesis derive.  The live BITMASK lane today emits
	 * only single-bit values chosen uniformly from picked->mask
	 * (the accumulated OR of all single-bit constants observed at
	 * this (nr, cmp_ip, width)); two natural combination probes
	 * carry information single-bit picks structurally cannot:
	 *
	 *  FULL_OR: emit picked->mask itself once popcount(mask) >= 2.
	 *  Reaches `(flags & A) && (flags & B)` gates the single-bit
	 *  lane cannot converge on -- the two arms need both bits set
	 *  simultaneously, and a lane that only ever fires ONE bit at a
	 *  time hits AT MOST one arm per probe.
	 *
	 *  ANDNOT_TOGGLE: gated on popcount(~mask & width_mask) small
	 *  enough (1..8 bits) that the complement forms a plausible
	 *  disallowed-bit set for an `x & ~c` allow-mask check.  Emits
	 *  candidates of the form (mask | (1<<b)) for each disallowed
	 *  bit b -- flipping one at a time surfaces WHICH disallowed
	 *  bit trips the gate.
	 *
	 * would_fire counts every derive at a BITMASK-picked hypothesis
	 * whose accumulated mask makes the respective combo eligible;
	 * would_win counts the subset where the combo candidate differs
	 * from the value the live BITMASK lane just emitted (a single
	 * bit picked from the mask), so a live promotion would surface
	 * a value the existing lane did not.  Nothing on the live pick /
	 * inject / credit path reads these counters; ratio in per-mille
	 * sizes the delta a live promotion would open up.  Append-only
	 * at the tail per convention so consumer offsets stay stable. */
	unsigned long cmp_hyp_bitmask_full_or_would_fire;
	unsigned long cmp_hyp_bitmask_full_or_would_win;
	unsigned long cmp_hyp_bitmask_andnot_toggle_would_fire;
	unsigned long cmp_hyp_bitmask_andnot_toggle_would_win;

	/*
	 * SHADOW win-scalar for the field-scoped CMP inject arm.
	 *
	 * Sibling to the existing cmp_field_consumer_would_pick baseline
	 * above: pick counts every post-guard eligible would-pick (the
	 * denominator the shadow_arm_registry evaluator reads), and this
	 * counter is the numerator -- bumped on the subset where the
	 * pool would have offered a value DIFFERENT from the value the
	 * generator was about to write to that slot.  A raw would-pick
	 * that always resolves to the same value the generator already
	 * chose is a no-op for coverage -- the live arm would flip zero
	 * bytes on the wire and no downstream metric could move.  The
	 * differs subset is the actionable slice: only these would_picks
	 * could produce a byte-changed arg on a live flip.
	 *
	 * Mirrors the measure-only "differs" precedent set by
	 * childop_cmp_consume_would_value_differs above: bumped once
	 * per would_pick where the elected pool entry differs from the
	 * caller's fallback, active in BOTH arms (SHADOW and LIVE), and
	 * strictly bounded above by cmp_field_consumer_would_pick so
	 * differs/would_pick reads as a plain per-mille rate.  Elected
	 * entry is entries[0] as a deterministic RNG-free proxy for the
	 * live arm's uniform draw (see cmp_hints_field_try_get): pool
	 * rotation over run duration surfaces the population differs-
	 * rate through slot 0 without advancing per-child RNG state or
	 * touching the generator, keeping the shadow bump dry-run byte-
	 * identical to a build without this row.
	 *
	 * Append-only at the tail per the existing convention so
	 * consumer offsets stay stable.
	 */
	unsigned long cmp_field_consumer_would_value_differs;

	/*
	 * SHADOW would-confirm win-scalar for the shared-tier cold-serve
	 * arm.
	 *
	 * Sibling to the cmp_shared_tier_shadow_warmstart_eligible
	 * baseline above: eligible bumps once per cmp_hints_try_get_ex()
	 * cold-miss return where the shared tier had at least one non-
	 * entry-path IP available to seed from (the OPPORTUNITY size a
	 * live cold-serve would consume), and this counter is the
	 * numerator -- bumped on the subset where the deterministically
	 * elected (cmp_ip, value, size) triple from the shared tier is
	 * already present in THIS nr's OWN native durable / recent pool
	 * at probe time (exact identity match).  A would-confirm bump
	 * means the shared tier's cold-serve would have elected a triple
	 * the native pool for this syscall already carries -- i.e. a
	 * live serve at this site would confirm what the native evidence
	 * already agrees with, and the elected value is not a cross-
	 * syscall lift the native pool has never seen.
	 *
	 * The election is READ-ONLY, no-RNG and deterministic (first
	 * occupied non-entry-path-excluded bucket by ascending index):
	 * no generator state is advanced and the pick stream stays byte-
	 * for-byte identical to a build without this row.  Bumped
	 * strictly inside the SAME eligible branch that bumps
	 * cmp_shared_tier_shadow_warmstart_eligible so
	 * would_confirm <= warmstart_eligible holds and the ratio
	 * reads as a plain per-mille rate -- the fraction of shared-
	 * tier cold-serve opportunities whose elected triple is already
	 * corroborated by this nr's own native evidence.
	 *
	 * CONSERVATIVE FLOOR: "present now" undercounts delayed native
	 * discovery -- a native pool that eventually observes the triple
	 * but has not yet at probe time reads as a would-confirm MISS.
	 * The measurement bounds the confirm fraction from below, which
	 * is the direction the go/no-go decision needs.
	 *
	 * Append-only at the tail per the existing convention so
	 * consumer offsets stay stable.
	 */
	unsigned long cmp_shared_tier_shadow_would_confirm;

	/*
	 * RedQueen plateau_burst per-call drain-cap A/B measure arm counters.
	 *
	 * The go/no-go metric for the burst_drain_arm_b measure lives in the
	 * distinct-edge lift domain, not the CMP-record domain: the 85k
	 * distinct-PC-edge wall is what the plateau intensification is meant
	 * to break, but reexec_new_cmps_total counts bloom-novel CMP records
	 * and a fresh CMP that opens no new distinct edge is invisible to
	 * that wall.  reexec_new_edges_total wires the 6th dispatch_step()
	 * out-param (pcres.transition_edges_real_local at
	 * random_syscall/dispatch.c:709) into redqueen_reexec_step()'s
	 * inner_new_cmp > 0 success block and accumulates it in lock-step
	 * with reexec_new_cmps_total, so a run can be scored on transition-
	 * distinct-edge lift instead of CMP-record lift.
	 *
	 * The _by_arm[2] triplet partitions each numerator by the child's
	 * burst_drain_arm_b stamp (arm A = index 0, arm B = index 1), bumped
	 * from redqueen_reexec_step() inside the same critical sections that
	 * bump the flat counters.  reexec_attempts_by_arm supplies the
	 * per-arm denominator; a per-arm distinct-edge ratio is then
	 *     reexec_new_edges_by_arm[B] / reexec_attempts_by_arm[B]
	 * versus the same ratio for arm A -- the shadow success criterion
	 * (§4 of the plateau-burst spec) is arm-B >= arm-A.
	 *
	 * Append-only at the tail per the existing convention.
	 */
	unsigned long reexec_new_edges_total;
	unsigned long reexec_attempts_by_arm[2];
	unsigned long reexec_new_cmps_by_arm[2];
	unsigned long reexec_new_edges_by_arm[2];
};

extern struct kcov_shared *kcov_shm;

/* Combined per-nr accessors for the [nr][do32?1:0]-split productivity
 * arrays.  Readers that want the pre-split scalar sum both arch dims
 * with RELAXED atomics -- a torn pair across the two loads is a
 * one-bump skew, well inside the slack the picker accept/retry loop
 * already tolerates.  Callers gate on kcov_shm != NULL and nr <
 * MAX_NR_SYSCALL themselves; these helpers do not re-check. */
static inline unsigned long per_syscall_edges_total(unsigned int nr)
{
	return __atomic_load_n(&kcov_shm->per_syscall_edges[nr][0],
			       __ATOMIC_RELAXED) +
	       __atomic_load_n(&kcov_shm->per_syscall_edges[nr][1],
			       __ATOMIC_RELAXED);
}
static inline unsigned long per_syscall_calls_total(unsigned int nr)
{
	return __atomic_load_n(&kcov_shm->per_syscall_calls[nr][0],
			       __ATOMIC_RELAXED) +
	       __atomic_load_n(&kcov_shm->per_syscall_calls[nr][1],
			       __ATOMIC_RELAXED);
}
static inline unsigned long per_syscall_edges_previous_total(unsigned int nr)
{
	return kcov_shm->per_syscall_edges_previous[nr][0] +
	       kcov_shm->per_syscall_edges_previous[nr][1];
}
static inline unsigned long per_syscall_edges_prior_total(unsigned int nr)
{
	return kcov_shm->per_syscall_edges_prior[nr][0] +
	       kcov_shm->per_syscall_edges_prior[nr][1];
}
static inline unsigned long per_syscall_calls_prior_total(unsigned int nr)
{
	return kcov_shm->per_syscall_calls_prior[nr][0] +
	       kcov_shm->per_syscall_calls_prior[nr][1];
}


/* Storage-neutrality asserts.  These pin sizeof(struct kcov_shared)
 * and offsetof for a set of load-bearing fields so an accidental
 * reorder or padding-introducing edit fails to compile instead of
 * silently shifting layout across a wide set of readers. */
_Static_assert(sizeof(struct kcov_shared) == 25845016UL,
	"struct kcov_shared sizeof drifted -- audit layout before updating this");
_Static_assert(offsetof(struct kcov_shared, bucket_seen) == 0UL,
	"kcov_shared.bucket_seen must remain the first field");
_Static_assert(offsetof(struct kcov_shared, cmp_records_collected) == 8388672UL,
	"kcov_shared.cmp_records_collected offset drifted");
_Static_assert(offsetof(struct kcov_shared, cmp_hints_injected) == 8388728UL,
	"kcov_shared.cmp_hints_injected offset drifted");
_Static_assert(offsetof(struct kcov_shared, per_syscall_edges) == 8397720UL,
	"kcov_shared.per_syscall_edges offset drifted");
_Static_assert(offsetof(struct kcov_shared, reexec_new_edges_by_arm) == 25845000UL,
	"kcov_shared last-field offset drifted -- append-only tail broken");
