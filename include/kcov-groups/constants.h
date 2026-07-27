#pragma once

/* KCOV sizing constants, thresholds, and remote-mode tunables split
 * out of kcov-types.h.  Pure #defines -- no types.  Included from
 * kcov-types.h so consumers keep seeing these symbols transparently. */

#include "exit.h"	/* NUM_EXIT_REASONS -- KCOV_RECOVERY_EXHAUSTED_EXIT_CODE */

/*
 * KCOV coverage collection support.
 *
 * Automatically detects whether the kernel supports KCOV by trying to
 * open /sys/kernel/debug/kcov at child init time. If it works, coverage
 * is collected around each syscall invocation: PC bucket coverage (a
 * shared bucket-seen table with AFL-style hit-count bucketing, seen
 * globally across all children) plus optional shadow transition
 * coverage (see the kcov_transition_coverage_mode enum below).
 *
 * No command-line flag needed — KCOV is used when available, silently
 * skipped when not.
 */

/* Default size of the per-child KCOV trace buffer (number of unsigned
 * longs).  256K entries is 2MB on 64-bit.  Deep kernel paths (long
 * io_uring chains, deep btrfs ops, multi-level fs walks, large
 * genetlink families) can blow past the previous 64K-entry budget and
 * silently truncate the tail of the trace, dropping uncounted edge
 * coverage on exactly the syscalls the fuzzer would learn the most
 * from.
 *
 * This is the compile-time DEFAULT and lower bound for the runtime
 * --kcov-trace-size knob (see kcov_trace_size in params.h).  Every
 * KCOV_INIT_TRACE / KCOV_REMOTE_ENABLE area_size / mmap / munmap /
 * truncation-clamp site reads kcov_trace_size; KCOV_TRACE_SIZE itself
 * still names the static default a caller falls back to before
 * parse_args has run, and is the unit the operator-facing help text
 * and the per-syscall truncation diagnostics name. */
#define KCOV_TRACE_SIZE (256 << 10)

/* Upper bound on --kcov-trace-size.  4M longs = 32MB per child;
 * Trinity's per-fleet child count makes this the realistic A/B-test
 * headroom without turning a typo into an OOM. */
#define KCOV_TRACE_SIZE_MAX (4UL << 20)

/* Size of the per-child KCOV comparison-operand buffer (number of
 * unsigned longs).  Each CMP record is 4 u64 (type, arg1, arg2, ip),
 * so 256K u64 entries hold up to (256K - 1)/4 ≈ 64K records (~2MB
 * per child).  Sized to match the PC trace buffer's footprint; CMP
 * record rate per syscall is typically lower than PC rate, but big
 * enough to absorb deep validation paths without truncating tails. */
#define KCOV_CMP_BUFFER_SIZE (256 << 10)
#define KCOV_CMP_RECORDS_MAX ((KCOV_CMP_BUFFER_SIZE - 1) / 4)

/* Number of distinct edge slots PCs hash into.
 * distinct_edges counts unique occupied slots in this 8M-entry table
 * (edges_found is a finer-grained bucket-bit novelty counter, not a
 * slot-occupancy count -- see its field comment).
 * The birthday-paradox figure (50% chance of *any* collision at
 * ~1.177 * sqrt(N) ~= 3400 PCs) is the first-collision threshold, not
 * a practical saturation point: an isolated collision does not skew
 * the cold-syscall or minicorpus heuristics that read the coverage
 * counters.  What skews them is fractional occupancy -- expected
 * unique slots after k inserts is N * (1 - (1 - 1/N)^k), reaching 50%
 * at k ~= N * ln(2) ~= 5.8M PCs.  Real runs see distinct_edges in the
 * hundreds of thousands without measurable bias.  Modern kernel builds
 * easily exercise hundreds of thousands of distinct edges within
 * seconds. */
#define KCOV_NUM_EDGES (1 << 23)

/* Shadow transition-coverage map.  See the
 * kcov_transition_coverage_mode enum below for the mode contract; this
 * macro sets the slot count.
 *
 * Trinity walks each KCOV trace in order, so hashing consecutive
 * canonical PCs as (prev, cur) pairs turns the trace into AFL-style
 * edge coverage from data the kernel is already producing.  Rewards a
 * class of progress the PC bitmap misses: a syscall that takes a new
 * branch through already-warm basic blocks flips no PC bucket bit and
 * registers as a "warm-known hit" today, even though the control-flow
 * path itself is new.
 *
 * Transition cardinality is strictly higher than PC cardinality: the
 * same shared helper reached through five distinct predecessor blocks
 * produces five transition entries vs one PC entry.  Sized to 16M
 * slots so the fractional-occupancy 50% point lands near 11.6M
 * observed transitions (N * ln(2)), two orders of magnitude above the
 * realistic per-run transition load on the surface Trinity exercises.
 * One byte per slot keeps the cost predictable (16 MB) and leaves the
 * upper seven bits free for a future bucket layer that parallels the
 * PC side's KCOV_NUM_BUCKETS hit-count semantics. */
#define KCOV_NUM_TRANSITIONS (1UL << 24)

/* AFL-style hit-count bucketing.  Each edge stores an 8-bit mask where bit
 * i is set if the edge has ever been hit a count that falls in bucket i:
 *   bucket 0: 1 hit            bucket 4: 8-15 hits
 *   bucket 1: 2 hits           bucket 5: 16-31 hits
 *   bucket 2: 3 hits           bucket 6: 32-127 hits
 *   bucket 3: 4-7 hits         bucket 7: 128+ hits
 * A hit count entering a never-seen bucket for a known edge counts as new
 * coverage — same trigger semantics as a never-seen edge in the old bitmap. */
#define KCOV_NUM_BUCKETS 8

/* Per-child dedup table for counting per-edge hits within a single trace.
 * Open-addressed, linear probing.  Sized so that the typical syscall's
 * unique-edge count fits well below 50% load factor; on probe overflow the
 * caller treats the entry as a single hit (degrades to old behaviour for
 * that edge in that one call).
 *
 * Slot validity is tracked via a generation counter — a slot is "live" only
 * when its generation matches the child's current_generation, otherwise it's
 * stale from a prior call and treated as empty.  Bumping current_generation
 * at the top of kcov_collect() invalidates the entire table in O(1) instead
 * of the per-call wipe the previous sentinel-based design needed. */
#define KCOV_DEDUP_SIZE 16384
#define KCOV_DEDUP_MASK (KCOV_DEDUP_SIZE - 1)
#define KCOV_DEDUP_MAX_PROBE 32

/* If a syscall hasn't found new edges in this many global calls,
 * it's considered "cold" and deprioritized during selection. */
#define KCOV_COLD_THRESHOLD 500000

/* Saturation cap: a stronger, faster-firing companion to the
 * global-gap KCOV_COLD_THRESHOLD path above.  The graduated cold-skip
 * compares last_edge_at[nr] to the GLOBAL total_calls counter, so a
 * syscall whose per-run pick budget is small (~1000 calls/run for a
 * tail-active syscall, like the v7-cache tail of lgetxattr / lchown /
 * vmsplice / prlimit64 / statfs that show 1000-call / 0-edge runs)
 * needs hundreds of fuzz sessions before its cumulative gap pushes
 * past 500000.  In the meantime it keeps burning its per-run quota on
 * known-dead surface.  The saturation cap looks instead at the
 * syscall's OWN cumulative call / edge counters (current run plus
 * warm-loaded priors) and short-circuits to a hard-deprioritise
 * percentage once either branch of the productivity test trips:
 *
 *   - edges_total == 0 && calls_total >= KCOV_SAT_CAP_CALLS:
 *     no edge has ever been observed for this syscall across the
 *     accumulated evidence.  Catches the always-EFAULT / always-
 *     EPERM / strict-validator-reject tail that the cold-skip path
 *     would otherwise wait 500000 global calls to retire.
 *
 *   - edges_total > 0 && calls_total / edges_total >= KCOV_SAT_CAP_RATIO:
 *     productivity has collapsed below one edge per RATIO calls.
 *     Catches trivial getters (getegid / getuid / gettid: 1 edge
 *     after the first call, every subsequent call adds nothing) and
 *     other syscalls whose kernel-side state space is exhausted.
 *
 * SKIP_PCT is a deliberate floor below 100% so a kernel rebuild or
 * runtime-state change (new namespace, new fd type, new sysctl) can
 * re-promote a previously-saturated slot via the 1-in-20 leak. */
#define KCOV_SAT_CAP_CALLS    200U
#define KCOV_SAT_CAP_RATIO    200U
#define KCOV_SAT_CAP_SKIP_PCT 95U

/* Coverage-plateau detector: window length and trigger thresholds.
 * The window is fixed at 600s (10 minutes) so a single below-threshold
 * sample already represents "sustained for ≥ 10 min".  The entry
 * threshold of 10 new edges per 600s window is exactly < 1 new edge
 * per 60s, the point at which manual observation has shown the fuzzer
 * is wedged at a local minimum and not making forward progress.
 *
 * Hysteresis: enter and exit do NOT share a threshold.  A run that
 * re-plateaued after the detector fired showed the rate oscillating
 * around 10 (clear at 10, re-enter at 4) within consecutive windows,
 * flapping plateau_active and so re-arming the intervention layer's
 * entry-only edge-triggered actions every other window.  EXIT is set
 * 3x ENTER so a recovering rate has to cross a separate, higher bar
 * before the detector releases. */
#define KCOV_PLATEAU_WINDOW_SEC 600
#define KCOV_PLATEAU_ENTER_THRESHOLD 10
#define KCOV_PLATEAU_EXIT_THRESHOLD  30

/*
 * Coverage-jump breadcrumb (diagnostic only).
 *
 * A recent run's bucket-edge (distinct_edges) count jumped from 223344
 * to 232965 inside a single ~10k-syscall window, with nothing in the
 * logs naming the triggering syscall / childop sequence.  When the
 * sampled delta over a window of WINDOW_CALLS syscalls exceeds
 * DELTA_THRESHOLD, emit ONE compact one-line breadcrumb to stats.log
 * naming the active strategy / hypothesis, the recent per-child
 * syscalls, the childops that fired most in the window, and the most
 * recent corpus save/replay deltas so the jump becomes attributable.
 *
 * RATE_CAP_CALLS imposes a per-emission floor on the number of total
 * syscall calls that must pass before a second breadcrumb may fire, so
 * a sustained burst over many adjacent windows produces one line, not
 * one-per-window spam.  No runtime behaviour reads the breadcrumb
 * fields -- this is pure observability fed back into the next
 * validation run.
 */
#define KCOV_COVJUMP_WINDOW_CALLS	10000UL
#define KCOV_COVJUMP_DELTA_THRESHOLD	2000UL
#define KCOV_COVJUMP_RATE_CAP_CALLS	50000UL
#define KCOV_COVJUMP_RECENT_N		4

/* KCOV remote coverage handle construction.
 * KCOV_SUBSYSTEM_COMMON covers softirqs and threaded IRQ handlers. */
#define KCOV_SUBSYSTEM_COMMON	(0x00ULL << 56)

/* Fraction of syscalls that use remote mode instead of per-thread mode.
 * 1 in KCOV_REMOTE_RATIO syscalls will use KCOV_REMOTE_ENABLE.  This is
 * the default rate for syscalls that do most of their kernel work on the
 * calling task: remote sampling is comparatively expensive (extra
 * KCOV_REMOTE_ENABLE/disable round-trip plus a softirq/threaded-IRQ
 * coverage merge) and a 1-in-10 trickle is enough to keep softirq-only
 * edges from going completely cold. */
#define KCOV_REMOTE_RATIO 10

/* Heavier sampling rate for syscalls flagged with KCOV_REMOTE_HEAVY in
 * their per-syscall flags (see include/syscall.h).  These are the calls
 * whose interesting kernel work is scheduled onto kthreads / workqueues
 * / softirqs and is therefore *only* visible through the remote KCOV
 * handle: netlink async delivery, io_uring SQ/IO workers, BPF attach
 * paths, mount workqueues, cgroup migration, namespace setup, etc.  At
 * the default 1-in-10 rate those deferred-work edges are persistently
 * under-sampled and stay cold long after the synchronous syscall
 * surface has saturated, so flagged syscalls bump to 1-in-2.  Cost is
 * ~5x more remote enables on those specific calls, not a fleet-wide
 * regression. */
#define KCOV_REMOTE_RATIO_HEAVY 2

/* Adaptive remote-KCOV mode predicate constants.  The static policy
 * above keys remote_mode purely off the per-syscall KCOV_REMOTE_HEAVY
 * flag, so a HEAVY-flagged syscall whose lifetime remote sampling has
 * never produced an edge still burns the heavier 1-in-2 rate, and an
 * unflagged syscall whose remote samples have outperformed its local
 * samples never gets promoted off the 1-in-10 trickle.  The per-syscall
 * mode-keyed yield counters bumped in kcov_collect() (remote_pc_calls,
 * remote_pc_edge_calls, local_pc_calls, local_pc_edge_calls in
 * struct kcov_shared) carry the evidence; what was missing was a
 * predicate that reads them and a per-child A/B arm that gates the
 * live mode flip on that read.
 *
 * MIN_REMOTE_CALLS / MIN_LOCAL_CALLS are the sample-size floors before
 * either disposition fires -- a HEAVY syscall whose first dozen remote
 * samples happen not to land on an edge must not be demoted off the
 * heavy rate, and an unflagged syscall whose ten local samples happen
 * to be zero-edge while one remote sample was productive must not be
 * promoted off the default trickle.  512 matches the order of
 * magnitude FRONTIER_ERRNO_PLATEAU_MIN_CALLS uses for the analogous
 * predicate-discipline gate on the picker side.
 *
 * PROMOTE_MARGIN_NUM / PROMOTE_MARGIN_DEN encode the relative-margin
 * the promote rule requires beyond strict inequality.  The naive
 * remote_edge_calls/remote_calls > local_edge_calls/local_calls would
 * flip on any tie-break noise; requiring the remote edge rate to beat
 * the local edge rate by at least PROMOTE_MARGIN_NUM/PROMOTE_MARGIN_DEN
 * (5/4 == +25%) keeps the predicate quiet on rate ratios that are
 * inside sampling noise.  The comparison is performed via cross-
 * multiplication so neither rate has to be divided; both products are
 * checked with __builtin_mul_overflow so a long run with very large
 * counters cannot silently wrap into a false promote. */
#define REMOTE_ADAPTIVE_MIN_REMOTE_CALLS	512UL
#define REMOTE_ADAPTIVE_MIN_LOCAL_CALLS		512UL
#define REMOTE_ADAPTIVE_PROMOTE_MARGIN_NUM	5UL
#define REMOTE_ADAPTIVE_PROMOTE_MARGIN_DEN	4UL

/* Sample-size floor for the stats render that highlights syscalls
 * whose remote-mode enable was attempted enough times to be
 * statistically meaningful but produced zero remote edges.  The
 * remote_pc_calls counter the yield blocks already render counts
 * only SUCCESSFUL KCOV_REMOTE_ENABLE round-trips, so a syscall
 * whose enable failed often reads there as low-remote-traffic and
 * falls below any rem_calls threshold the wasted view might use;
 * the wasted-remote view therefore gates on remote_enable_requested
 * (bumped before the ioctl outcome is known) so the verdict is
 * indifferent to fallback rate.  512 matches
 * REMOTE_ADAPTIVE_MIN_REMOTE_CALLS so the stats view and the (later)
 * demote rule share a single "sampled enough to act on" floor. */
#define REMOTE_WASTE_FLOOR			512UL

/* Plateau-aware widening of the promote disposition.  When the
 * parent-published plateau hypothesis is PLATEAU_HYPOTHESIS_REMOTE_
 * DOMINANT the fleet is already discovering most of its forward edges
 * via remote sampling (rule PHC_REMOTE_DOMINANT in strategy.c demands
 * delta.remote_calls > 2 * inline_calls with a floor of 100), so an
 * unflagged syscall that has demonstrated ANY remote yield is worth
 * keeping in the remote sampling pool even when its remote edge rate
 * has not (yet) beaten its local edge rate by the
 * PROMOTE_MARGIN_NUM/DEN relative margin the non-plateau promote rule
 * requires.  The plateau-force disposition fires on the non-HEAVY +
 * static_remote==false path AFTER the regular promote check has run
 * and produced no flip; if it fires it sets adaptive_remote to true
 * unconditionally on Arm B (Arm A still ignores the disposition and
 * keeps the static decision, matching the existing arm contract).
 *
 * MIN_REMOTE_CALLS is the per-syscall sample-size floor before the
 * plateau-force can fire.  Lower than REMOTE_ADAPTIVE_MIN_REMOTE_CALLS
 * (512) because a remote-dominant plateau is the operator's signal
 * that forward progress is coming from remote sampling and the normal
 * MIN floor is too patient to widen promote at plateau speed; a
 * single under-justified force costs one extra KCOV_REMOTE_ENABLE/
 * disable round-trip per call (the same cost a HEAVY-flagged syscall
 * pays unconditionally), so the downside of acting on weaker evidence
 * is bounded.  128 lands roughly halfway between "single-digit
 * samples is noise" and "the conservative MIN bar".
 *
 * MIN_EDGES is the minimum lifetime remote_pc_edge_calls bumps for
 * the syscall to qualify as a "proven yielder" under plateau-force.
 * 1 is the smallest signal-bearing value -- the syscall has at least
 * once produced an edge under remote sampling.  A higher floor would
 * gate plateau-force on a stronger "yields more than luck" signal at
 * the cost of waiting longer to act on a marginal yielder during the
 * plateau emergency.  MIN_REMOTE_CALLS above already gates "the
 * syscall has been sampled enough to mean anything"; this second
 * floor's only job is to distinguish "ever yielded" from "sampled
 * enough but never yielded".
 *
 * Demote branch is intentionally NOT widened by the plateau: a HEAVY-
 * flagged syscall whose lifetime remote sample has crossed
 * REMOTE_ADAPTIVE_MIN_REMOTE_CALLS without producing a single edge
 * has empirical evidence that remote sampling on this specific call
 * is wasted regardless of the fleet-wide plateau classification, and
 * relaxing the demote rule under plateau would re-introduce the
 * 1-in-2 cost the demote disposition exists to recover. */
#define REMOTE_ADAPTIVE_PLATEAU_FORCE_MIN_REMOTE_CALLS	128UL
#define REMOTE_ADAPTIVE_PLATEAU_FORCE_MIN_EDGES		1UL

#define CHILDOP_KCOV_NR_BASE  0x10000UL
/*
 * Childops borrow the kcov_collect() nr parameter to bypass
 * the per_syscall_*[] arrays (gated on nr < MAX_NR_SYSCALL
 * in kcov.c).  Reserve the >= 0x10000 range so syscall ids
 * never collide.
 */

/* Compile-time upper bound on NR_CHILD_OP_TYPES, used to size the
 * per-childop arrays inside struct kcov_shared.  kcov.h cannot
 * include child.h (child.h includes kcov.h for struct kcov_child),
 * so the real enum count is asserted to fit inside this bound from
 * kcov.c at build time -- bump KCOV_CHILDOP_NR_MAX (and accept the
 * shm cost) if the assertion ever fires. */
#define KCOV_CHILDOP_NR_MAX 160

/* EINTR retry budget for KCOV_ENABLE / KCOV_REMOTE_ENABLE.  Eight is
 * generous enough to ride out a signal storm without turning a real
 * driver issue into a stall. */
#define KCOV_ENABLE_EINTR_MAX 8

/* Per-slot cap on how many times kcov_recover_fd() may rebuild a
 * vanished kcov fd before kcov_enable_trace gives up and _exit()s
 * the child so the parent's reaper respawns it with a fresh slot.
 * The closer driving these EBADFs is not transient — fleet evidence
 * shows the first hit on a child usually arrives within seconds and
 * recovery cost is essentially init cost (open + INIT_TRACE + mmap +
 * F_DUPFD_CLOEXEC), so a low cap keeps blast radius bounded without
 * leaving recoverable slots silently degraded.  Counters are uint8_t
 * 4-bit bitfields and KCOV_RECOVERY_MAX must stay <= 15. */
#define KCOV_RECOVERY_MAX 3

/* Exit status used by kcov_enable_trace / kcov_enable_remote when the
 * per-slot recovery budget is exhausted (or kcov_recover_fd() itself
 * fails) and the child has to bail so the reaper can hand it a fresh
 * init_child slot.  Must be non-zero so reap_entry_is_fast_die() in
 * main/loop.c treats the reap as a fast-die candidate — a fork→exit(0)→
 * respawn loop would otherwise slip past the circuit breaker, because
 * the breaker only counts exit_status > 0.  Must also be >=
 * NUM_EXIT_REASONS so decode_exit() in bail_fast_die_loop() does not
 * mislabel the ring-dump line as one of the named fleet-terminator
 * reasons (the [1, NUM_EXIT_REASONS) range belongs to enum
 * exit_reasons).  NUM_EXIT_REASONS + 1 satisfies both and stays
 * distinct even if enum exit_reasons grows. */
#define KCOV_RECOVERY_EXHAUSTED_EXIT_CODE (NUM_EXIT_REASONS + 1)

#ifdef CONFIG_GUARD_SHARED
/*
 * Distinct exit code for the kcov_enable_trace() on-fault diagnostic:
 * the trace_buf[0]=0 reset raised SEGV_ACCERR/SIGBUS, the recovery
 * jmp_buf fired, the full diagnostic was dumped, and we _exit() with
 * this code so the reap statistics distinguish a protection-strip
 * fault from a clean exit or a recovery-budget exhaustion bail.
 * Same selection rationale as KCOV_RECOVERY_EXHAUSTED_EXIT_CODE: non-
 * zero so reap_entry_is_fast_die() sees it, and outside the named-
 * exit-reason range so decode_exit() does not mislabel it.
 */
#define KCOV_PROT_FAULT_EXIT_CODE (NUM_EXIT_REASONS + 2)
#endif

/* RedQueen attribution arg-slot histogram width.  Syscalls have at most
 * 6 args (a1..a6), so the histogram has 6 entries indexed by
 * (slot - 1).  Pinned here so the kcov_shared field, the bump sites,
 * and the periodic dump renderer agree on the bound. */
#define CMP_REDQUEEN_SLOT_HIST_NR 6

/* Width of reexec_pending_pick_success[] below.  Mirrors
 * MAX_REEXEC_PENDING (defined in include/cmp_hints.h) -- the
 * per-call reexec_pending[] census is at most that many entries,
 * so the success-by-pick-index counter has the same bound.  Pinned
 * here as a separate define so kcov.h stays self-contained (no
 * dependency on cmp_hints.h); a _Static_assert in random_syscall/dispatch.c
 * (which includes both headers) catches any drift between the two. */
#define REEXEC_PENDING_PICK_HIST_NR 8U
