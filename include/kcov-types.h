#pragma once

/* KCOV constants, enum modes, and non-shared child/diagnostic structs.
 * Split out of include/kcov.h.  Do not add fields to struct kcov_shared
 * here -- that lives in kcov-shared.h. */

#include <time.h>

#include "exit.h"	/* NUM_EXIT_REASONS */
#include "prop_ring.h"	/* enum scalar_kind, SCALAR_NR_KINDS */
#include "types.h"
#include "syscall.h"	/* MAX_NR_SYSCALL */
#include "cmp_hints.h"	/* CMP_HYP_STATE_NR */

#include "kernel/fcntl.h"
/* 8-bucket errno classification used by per_syscall_errno[] below.
 * Bucket layout is part of the dump_stats() output contract; keep
 * the order stable so the column headers in stats.c match. */
enum errno_bucket {
	ERRNO_BUCKET_SUCCESS = 0,	/* rec->retval != -1UL */
	ERRNO_BUCKET_EFAULT  = 1,
	ERRNO_BUCKET_EINVAL  = 2,
	ERRNO_BUCKET_ENOSYS  = 3,
	ERRNO_BUCKET_EPERM   = 4,
	ERRNO_BUCKET_EBADF   = 5,
	ERRNO_BUCKET_EAGAIN  = 6,
	ERRNO_BUCKET_OTHER   = 7,
	ERRNO_BUCKET_NR      = 8,
};

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

/* Shadow transition-coverage mode (--kcov-transition-coverage).
 *
 *   OFF    - skip the transition hash inside kcov_collect.  The map
 *            and counters stay zero; nothing else in Trinity reads
 *            them today, so this is purely a "don't pay the per-PC
 *            cost" knob.
 *   SHADOW - default.  Hash consecutive canonical PCs into the
 *            transition map and bump the transition_* counters in
 *            parallel with the existing PC bitmap update.  Stats dump
 *            surfaces the top transition-yielding syscalls alongside
 *            the existing PC top-N so the two signals can be compared
 *            side-by-side; transition deltas do NOT feed
 *            bandit_record_pull(), frontier_record_new_edge(), the
 *            plateau detector, or any other steering consumer yet.
 *            Promotion to a reward source is gated on the shadow
 *            signal proving out first. */
enum kcov_transition_coverage_mode {
	KCOV_TRANSITION_COVERAGE_OFF = 0,
	KCOV_TRANSITION_COVERAGE_SHADOW = 1,
};

extern enum kcov_transition_coverage_mode kcov_transition_coverage_mode;

/* Transition-edge reward mode (--kcov-transition-reward).  Promotes the
 * shadow transition-coverage signal (see kcov_transition_coverage_mode
 * above) from observability-only into an active reward input for the
 * scheduler.  The coverage mode must be SHADOW for any of the reward
 * modes below to do work; if coverage is OFF the per-syscall transition
 * counters never bump and every reward path below sees a zero delta.
 *
 *   OFF          - skip the reward path entirely.  Per-strategy
 *                  transition attribution counters stay zero, the
 *                  frontier-cold-weight blend drops back to its
 *                  pre-transition formula (PC-edge + bucket-bits +
 *                  distinct-PCs only), and bandit_record_pull adds no
 *                  transition term.
 *   SHADOW_ONLY  - compute the transition-reward terms and bump the
 *                  per-strategy attribution counters in shm->stats so
 *                  the operator can read the divergence, but DO NOT
 *                  change live picker behaviour: frontier_cold_weight()
 *                  returns the pre-transition weight, bandit_record_
 *                  pull() drops the transition term from the reward
 *                  total, and the frontier-edge ring is bumped only by
 *                  the PC-edge hook.  Selecting this mode leaves
 *                  selection byte-identical to the pre-knob baseline;
 *                  kept as a rollback path now that COMBINED is the
 *                  default.
 *   COMBINED     - default.  Feed the capped transition reward into
 *                  live selection: frontier_cold_weight() returns the
 *                  transition-blended weight, bandit_record_pull()
 *                  folds the transition window delta into the per-arm
 *                  reward total, and the transition-discovery hook
 *                  bumps the frontier-edge ring alongside the PC-edge
 *                  hook so syscalls that produce only transitions
 *                  (no fresh PC bits) still earn frontier credit.
 *
 * Remote-mode constraint: remote-mode kcov traces merge coverage
 * copied from remote contexts into the same buffer; the ordering of
 * the merged PCs is not verified to preserve transition adjacency, so
 * a remote-mode transition record carries a weaker signal than a
 * local-mode one.  Even under COMBINED, remote-mode calls do NOT bump
 * any of the live-reward inputs (the per-syscall _real_local counter,
 * the per-strategy attribution counters, or the transition-discovery
 * frontier hook) so the live reward sees local-mode transitions only.
 * The existing per_syscall_transition_edges[_real] counters keep
 * including remote contributions for the unchanged stats-dump top-N.
 */
enum kcov_transition_reward_mode {
	KCOV_TRANSITION_REWARD_OFF = 0,
	KCOV_TRANSITION_REWARD_SHADOW_ONLY = 1,
	KCOV_TRANSITION_REWARD_COMBINED = 2,
};

extern enum kcov_transition_reward_mode kcov_transition_reward_mode;

/* --expensive-adaptive: adaptive accept-rate mode for the EXPENSIVE
 * early-out gate in random-syscall.c.
 *
 * The static gate is `syscall_is_expensive(nr, do32) && !ONE_IN(1000)`:
 * EXPENSIVE-flagged syscalls take a fixed 999/1000 reject, so fleet
 * wall-cost stays bounded but the gate cannot scale the rate based on
 * what the syscall is producing.  This mode flag selects how the
 * per-syscall productivity signal (per_syscall_edges /
 * per_syscall_calls, plus the warm-loaded _prior arrays and a
 * total_calls -- last_edge_at gap decay re-using the kcov_syscall_cold_
 * skip_pct shape) influences the live accept denominator.
 *
 *   OFF          - default.  Byte-identical to the static expression:
 *                  no kcov_shm reads, no adaptive math, the single
 *                  ONE_IN(1000) RNG draw fires in the same conditions
 *                  as the original `&&` short-circuit -- the pick
 *                  stream is preserved bit-for-bit for a given seed.
 *   SHADOW_ONLY  - compute the adaptive denominator (cost path active)
 *                  but the LIVE accept still draws ONE_IN(1000); pick
 *                  stream stays identical to OFF.  Placeholder for the
 *                  follow-up row that adds shadow A/B counters.
 *   COMBINED     - the adaptive denominator drives the live accept
 *                  (ONE_IN(n_adaptive)).  Only mode that diverges from
 *                  OFF.  The decay back toward the floor when a
 *                  syscall stops producing edges is load-bearing: the
 *                  floor caps wall-cost, so an adaptive grant MUST
 *                  decay once productivity stops.
 *
 * Degrade-safe: helper falls back to the static 1/1000 rate when
 * kcov_shm is unavailable, same fallback shape kcov_syscall_cold_skip_
 * pct / frontier_cold_weight already take. */
enum expensive_adaptive_mode {
	EXPENSIVE_ADAPTIVE_MODE_OFF = 0,
	EXPENSIVE_ADAPTIVE_MODE_SHADOW_ONLY = 1,
	EXPENSIVE_ADAPTIVE_MODE_COMBINED = 2,
};

extern enum expensive_adaptive_mode expensive_adaptive_mode;

/* Per-window transition delta divided by this reciprocal before being
 * folded into the bandit's per-arm reward total in bandit_record_pull
 * under COMBINED mode.  Matches the shape (and starting value) of
 * CMP_BANDIT_REWARD_WEIGHT_RECIPROCAL: a 0.25 secondary weight against
 * the PC-edge-call primary signal.  Tunable once the COMBINED arm has
 * soaked enough A/B data to bias the choice. */
#define TRANSITION_BANDIT_REWARD_WEIGHT_RECIPROCAL 4

/* Per-call clamp on how many transition slots a single trace can
 * contribute to the per-strategy reward counters.  A pathological
 * trace that opens a brand-new control-flow region can flip thousands
 * of transition slots in one call; without this clamp such a trace
 * would monopolize the per-strategy delta the bandit reads as reward,
 * letting one window's worth of luck dominate the learner.  The raw
 * per_syscall_transition_edges_real counter stays uncapped (it is the
 * stats-dump observability signal), and the frontier_cold_weight blend
 * uses ilog2() as its per-call clamp -- this constant only gates the
 * per-strategy bandit-reward path. */
#define TRANSITION_PER_CALL_REWARD_CAP 64UL

/* Transition-discovery sibling of frontier_record_new_edge() defined
 * in strategy.c.  Declared here (rather than alongside frontier_
 * record_new_edge in include/strategy.h) because the function exists
 * solely to feed the transition-reward path: its only caller is the
 * COMBINED-mode branch in random-syscall.c, and gating the prototype
 * to the same header that defines kcov_transition_reward_mode keeps
 * "who is allowed to call this" co-located with "what makes calling
 * this meaningful".  See the function body for the contract. */
void frontier_record_transition_edge(unsigned int nr);

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

/* KCOV trace modes */
#define KCOV_TRACE_PC  0
#define KCOV_TRACE_CMP 1

/*
 * Per-child KCOV mode.  The kernel rejects a second KCOV_ENABLE on the
 * same task with -EBUSY (the one-`t->kcov`-per-task rule in kernel/kcov.c),
 * so PC and CMP collection cannot run simultaneously inside a single
 * child.  Each child picks one mode at init and keeps it for its
 * lifetime; the fleet-wide PC/CMP signal split comes from the population
 * mix of children, not from per-call mode toggling.
 */
enum kcov_child_mode {
	KCOV_MODE_PC = 0,
	KCOV_MODE_CMP,
};

/*
 * Reciprocal probability that a child runs in CMP-only mode.  CMP records
 * feed the constant-comparison hint pool, which helps the fuzzer break
 * plateaus by unblocking comparison-gated kernel branches; PC coverage is
 * the load-bearing signal for everything else (bandit reward attribution,
 * edge-discovery rate, cold-syscall skipping).
 * Biased toward PC mode so the high-frequency signal isn't starved; retune
 * after A/B if cmp_records throughput is the bottleneck.
 */
#define KCOV_CMP_CHILD_RECIPROCAL 4   /* 1-in-4 children run CMP-only */

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

/* Per-call dedup slot — counts how many times a single trace hit a given
 * edge so the hit count can be classified into a bucket.  A slot is "live"
 * for the current call only when generation == kcov_child::current_generation;
 * any other value means the slot is stale from a prior call and should be
 * treated as empty. */
struct kcov_dedup_slot {
	uint32_t edge_idx;
	uint32_t count;
	uint64_t generation;
};

/* On-the-wire layout of a single KCOV_TRACE_CMP record, as the kernel
 * writes it after the count header at trace_buf[0].  type encodes the
 * operand size in its low bits and KCOV_CMP_CONST (1<<0) when one
 * operand was a compile-time constant; arg1/arg2 are the operands;
 * ip is the kernel PC of the comparison. */
struct kcov_cmp_record {
	uint64_t type;
	uint64_t arg1;
	uint64_t arg2;
	uint64_t ip;
};

/* Per-syscall diagnostic counters indexed by [nr][do32].  Mirrors the
 * existing globals (trace_truncated, cmp_trace_truncated,
 * dedup_probe_overflow, dedup_max_probe_seen) but partitions each by
 * syscall slot and arch dimension so post-mortems can pin which (nr,
 * arch) tuple is dominating the global counter.  bucket_bits_real and
 * distinct_pcs are new per-call totals: bucket_bits_real is the count
 * of bucket bits this syscall has ever flipped (kcov_collect()'s
 * edges_this_call summed over all calls); distinct_pcs is the count of
 * distinct edges this syscall has ever touched in a single call summed
 * over all calls (dedup_inc() first-sight events).  All counters are
 * relaxed atomics; max_trace_size uses a CAS-loop-up against the
 * existing dedup_max_probe_seen high-water-mark pattern.  Layout is
 * pinned at 48 bytes per slot — see the _Static_assert below — so the
 * shm cost is predictable: 48 * MAX_NR_SYSCALL * 2 arch dims ≈ 96 KiB. */
struct kcov_per_syscall_diag {
	uint64_t trace_truncated;
	uint64_t cmp_trace_truncated;
	uint64_t dedup_probe_overflow;
	uint64_t bucket_bits_real;
	uint64_t distinct_pcs;
	uint32_t max_trace_size;
	uint32_t pad;
};
_Static_assert(sizeof(struct kcov_per_syscall_diag) == 48,
	"kcov_per_syscall_diag must be 48 bytes; shm budget assumes it");

/* Per-failure-site diagnostic slots for the KCOV_TRACE_CMP setup and
 * runtime paths.  Written from child context (post-dup2-to-/dev/null,
 * so output() to stdout is silently swallowed) but read by the parent
 * via shared memory, which is how the data survives back out.  First
 * failure wins for *_errno (CAS-from-zero); *_count tallies every
 * failure at that site across all children. */
struct kcov_cmp_diag {
	int init_open_errno;
	int init_init_trace_errno;
	int init_mmap_errno;
	int init_enable_errno;
	int init_disable_errno;
	int runtime_enable_errno;
	int runtime_disable_errno;
	unsigned int init_open_count;
	unsigned int init_init_trace_count;
	unsigned int init_mmap_count;
	unsigned int init_enable_count;
	unsigned int init_disable_count;
	unsigned int runtime_enable_count;
	unsigned int runtime_disable_count;
};

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

/* Bound for the chronicle snapshot captured into struct
 * kcov_pc_diag::first_ebadf_chronicle[] at first-EBADF latch time.
 * The owning child's child_syscall_ring is sized at
 * CHILD_SYSCALL_RING_SIZE (16); we copy out a parallel structure
 * here so include/kcov.h does not have to drag in include/child.h
 * (child.h includes kcov.h, so the dependency would cycle).  The
 * cap matches the source ring's size -- a smaller cap would let
 * the closer further back scroll off the snapshot the same way
 * it scrolls off the live ring, defeating the whole point of
 * capturing it at the EBADF crime scene. */
#define KCOV_EBADF_CHRONICLE_MAX 16U
struct kcov_ebadf_chronicle_slot {
	unsigned long a1, a2, a3;	/* post-sanitize args as the kernel saw. */
	unsigned long retval;		/* return value the kernel reported. */
	unsigned int  nr;		/* syscall table index. */
	int           errno_post;	/* errno after return. */
	unsigned char do32bit;		/* selects which table nr indexes. */
	unsigned char valid;		/* false for zero-init slots the producer
					 * had not filled by latch time. */
};

/* Bound for the /proc/self/fd snapshot captured into struct
 * kcov_pc_diag::first_ebadf_proc_fds[].  Sized small enough that the
 * snapshot fits comfortably inside the 256-byte buffer the periodic
 * stats.c and main/loop.c summary callers hand to kcov_pc_diag_format(),
 * even with the rest of the diag line in front of it -- a snapshot of
 * the immediate fd neighbourhood of the protected slot is what the
 * operator needs to root-cause the closer; an exhaustive dump is the
 * unbounded-copy DoS shape this cap prevents.
 * Children that hold more than this number of fds get the snapshot
 * truncated; first_ebadf_proc_fd_count == this define on the wire
 * is the signal that truncation happened. */
#define KCOV_FIRST_EBADF_PROC_FD_MAX 16U

/* Per-failure-site diagnostic slots for the PC and remote KCOV enable/
 * disable paths.  Same shape as struct kcov_cmp_diag: first failure
 * wins for *_errno (CAS-from-zero), *_count tallies every failure at
 * that site across all children. */
struct kcov_pc_diag {
	int pc_enable_errno;
	int pc_disable_errno;
	int remote_enable_errno;
	unsigned int pc_enable_count;
	unsigned int pc_disable_count;
	unsigned int remote_enable_count;
	unsigned int remote_fallback_to_pc;
	unsigned int pc_enable_eintr_retries;
	unsigned int remote_enable_eintr_retries;
	unsigned int remote_fallback_pc_enable_eintr_retries;
	/* First-failure-wins capture of which fuzzed syscall was in
	 * flight (or had just retired) when kcov_enable_trace observed
	 * its first EBADF in this run.  CAS-from-zero on
	 * first_ebadf_op_nr selects the winner so the four fields below
	 * are consistent w.r.t. each other.  Used to pin down the
	 * close-race source: the syscall_nr field should resolve via
	 * the syscall table to close / close_range if the chain-
	 * substitution hypothesis holds; anything else points at an
	 * unaudited closer.  fd_value preserves the slot number at
	 * failure for cross-reference with KCOV_FD_HIGH_BASE. */
	unsigned long first_ebadf_op_nr;	/* CAS-elected winner, 0 == empty */
	unsigned long first_ebadf_pid;
	unsigned int  first_ebadf_syscall_nr;
	int           first_ebadf_fd_value;
	/* Richer context for the first-EBADF capture above.  All five
	 * fields below are written by the CAS winner after the four
	 * fields above land, so they share the same one-shot gate and
	 * stay consistent w.r.t. the winning child.  Readers must still
	 * gate on first_ebadf_valid (ACQUIRE) before consulting these.
	 *
	 *   generation              -- kcov_child::current_generation at
	 *                              latch time, so a winner's slot
	 *                              ties the snapshot to a per-child
	 *                              kcov-collect epoch.
	 *   last_fd_mut_syscall_nr  -- most recent close / dup / dup2 /
	 *                              dup3 / close_range / fcntl(F_DUPFD*)
	 *                              found in this child's
	 *                              child_syscall_ring; 0 if the ring
	 *                              held none.  Broad fd-mutator set
	 *                              (allocators included), retained for
	 *                              backward log compatibility -- prefer
	 *                              last_closer_syscall_nr below for
	 *                              EBADF root-cause work.
	 *   protected_touched       -- 1 if the captured fd-mut syscall
	 *                              targeted a protected fd (kcov PC /
	 *                              cmp fd, stderr, the stderr capture
	 *                              memfd).  0 means the closer was
	 *                              the unaudited path the registry
	 *                              cannot see.
	 *   last_closer_syscall_nr  -- most recent close / close_range /
	 *                              dup2 / dup3 found in this child's
	 *                              child_syscall_ring; 0 if the ring
	 *                              held none.  Strictly fd CLOSERS
	 *                              (dup and fcntl F_DUPFD* are fd
	 *                              ALLOCATORS and are excluded -- they
	 *                              never close kc->fd, but they can
	 *                              mask a real closer further back in
	 *                              the ring when last_fd_mut_syscall_nr
	 *                              walks the broad set).  Compare to
	 *                              last_fd_mut_syscall_nr: if they
	 *                              differ, a benign allocator was
	 *                              masking the real closer.
	 *   closer_protected_touched -- 1 if the captured closer's args
	 *                              targeted a protected fd via the
	 *                              fd_is_protected / lowest_protected_-
	 *                              fd_in_range registry (close: a1;
	 *                              close_range: [a1, a2]; dup2/dup3:
	 *                              a1 || a2).  0 means the captured
	 *                              closer did not name kc->fd at all
	 *                              -- either it was a benign close on
	 *                              an unrelated slot or the real
	 *                              closer scrolled off the 16-slot
	 *                              ring.
	 *   proc_fd_count           -- entries populated in proc_fds[].
	 *                              Capped at KCOV_FIRST_EBADF_PROC_FD_MAX
	 *                              so a fleet running with thousands
	 *                              of fds cannot blow the diag-line
	 *                              budget.
	 *   proc_fds[]              -- numeric /proc/self/fd snapshot of
	 *                              the winning child, truncated to
	 *                              proc_fd_count entries.
	 */
	uint64_t      first_ebadf_generation;
	unsigned int  first_ebadf_last_fd_mut_syscall_nr;
	unsigned char first_ebadf_protected_touched;
	unsigned char first_ebadf_proc_fd_count;
	/* Release/acquire beacon paired with the CAS on first_ebadf_op_nr
	 * above.  The CAS elects the winner but does NOT order the payload
	 * stores that follow it, so a naive reader that only checks
	 * first_ebadf_op_nr can observe the winner mark with the payload
	 * fields still stale.  The winner therefore performs every payload
	 * store above with RELAXED ordering and finally publishes
	 * first_ebadf_valid = 1 with __ATOMIC_RELEASE.  Payload consumers
	 * (kcov_diag_record / kcov_first_ebadf_trap_drain) must gate on an
	 * __ATOMIC_ACQUIRE load of this field before reading any payload
	 * field.  Slotted here (next to proc_fd_count) so the byte lands
	 * inside the existing 4-align padding before first_ebadf_proc_fds[]
	 * -- keeps sizeof(struct kcov_pc_diag) unchanged and preserves the
	 * shm-layout _Static_asserts in include/kcov-shared.h.  Mirrors the
	 * breadcrumb_ring.c and include/bug_backtrace.h valid-flag idiom. */
	unsigned char first_ebadf_valid;
	int           first_ebadf_proc_fds[KCOV_FIRST_EBADF_PROC_FD_MAX];
	unsigned int  first_ebadf_last_closer_syscall_nr;
	unsigned char first_ebadf_closer_protected_touched;
	/* Tally of sanitise_close_range() truncations: bumped each time
	 * the lowest_protected_fd_in_range() guard fires and rewrites
	 * rec->a2 to keep the kernel-side range below a protected fd
	 * (kcov PC/cmp, stderr, the stderr capture memfd).  Gives the
	 * /prot=absent diag-line readings a denominator -- if the
	 * counter is non-zero we know the guard is actively firing
	 * (close_range picker really did target a protected fd; the
	 * sanitizer caught it).  If first_ebadf=...:closer=nr<close_range>
	 * is rare AND this counter is non-zero, the guard is doing its
	 * job and close_range is exonerated as the EBADF source. */
	unsigned long close_range_protect_truncate_count;

	/* First-EBADF trap: full per-child diagnostic snapshot taken in
	 * kcov_latch_first_ebadf() so the operator can name the real
	 * closer even when it scrolled off the 16-slot child_syscall_-
	 * ring summarized by first_ebadf_last_closer_syscall_nr above.
	 * All four fields share the same one-shot CAS gate
	 * (first_ebadf_op_nr) as the existing latch fields -- readers
	 * must gate on first_ebadf_valid (ACQUIRE) before consulting
	 * these so the payload writes are visible.
	 *
	 *   recovery_attempts        -- kcov_child::recovery_attempts at
	 *                               latch time (capped at
	 *                               KCOV_RECOVERY_MAX == 3).  Non-
	 *                               zero means at least one prior
	 *                               kcov_recover_fd() succeeded for
	 *                               this child, so the EBADF being
	 *                               latched is on a REBUILT fd, not
	 *                               the original from kcov_init_-
	 *                               child.  Directly addresses the
	 *                               "kcov_recover_fd race" suspect:
	 *                               zero exonerates it.
	 *   cmp_recovery_attempts    -- companion counter for the cmp fd.
	 *   chronicle_count          -- number of valid slots actually
	 *                               populated in the snapshot below
	 *                               (the producer-side ring may have
	 *                               fewer than KCOV_EBADF_CHRONICLE_MAX
	 *                               valid slots if the child hadn't
	 *                               finished its first 16 syscalls).
	 *   chronicle[]              -- snapshot of the EBADF-observing
	 *                               child's syscall_ring at latch
	 *                               time, captured newest-first
	 *                               (chronicle[0] is the most recent
	 *                               retired syscall).  Lets a parent-
	 *                               side dumper emit the full trail
	 *                               so the operator can see the real
	 *                               closer even when the broad/
	 *                               closer walkers were defeated by
	 *                               ring scroll.
	 */
	unsigned char first_ebadf_recovery_attempts;
	unsigned char first_ebadf_cmp_recovery_attempts;
	unsigned char first_ebadf_chronicle_count;
	struct kcov_ebadf_chronicle_slot
		first_ebadf_chronicle[KCOV_EBADF_CHRONICLE_MAX];
};

/* Selector for kcov_cmp_diag_format() — keeps stats.c's two-line split
 * (init vs runtime sites) while still allowing main/loop.c to fold all six
 * sites into a single one-line summary. */
enum kcov_cmp_diag_part {
	KCOV_CMP_DIAG_INIT,	/* init_open, init_init_trace, init_mmap */
	KCOV_CMP_DIAG_RUNTIME,	/* init_enable, init_disable, runtime_enable */
	KCOV_CMP_DIAG_ALL,
};

/* Build a " name=<errno>/<count>" segment per non-zero cmp_diag site
 * into buf.  Each segment starts with a single space so the caller
 * concatenates straight into a log line.  Returns the number of bytes
 * written (excluding the trailing NUL); zero if no site has any
 * recorded failures, or if kcov_shm is NULL. */
int kcov_cmp_diag_format(char *buf, size_t bufsz, enum kcov_cmp_diag_part part);

/* Build a one-line summary of the PC/remote enable/disable
 * diagnostic counters defined in struct kcov_pc_diag.  Each
 * non-zero error site contributes a `" name=ERRNO_MACRO(errno)/count"`
 * token; each non-zero retry/success counter contributes a
 * `" name=count"` token; absent counters contribute nothing.
 * Same shape as kcov_cmp_diag_format so the two callsites in
 * stats.c periodic dump and main/loop.c summary stay in lockstep.
 * Returns the number of bytes written (excluding the trailing
 * NUL); zero if every counter is zero or kcov_shm is NULL. */
int kcov_pc_diag_format(char *buf, size_t bufsz);

/* Drain the first-EBADF trap dump (recovery counters + full
 * chronicle snapshot) once, the first time the caller observes a
 * non-zero first_ebadf_op_nr.  Returns true and emits one or more
 * output(0, ...) lines if a fresh trap is available, false if the
 * trap is empty or has already been drained in this process.
 * Parent-only call site: stats / main-stats periodic loop.  The
 * one-shot guard is process-local (a static bool inside the helper)
 * so a child that observed first_ebadf cannot accidentally fire the
 * dump from its routed-to-/dev/null output(); only the parent's
 * print loop ever sees the trap surface in the operator log. */
bool kcov_first_ebadf_trap_drain(void);

struct kcov_child {
	/* Field order is constrained by the hot-cacheline budget in struct
	 * childdata (see static_assert in child.c).  Sized to 48 bytes:
	 * 2 ints (8) + 1 u64 (8) + 6 bools + 1 uint8_t mode (7) + 1 byte
	 * holding the two 4-bit recovery counters + 3 pointers (24).  The
	 * mode byte and the packed recovery counters slot into the bool
	 * block so the struct stays at 48 bytes without disturbing pointer
	 * alignment.  That leaves room in the 64-byte hot leading cacheline
	 * for the childdata fields that follow (last_group, op_nr).
	 * child_id is intentionally not stored here —
	 * kcov_enable_remote() takes it as a parameter (sourced from
	 * childdata->num) so the second fd's metadata fits without
	 * overflowing the cacheline. */
	int fd;
	int cmp_fd;                     /* second fd for KCOV_TRACE_CMP, -1 if unavailable */
	uint64_t current_generation;	/* bumped per kcov_collect() to invalidate dedup */
	bool active;       /* true if this child successfully opened kcov */
	bool cmp_capable;  /* true if cmp_fd was probed and KCOV_TRACE_CMP works */
	bool cmp_enabled_this_call;	/* true between kcov_enable_cmp() and kcov_disable() */
	bool remote_mode;  /* true when using KCOV_REMOTE_ENABLE */
	bool remote_capable; /* true if kernel supports KCOV_REMOTE_ENABLE */
	bool bracket_owned;	/* true between kcov_bracket_begin() and
				 * kcov_bracket_end().  Keeps the bracket
				 * helpers idempotent under nesting: a childop
				 * that recurses into random_syscall() must
				 * not have its inner enable_trace clobbered
				 * by the outer bracket. */
	/* Logically enum kcov_child_mode; stored as uint8_t so the field
	 * lives inside the existing pad bytes after the bool block instead
	 * of forcing an int-sized hole that would push the pointer triplet
	 * out past 48 bytes and break the hot-cacheline budget. */
	uint8_t mode;
	/* Per-slot recovery attempt counters for kcov_recover_fd().  Two
	 * 4-bit fields share the single byte of padding that used to sit
	 * after `mode`, keeping the struct at 48 bytes (a third uint8_t
	 * would force pointer-alignment padding and push the struct to
	 * 56, blowing the hot-cacheline budget).  Each counter caps at
	 * KCOV_RECOVERY_MAX (3) before kcov_enable_trace _exit()s the
	 * child with KCOV_RECOVERY_EXHAUSTED_EXIT_CODE; the counter is
	 * owner-write-only so the bitfield RMW is always sequential
	 * within a single child context. */
	uint8_t recovery_attempts     : 4;
	uint8_t cmp_recovery_attempts : 4;
	unsigned long *trace_buf;
	unsigned long *cmp_trace_buf;	/* mmap of cmp_fd, NULL if unavailable */
	struct kcov_dedup_slot *dedup;	/* KCOV_DEDUP_SIZE entries, child-private */
};

/* Per-child local staging for the kcov global counters
 * (kcov_shared::total_calls / remote_calls / total_pcs).  Bumped on
 * the hot per-syscall path inside the owning child and flushed in
 * batches into the shared atomics via kcov_child_flush_stats() so the
 * shared cacheline stops bouncing on every call.  Lives behind a
 * pointer on struct childdata (NOT inside struct kcov_child, which is
 * pinned to 48 bytes by the static_assert on
 * offsetof(childdata, op_nr) < 64 -- folding scalar counters in would
 * push op_nr out of the leading hot cacheline). */
struct kcov_child_local_stats {
	unsigned long total_calls;
	unsigned long remote_calls;
	unsigned long total_pcs;
	unsigned long total_warm_known_hits;
	/* Running count of syscalls since the last local-stats flush.
	 * Drives the flush-cadence heuristic in kcov_child_flush_stats()
	 * (flush when >= KCOV_LOCAL_STATS_FLUSH_SYSCALLS); bumped
	 * alongside total_calls and cleared on flush. */
	unsigned int local_syscalls_since_flush;
};

/* observability: the two generate-args.c callsites that pull a value via
 * prop_ring_try_get() are partitioned into fixed buckets so the
 * per-callsite propagation-injection split is visible alongside the flat
 * propagation_injected scalar.  Ordering is pinned (the slot index is the
 * bucket id) -- append-only.  Distinct from enum cmp_hint_callsite (in
 * cmp_hints.h): that one buckets cmp_hints_try_get() consumers (kernel
 * KCOV_TRACE_CMP value source), this one buckets prop_ring_try_get()
 * consumers (trinity-observed syscall-return value source). */
enum prop_injected_callsite {
	PROP_INJECTED_CALLSITE_ARG_OP = 0,
	PROP_INJECTED_CALLSITE_ARG_UNDEFINED,
	PROP_INJECTED_CALLSITE_NR,
};

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
 * dependency on cmp_hints.h); a _Static_assert in random-syscall.c
 * (which includes both headers) catches any drift between the two. */
#define REEXEC_PENDING_PICK_HIST_NR 8U

/* Probe-class buckets for the cmp_hyp_probe_class_hist[] census at the
 * tail of struct kcov_shared.  Every entry above the SHADOW block below
 * corresponds one-for-one with a branch cmp_hyp_derive_value() ACTUALLY
 * emits a value through today; keep those in lock-step with the switch.
 * The set deliberately excludes the false-return rejects (hi < lo,
 * default kind) which emit no value.  The BOUNDARY_* classes are the
 * neighbourhood ladder the CMP_HYP_BOUNDARY arm walks -- inequality-
 * gate-friendly probes RANGE deliberately refuses to emit because the
 * value-keyed credit walk can only reach interior members.
 *
 * SHADOW-only classes are appended at the tail below _SINGLE_BIT's
 * live siblings.  They are reserved as dedicated bucket ids so a
 * future live promotion of a shadow-measured lane can flip on without
 * shifting the histogram indices consumers already read; today they
 * are never assigned to `cls` inside the derive switch, so their
 * cmp_hyp_probe_class_hist[] slots stay at zero and the dedicated
 * shadow counters at the tail of struct kcov_shared carry the
 * would-fire / would-win signal instead. */
enum cmp_hyp_probe_class {
	CMP_HYP_PROBE_CLASS_EXACT_EXEMPLAR,
	CMP_HYP_PROBE_CLASS_ENUM_EXEMPLAR,
	CMP_HYP_PROBE_CLASS_ENUM_LO,
	CMP_HYP_PROBE_CLASS_ENUM_HI,
	CMP_HYP_PROBE_CLASS_BITMASK_SINGLE_BIT,
	CMP_HYP_PROBE_CLASS_EXEMPLAR_FALLBACK,
	CMP_HYP_PROBE_CLASS_RANGE_LO,
	CMP_HYP_PROBE_CLASS_RANGE_HI,
	CMP_HYP_PROBE_CLASS_RANGE_MIDPOINT,
	CMP_HYP_PROBE_CLASS_BOUNDARY_MINUS1,
	CMP_HYP_PROBE_CLASS_BOUNDARY_PLUS1,
	CMP_HYP_PROBE_CLASS_BOUNDARY_EXACT,
	CMP_HYP_PROBE_CLASS_BOUNDARY_SWEEP,
	/* SHADOW-only bitmask combination classes.  Extend the existing
	 * BITMASK single-bit lane in cmp_hyp_derive_value() with combo
	 * probes: FULL_OR is the OR of all single-bit observations at
	 * (nr, cmp_ip, width) (targets `(flags & A) && (flags & B)`
	 * gates single-bit probing structurally cannot reach);
	 * ANDNOT_TOGGLE flips one disallowed bit at a time within the
	 * complement of the observed-bits set at the same site (targets
	 * `old & ~c` allow-mask checks).  No branch in the derive switch
	 * emits either value today; the dedicated shadow counters below
	 * carry the coverage-headroom signal. */
	CMP_HYP_PROBE_CLASS_BITMASK_FULL_OR,
	CMP_HYP_PROBE_CLASS_BITMASK_ANDNOT_TOGGLE,
	CMP_HYP_PROBE_CLASS_NR,
};

