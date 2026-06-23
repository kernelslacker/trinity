#pragma once

#include <time.h>

#include "exit.h"	/* NUM_EXIT_REASONS */
#include "prop_ring.h"	/* enum scalar_kind, SCALAR_NR_KINDS */
#include "types.h"
#include "syscall.h"	/* MAX_NR_SYSCALL */
#include "cmp_hints.h"	/* CMP_HYP_STATE_NR */

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

/* Size of the per-child KCOV trace buffer (number of unsigned longs).
 * 256K entries is 2MB on 64-bit.  Deep kernel paths (long io_uring
 * chains, deep btrfs ops, multi-level fs walks, large genetlink
 * families) can blow past the previous 64K-entry budget and silently
 * truncate the tail of the trace, dropping uncounted edge coverage
 * on exactly the syscalls the fuzzer would learn the most from. */
#define KCOV_TRACE_SIZE (256 << 10)

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
#define KCOV_SAT_CAP_RATIO    500U
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
#define KCOV_SUBSYSTEM_MASK	(0xffULL << 56)
#define KCOV_INSTANCE_MASK	(0xffffffffULL)

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
#define KCOV_CHILDOP_NR_MAX 128

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
 * main.c treats the reap as a fast-die candidate — a fork→exit(0)→
 * respawn loop would otherwise slip past the circuit breaker, because
 * the breaker only counts exit_status > 0.  Must also be >=
 * NUM_EXIT_REASONS so decode_exit() in bail_fast_die_loop() does not
 * mislabel the ring-dump line as one of the named fleet-terminator
 * reasons (the [1, NUM_EXIT_REASONS) range belongs to enum
 * exit_reasons).  NUM_EXIT_REASONS + 1 satisfies both and stays
 * distinct even if enum exit_reasons grows. */
#define KCOV_RECOVERY_EXHAUSTED_EXIT_CODE (NUM_EXIT_REASONS + 1)

/* Bound for the /proc/self/fd snapshot captured into struct
 * kcov_pc_diag::first_ebadf_proc_fds[].  Sized small enough that the
 * snapshot fits comfortably inside the 256-byte buffer the periodic
 * stats.c and main.c summary callers hand to kcov_pc_diag_format(),
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
	unsigned long first_ebadf_op_nr;	/* CAS gate, 0 == empty */
	unsigned long first_ebadf_pid;
	unsigned int  first_ebadf_syscall_nr;
	int           first_ebadf_fd_value;
	/* Richer context for the first-EBADF capture above.  All five
	 * fields below are written by the CAS winner after the four
	 * fields above land, so they share the same one-shot gate and
	 * stay consistent w.r.t. the winning child.  Readers must still
	 * load first_ebadf_op_nr first and only consult these if it is
	 * non-zero.
	 *
	 *   generation              -- kcov_child::current_generation at
	 *                              latch time, so a winner's slot
	 *                              ties the snapshot to a per-child
	 *                              kcov-collect epoch.
	 *   last_fd_mut_syscall_nr  -- most recent close / dup / dup2 /
	 *                              dup3 / close_range / fcntl(F_DUPFD*)
	 *                              found in this child's
	 *                              child_syscall_ring; 0 if the ring
	 *                              held none.  Names the likely
	 *                              closer when the chain-substitution
	 *                              hypothesis holds.
	 *   protected_touched       -- 1 if the captured fd-mut syscall
	 *                              targeted a protected fd (kcov PC /
	 *                              cmp fd, stderr, the stderr capture
	 *                              memfd).  0 means the closer was
	 *                              the unaudited path the registry
	 *                              cannot see.
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
	int           first_ebadf_proc_fds[KCOV_FIRST_EBADF_PROC_FD_MAX];
};

/* Selector for kcov_cmp_diag_format() — keeps stats.c's two-line split
 * (init vs runtime sites) while still allowing main.c to fold all six
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
 * stats.c periodic dump and main.c summary stay in lockstep.
 * Returns the number of bytes written (excluding the trailing
 * NUL); zero if every counter is zero or kcov_shm is NULL. */
int kcov_pc_diag_format(char *buf, size_t bufsz);

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
	/* Number of syscalls since the last flush.  Drives the
	 * flush-cadence heuristic the future kcov_child_flush_stats()
	 * implementation will use; bumped alongside total_calls and
	 * cleared on flush. */
	unsigned int local_syscalls_since_flush;
};

/* observability: the four generate-args.c callsites
 * that pull a cmp_hint via cmp_hints_try_get() are partitioned into
 * fixed buckets so the per-callsite injection-rate split is visible in
 * the periodic stats dump without a per-argtype array.  Ordering is
 * pinned (the slot index is the bucket id) -- append-only.  STRUCT_FIELD
 * is reserved with no current bumper; the slot exists so the future
 * field-fill path described in struct_catalog.c can land without
 * renumbering. */
enum cmp_hint_callsite {
	CMP_HINT_CALLSITE_ARG_OP = 0,
	CMP_HINT_CALLSITE_ARG_LIST,
	CMP_HINT_CALLSITE_ARG_UNDEFINED,
	CMP_HINT_CALLSITE_ARG_STRUCT_SIZE,
	CMP_HINT_CALLSITE_STRUCT_FIELD,
	CMP_HINT_CALLSITE_OTHER,
	CMP_HINT_CALLSITE_NR,
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
	unsigned long per_syscall_edges[MAX_NR_SYSCALL];
	unsigned long per_syscall_calls[MAX_NR_SYSCALL];
	unsigned long last_edge_at[MAX_NR_SYSCALL];
	/* Snapshot of per_syscall_edges at the previous stats interval.
	 * Used to compute per-interval growth rate of the call-count signal
	 * above. */
	unsigned long per_syscall_edges_previous[MAX_NR_SYSCALL];
	/* Warm-loaded priors from the previous session's bitmap save.
	 * Never bumped during this run -- frozen at warm-start.  Empty
	 * (all-zero) on cold-start or when the priors blob in the bitmap
	 * file failed its CRC check.  Consumers treat these as soft
	 * priors -- current-run evidence in per_syscall_edges[] /
	 * per_syscall_calls[] overrides them as soon as it accumulates. */
	unsigned long per_syscall_edges_prior[MAX_NR_SYSCALL];
	unsigned long per_syscall_calls_prior[MAX_NR_SYSCALL];
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

	/* Per-callsite total cmp-hint injections, indexed by enum
	 * cmp_hint_callsite.  Aggregated across all syscalls; the "which
	 * argtype-handler is responsible for the bulk of injections" question
	 * is callsite-shaped, not syscall-shaped, so the per-nr split lives
	 * in per_syscall_cmp_injected above and this array stays flat.  6
	 * buckets: ARG_OP, ARG_LIST, ARG_UNDEFINED, ARG_STRUCT_SIZE,
	 * STRUCT_FIELD (reserved -- no call site today), OTHER. */
	unsigned long cmp_hint_callsite_injected[CMP_HINT_CALLSITE_NR];

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
	unsigned long reexec_pending_dropped;
	/*
	 * Obsolete wastage counter.  Originally bumped at the gate-pass
	 * site by (reexec_pending_count - 1) under the prior single-drain
	 * rule (consumer drained exactly ONE entry, the rest were
	 * discarded with the per-call scratch reset).  The dispatch_step
	 * tail now drains every staged reexec_pending[] entry per parent
	 * dispatch, so no entries are wasted per gate-pass and the
	 * counter is no longer incremented.  Field kept so the shm
	 * layout and existing stats consumers do not need to regenerate;
	 * current value is always zero in live runs.
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
	 * SHADOW counters for the run-local CMP "recent" pool tier.
	 * The recent ring sits next to the
	 * durable per-syscall pool and absorbs every fresh insert /
	 * evict-replace pool_add_locked() observes -- a small lossy
	 * window over constants the kernel has produced recently that
	 * the saturated durable pool would otherwise drop on the
	 * eviction floor.  The A/B flag (--cmp-recent-pool) gates
	 * whether cmp_hints_try_get_ex() samples the recent ring first
	 * during a CMP_RISING_PC_FLAT plateau; the default keeps the
	 * historical durable-first behaviour, so the recent-ring tier
	 * is behaviour-neutral until the flag is flipped.  Every counter
	 * below is RELAXED + flat per the SHADOW-first discipline:
	 * recording active in BOTH arms so an A/B run reads the same
	 * shadow rates the live arm will eventually consume.
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
	 *      hypothesis is CMP_RISING_PC_FLAT -- i.e. the call where
	 *      the recent-first arm would have sampled from the recent
	 *      ring.  Active in BOTH arms so the would-be-pick rate is
	 *      legible from the default durable-first run.
	 *  cmp_recent_would_miss
	 *      Bumped once per cmp_hints_try_get_ex() call where the
	 *      plateau hypothesis is CMP_RISING_PC_FLAT but the recent
	 *      ring is empty (the recent-first arm would have fallen
	 *      back to the durable pool).  would_pick + would_miss is
	 *      the plateau-window try_get population.
	 *  cmp_recent_live_picks
	 *      Bumped once per cmp_hints_try_get_ex() return that was
	 *      actually served from the recent ring.  Stays at zero
	 *      under the default A/B arm; non-zero once the operator
	 *      flips --cmp-recent-pool=recent-first.
	 *  cmp_recent_promotions
	 *      Bumped from the feedback drain when a recent-ring
	 *      sample converts (PC-edge / CMP-novel / errno-shift) --
	 *      the conversion event that the follow-up commit will
	 *      route into a real recent->durable promotion.  Today
	 *      the recording-only path; no entry is moved.
	 *
	 * Append-only at the tail per the existing convention so
	 * consumer offsets stay stable. */
	unsigned long cmp_recent_inserts;
	unsigned long cmp_recent_evicts;
	unsigned long cmp_recent_would_pick;
	unsigned long cmp_recent_would_miss;
	unsigned long cmp_recent_live_picks;
	unsigned long cmp_recent_promotions;

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
	 *      empty AND uncorrupted -- i.e. the call where the live
	 *      arm would have served a value.  Active in BOTH arms.
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
	 *  cmp_hyp_kind_full       -- per-kind sub-cap exhausted for a kind.
	 *  cmp_hyp_state_transitions[CMP_HYP_STATE_NR]
	 *                          -- bumped on every state edge into the
	 *                             indexed terminal state (OBSERVED ->
	 *                             TESTING / PROMOTED / DEMOTED / RETIRED).
	 *                             Zero until the feedback unit lands.
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
	unsigned long cmp_hyp_state_transitions[CMP_HYP_STATE_NR];
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
	 *      for the same site.  Scalar (no per-kind partition); the
	 *      per-kind drilldown lives in cmp_hyp_would_pick_by_kind.
	 */
	unsigned long cmp_hyp_would_pick_by_kind[CMP_HYP_KIND_NR];
	unsigned long cmp_hyp_would_miss_by_kind[CMP_HYP_KIND_NR];
	unsigned long cmp_hyp_would_value_differs;

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
};

extern struct kcov_shared *kcov_shm;

/* Called once from init_shm() to allocate shared coverage state. */
void kcov_init_global(void);

/* Called per-child to try to open/mmap the kcov fd.
 * child_id is a unique per-child identifier used for remote handles.
 * Sets kc->active = true only if kcov is usable. */
void kcov_init_child(struct kcov_child *kc, unsigned int child_id);

/* Called per-child on exit to clean up. */
void kcov_cleanup_child(struct kcov_child *kc);

/* Forward declaration -- kcov.h cannot include child.h (child.h
 * includes kcov.h for struct kcov_child), so the flush stub takes
 * a forward-declared childdata pointer. */
struct childdata;

/* Drain the per-child kcov_child_local_stats counters into the
 * shared kcov_shared atomics.  No-op stub today -- no bumper has been
 * migrated to the staging counters yet, so the flush has nothing to
 * publish. */
void kcov_child_flush_stats(struct childdata *child);

/* Bracket the actual syscall() call with these. No-ops if !active. */
void kcov_enable_trace(struct kcov_child *kc);
void kcov_enable_cmp(struct kcov_child *kc);
void kcov_enable_remote(struct kcov_child *kc, unsigned int child_id);
void kcov_disable(struct kcov_child *kc);

/* Zero the trace count header at trace_buf[0] (or cmp_trace_buf[0]
 * for CMP-mode children) without touching the kcov ioctls.  Use on
 * paths that bypass the normal kcov_enable / syscall / kcov_disable
 * bracket so the next kcov_collect() / kcov_collect_cmp() does not
 * re-read the stale count left by the previous bracketed call and
 * re-account the same PCs / cmp records against the current slot.
 * No-op when KCOV is disabled or the slot is inactive. */
void kcov_reset_trace_header(struct kcov_child *kc);

bool kcov_bracket_begin(struct kcov_child *kc);
unsigned long kcov_bracket_end(struct kcov_child *kc,
				unsigned long op_nr);

/*
 * Per-childop KCOV attribution mode (--childop-kcov-attribution).
 *
 *   OFF  - childop dispatch path is unchanged; nothing is bracketed
 *          and childop_edges_clean[] stays at zero.  Consumers that
 *          read the clean signal (adapt_budget, canary queue) see
 *          zero edges per call in this mode and behave as they would
 *          on a build without KCOV: budget multipliers stay at unity
 *          and canary windows always demote on "zero_edges".  Use
 *          only when the bracket path itself is the suspect.
 *   DUAL - default.  Bracket every eligible childop and publish the
 *          per-call delta to childop_edges_clean[].  The existing
 *          global edges_found before/after delta path keeps writing
 *          childop_edges_discovered[] / childop_calls_with_edges[]
 *          as a diagnostic comparator -- operators can watch the
 *          discovered/clean ratio per op to validate the bracket
 *          coverage before remaining consumers (plateau snapshot)
 *          follow.
 *   ON   - reserved for retiring the discovered diagnostic counter.
 *          Currently identical to DUAL.
 */
enum childop_kcov_attribution_mode {
	CHILDOP_KCOV_ATTR_OFF = 0,
	CHILDOP_KCOV_ATTR_DUAL,
	CHILDOP_KCOV_ATTR_ON,
};

extern enum childop_kcov_attribution_mode childop_kcov_attr_mode;

/* Per-call PC-edge result struct, optionally filled by kcov_collect().
 *
 * The legacy new_edge_count out-param returns bucket_bits only -- the count
 * of (edge, bucket) bit-flips this call drove into kcov_shm->bucket_seen[].
 * That conflates "reached new code" with "flipped a new hit-count bucket on
 * already-warm code".  The result struct splits the signal three ways so
 * consumers can pick the right one without diffing global shm counters
 * (racy under concurrent children) or re-walking the trace:
 *
 *   bucket_bits
 *       Identical to the legacy new_edge_count: number of bucket-mask bit
 *       transitions 0->1 in bucket_seen[] this call.  A re-hit of a known
 *       PC that lands in a never-seen bucket still bumps this.
 *   distinct_edges
 *       True first-sighting count: number of PCs this call drove from
 *       bucket_seen[edge] == 0 (no bucket bit ever set) to non-zero.
 *       Filters out the bucket-churn component of bucket_bits, leaving
 *       only "new code reached" events.  Mirrors at the per-call
 *       granularity what kcov_shm->distinct_edges tracks globally.
 *   local_distinct_pcs
 *       Count of dedup_inc() first-sight events: distinct PCs walked
 *       in this call's trace buffer regardless of whether the global
 *       bitmap had already seen them.  A measure of the trace's own
 *       width independent of cross-run / cross-child history.
 *   transition_edges_real_local
 *       Number of transition slots this call flipped from 0 -> 1,
 *       filtered to the local kcov mode (zero for remote-mode traces
 *       per the kcov_transition_reward_mode contract).  Returned to
 *       the caller so the per-strategy reward attribution path can
 *       bump shm->stats.transition_edge_*_by_strategy[] without
 *       re-walking the trace; the strategy that owns the credit is
 *       only known to the caller via child->strategy_at_pick.  Zero
 *       when kcov_transition_coverage_mode is OFF (no transitions
 *       were counted) or kcov_transition_reward_mode is OFF (reward
 *       path disabled).
 *
 * All four are populated when result is non-NULL; pass NULL when only
 * the legacy bucket-bits signal is wanted.  No extra atomics: the
 * counters fall out of the existing PC walk. */
struct kcov_pc_result {
	unsigned long bucket_bits;
	unsigned long distinct_edges;
	unsigned long local_distinct_pcs;
	unsigned long transition_edges_real_local;
	/* Per-call PC trace length post-cap (count of PCs the kernel wrote
	 * into trace_buf this call, clamped at KCOV_TRACE_SIZE - 1 when the
	 * buffer filled).  Exposed so post-collect bookkeeping can recognise
	 * near-truncation calls -- a syscall whose trace approached the
	 * buffer ceiling executed a meaningful amount of kernel code even
	 * when bucket_bits / distinct_edges came back zero, the "deep but
	 * warm" shape the per_syscall_diag[].max_trace_size high-water mark
	 * tracks across the run.  Same cost discipline as the other fields:
	 * the value is the same `count` the trace_truncated / max_trace_size
	 * accounting above already computed, so populating it costs one
	 * extra store. */
	unsigned long trace_size;
};

/* After disabling, collect PCs and update the global bitmap.
 *
 * Returns true if new coverage was found (i.e. this call set at least one
 * never-seen bucket bit); the returned bool collapses the per-call count
 * to a {0,1} signal that the caller's name-and-shame attribution paths
 * already expect.
 *
 * If new_edge_count is non-NULL it is written with the actual number of
 * bucket bits this call flipped — the real edge-count signal, distinct
 * from the bool return.  Callers needing only the boolean signal pass
 * NULL.  Computed during the same pass that updates kcov_shm->edges_found,
 * so it costs no extra atomics: the caller would otherwise have to read
 * the global counter before/after and diff it, which is racy under
 * concurrent children that also bump the global.
 *
 * If result is non-NULL it is filled with the per-call counts described
 * on struct kcov_pc_result: bucket_bits (same value the new_edge_count
 * out-param would receive), distinct_edges (true first-sighting count,
 * filters bucket-churn out of bucket_bits), and local_distinct_pcs
 * (dedup_inc() first-sight events).  Pass NULL when only the legacy
 * bucket-bits signal is wanted; new_edge_count and result may be used
 * together or independently.
 *
 * nr is the syscall number for per-syscall edge tracking.  do32 is the
 * KCOV mode bit indicating 32-bit-record collection (snapshotted from the
 * child's current syscall record at set_syscall_nr time, matching how
 * kcov_collect_cmp already receives it).  Threaded into dedup_inc() and
 * reserved for per-syscall diagnostic indexing. */
bool kcov_collect(struct kcov_child *kc, unsigned int nr, bool do32,
		  unsigned long *new_edge_count,
		  struct kcov_pc_result *result);

/* After disabling, drain the CMP buffer into the per-syscall hint pool
 * and bump the CMP-records-collected counter.  No-op when cmp_capable
 * is false.  is_explorer is forwarded to bandit_cmp_observe() so the
 * explorer pool's novelty observations skip per-arm reward attribution
 * (they ran a different strategy than the bandit's current arm).
 * strategy_at_pick is the enum strategy_t snapshotted in set_syscall_nr
 * when this syscall was picked (or -1 for explorers / pre-first-pick);
 * forwarded so bandit_cmp_observe attributes CMP novelty to the arm
 * that picked the call rather than re-reading shm->current_strategy
 * (which may have rotated mid-syscall).
 *
 * Returns the count of bloom-novel KCOV_CMP_CONST constants observed
 * on this call (the bandit_cmp_observe return value).  0 means no
 * novelty; any positive value means "this call exercised at least one
 * new compile-time-constant comparison and is a candidate for
 * CMP-source corpus save".  Returns 0 when cmp_capable is false, the
 * buffer is empty, or the kernel only produced non-CONST records. */
unsigned long kcov_collect_cmp(struct kcov_child *kc, unsigned int nr,
			       bool do32, bool is_explorer,
			       int strategy_at_pick);

/*
 * Per-child kcov PC fd and cmp fd are protected from fuzz close /
 * dup2 / dup3 / close_range targeting via fd_is_protected() /
 * lowest_protected_fd_in_range() in include/fd.h -- the same registry
 * that protects STDERR_FILENO and the stderr capture memfd.  See those
 * declarations for the contract.
 */

/* Returns true if syscall nr hasn't found new edges recently.
 * Used by syscall selection to deprioritize saturated syscalls. */
bool kcov_syscall_is_cold(unsigned int nr);

/* Returns the recommended skip percentage (0-90) for syscall nr based on
 * how stale its coverage is.  0 means "not cold, don't skip"; otherwise
 * the value grows with the staleness gap so persistently cold syscalls
 * are deprioritized harder than ones that just crossed the threshold. */
unsigned int kcov_syscall_cold_skip_pct(unsigned int nr);

/* Sliding-window edge-rate plateau check.  Self-gates on
 * KCOV_PLATEAU_WINDOW_SEC, so the caller can invoke it once per
 * main_loop tick alongside the other periodic samplers.  Emits a
 * one-line PLATEAU warning to stats.log when the per-window edge
 * discovery rate drops below KCOV_PLATEAU_ENTER_THRESHOLD and a matching
 * PLATEAU CLEARED line when the rate climbs back above
 * KCOV_PLATEAU_EXIT_THRESHOLD (hysteresis band).  On the PLATEAU rising
 * edge it also fires strategy_plateau_response(), which forces a
 * strategy rotation into the plateau-intervention layer (RRC-biased
 * replay, anti-prior accept gating, or uniform random in a flat
 * round-robin -- the rotation does not pin a mode based on the
 * hypothesis classifier).  Interventions unwind on CLEARED. */
void kcov_plateau_check(void);

/* Mid-run snapshot cadence for kcov_bitmap_maybe_snapshot().  The bitmap
 * is 8 MB and writing it is bursty I/O, so the triggers are coarser than
 * the minicorpus snapshot interval: 1000 new edges OR 300s since the
 * last save, whichever fires first.  Hardcoded -- no operator knob,
 * fleet boxes shouldn't need to retune. */
#define KCOV_BITMAP_SNAPSHOT_EDGES		1000UL
#define KCOV_BITMAP_SNAPSHOT_INTERVAL_SEC	300UL

/* Warm-start persistence for the kcov_shm bucket_seen[] hit-count bitmap
 * and the edges_found counter.  Save/load are gated on a kernel-binary
 * fingerprint -- sha256 over /proc/kallsyms with the address column
 * stripped -- so a rebuilt kernel (even with an unchanged utsname.release
 * / utsname.version pair) gets a fresh bitmap instead of loading stale
 * data against a different edge layout.  The address-stripping step
 * makes the fingerprint identical whether kallsyms is read as root or
 * non-root (kptr_restrict zeroes the addresses for the latter) and also
 * invariant across KASLR vs nokaslr boots of the same build.  Stale or
 * unreadable files are silently discarded and the loader returns false;
 * cold-start is the legitimate first-run state. */
bool kcov_bitmap_save_file(const char *path);
bool kcov_bitmap_load_file(const char *path);
const char *kcov_bitmap_default_path(void);

/* Fill OUT[32] with the cached kallsyms-derived kernel fingerprint
 * (sha256 over /proc/kallsyms with the leading address column stripped
 * and module / BPF runtime symbols filtered out -- see the comment on
 * kcov_fingerprint_kernel() for the precise filter rules).  First call
 * streams /proc/kallsyms and caches; subsequent calls memcpy from the
 * cache.  Returns false (with OUT untouched) when /proc/kallsyms is
 * unreadable; caller should treat that as "warm-start disabled this
 * run".  Exposed so cross-run-state files outside kcov.c (e.g. the
 * cmp-hints pool) can stamp the same fingerprint into their headers
 * and stay in lock-step with the kcov-bitmap warm-start invariants. */
bool kcov_get_kernel_fp(uint8_t out[32]);

/* Read-only accessor for the runtime kernel-text base resolved by
 * kcov_init_global from /proc/kallsyms.  Zero means the lookup failed
 * (kallsyms unreadable, _text/_stext absent, or kptr_restrict zeroed
 * every address) and the run is hashing kernel addresses raw.  Exposed
 * so cross-run-state writers outside kcov.c (the cmp-hints pool) can
 * stamp the same value into their on-disk headers and reject a
 * canonical-vs-raw mismatch on load, matching the kcov-bitmap header's
 * kaslr_base field. */
uint64_t kcov_kaslr_base_value(void);

/* Strip the runtime KASLR base from a kernel comparison-instruction
 * address before it enters the cmp-hints bloom + per-syscall pool +
 * persisted state file.  Companion to kcov_canon_pc (the PC-coverage
 * canonicaliser) -- same arithmetic, separate named entry point so the
 * cmp-hint canonicalisation invariant can be enforced in isolation by
 * scripts/check-static/cmp-hints-canonicalise-cmp-ip.sh.  Returns the
 * argument unchanged on systems where kcov_kaslr_base stayed zero. */
unsigned long kcov_canon_cmp_ip(unsigned long ip);

/* Wire periodic mid-run snapshots of the bucket_seen bitmap to PATH.
 * Subsequent kcov_bitmap_maybe_snapshot() calls become live; a no-op
 * before this is called.  Path is copied. */
void kcov_bitmap_enable_snapshots(const char *path);

/* Cheap per-tick gate: writes the snapshot if either trigger has elapsed
 * since the last successful save, otherwise returns immediately.  Called
 * from the parent's stats tick and from kcov_plateau_check() when a
 * plateau is first entered. */
void kcov_bitmap_maybe_snapshot(void);
