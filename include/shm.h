#pragma once

#include <stdatomic.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>
#include "arch.h"
#include "child.h"
#include "efault_cache.h"
#include "exit.h"
#include "files.h"
#include "healer.h"
#include "locks.h"
#include "net.h"
#include "object-types.h"
#include "stats.h"
#include "strategy.h"
#include "syscall.h"
#include "types.h"

struct io_uringobj;

void create_shm(void);
void init_shm(void);

/*
 * Concurrent in-flight cap for unshare(CLONE_NEWNET) and the matching
 * clone()/clone3() flag.  Trinity children fuzzing fork()/clone()/clone3()
 * spawn untracked grandchildren; each grandchild that calls unshare with
 * CLONE_NEWNET feeds the kernel's netns cleanup workqueue, and the
 * per-call cost grows with the queue's backlog.  Past a few in-flight
 * unshares per host the workqueue can't keep up — copy_net_ns() begins
 * blocking in D-state, the untracked grandchild population grows
 * unbounded, and the box turns into a forkbomb.  A small fleet-wide
 * cap on in-flight CLONE_NEWNET callers caps the backlog the kernel
 * side has to drain.  See shm->newnet_in_flight and the
 * unshare_newnet_throttled stat counter.
 */
#define MAX_CONCURRENT_NEWNET 4

struct shm_s {
	char __padding[4096];

	/* Frequently updated by all children — own cache line. */
	struct stats_s stats __attribute__((aligned(64)));

	/* Wall-clock time init_shm() ran.  Read-only after init; used by
	 * dump_stats() to log absolute runtime alongside iters/s, which lets
	 * crash post-mortem correlate trinity output to external logs. */
	time_t start_time;

	/*
	 * Identity of trinity's own binary, captured once in init_shm() via
	 * stat("/proc/self/exe", ...).  Read-only after init; written exactly
	 * once before any child forks, so children inherit the populated cache
	 * via shared mapping and the execve sanitiser can fstatat() the target
	 * of a fuzzed execve / execveat and refuse the syscall if the resolved
	 * (dev, ino) matches.  Catches every path that resolves to the trinity
	 * binary regardless of name -- /proc/self/exe, /proc/<pid>/exe,
	 * hardlinks, bind-mounted aliases, the literal path the operator
	 * launched with, and execveat(fd, "", AT_EMPTY_PATH) where fd is
	 * inherited from the parent.  valid == false means the startup stat
	 * failed (very unlikely; /proc not mounted or similar) and the guard
	 * short-circuits to "no protection" -- degraded behaviour matches the
	 * pre-guard baseline.  See sanitise_execve() in syscalls/execve.c.
	 */
	struct {
		dev_t dev;
		ino_t ino;
		bool valid;
	} trinity_self_exe;

	/*
	 * Monotonic generation counter bumped by each new child after it
	 * completes its sibling-childdata freeze in init_child.  Each child
	 * caches the last value it saw and re-checks it at the top of the
	 * child_process loop; a mismatch triggers a catch-up refreeze that
	 * pulls any newly-spawned sibling into our PROT_READ set.
	 *
	 * Closes the startup race where a sibling that was mid-syscall when
	 * a fresh child was forked still has the new child's childdata at
	 * PROT_READWRITE in its view.  In that window a value-result kernel
	 * write triggered by the busy sibling can land inside the new
	 * child's not-yet-frozen region (childdata is alloc_shared and so
	 * occupies a discrete 4 KiB-aligned mmap slot per child — random
	 * pointer args from the busy sibling can fall there).  The window
	 * was previously open forever; now it shrinks to "until each
	 * existing sibling reaches its next loop top check", typically one
	 * syscall worth of latency.
	 *
	 * Lives next to start_time deliberately: that slot was padding
	 * before the 64-byte-aligned fd_hash cacheline, so adding the
	 * counter doesn't introduce false sharing with anything hot.  Only
	 * written on spawn (rare); reads are RELAXED-equivalent loads on
	 * the loop top — one pulled cacheline shared across all readers.
	 */
	unsigned int sibling_freeze_gen;

	/* Written by main process — own cache line to avoid
	 * false sharing with child-written stats above. */
	unsigned int running_childs __attribute__((aligned(64)));

	/* rng related state */
	unsigned int seed;

	/* Indices of syscall in syscall table that are active.
	 * All indices shifted by +1. Empty index equals to 0.
	 *
	 * 'active_syscalls' is only used on uniarch. The other two
	 * are only used on biarch. */
	int active_syscalls32[MAX_NR_SYSCALL];
	int active_syscalls64[MAX_NR_SYSCALL];
	int active_syscalls[MAX_NR_SYSCALL];
	unsigned int nr_active_syscalls;
	unsigned int nr_active_32bit_syscalls;
	unsigned int nr_active_64bit_syscalls;

	/*
	 * Cached "table has at least one active syscall" booleans for the
	 * biarch picker.  Maintained by validate_syscall_table_{32,64}() at
	 * startup and invalidated by the deactivate_syscall{32,64}() paths
	 * (and the 32-on-64 emulation auto-disable) when the corresponding
	 * nr_active_*bit_syscalls counter falls to zero.  Lets
	 * choose_syscall_table() short-circuit the per-pick walk through
	 * validate_syscall_table_{32,64}() with two single-byte loads.
	 *
	 * Only meaningful on biarch builds; uniarch never reads them.
	 */
	bool valid_syscall_table_32;
	bool valid_syscall_table_64;

#ifdef ARCH_IS_BIARCH
	/* Check that 32bit emulation is available. */
	unsigned int syscalls32_succeeded;
	unsigned int syscalls32_attempted;
#endif
	/* io_uring ring with valid mappings, shared across children.
	 * Init write uses RELEASE; child reads use ACQUIRE (lockless).
	 * Destructor nulls this. */
	struct io_uringobj *mapped_ring;

	/* Contended child<>child locks — own cache line. */
	lock_t syscalltable_lock __attribute__((aligned(64)));
	lock_t buglock;

	/*
	 * Sibling cursor for the shared string heap (see
	 * alloc_shared_str() in utils.c).
	 */
	size_t shared_str_heap_used __attribute__((aligned(64)));

	/*
	 * Per-bucket freelist head for the shared string heap.
	 * NUM_SHM_FREELIST_BUCKETS fixed-size slots (8..1024 bytes, powers of
	 * two); allocations above 1024 bytes bypass the freelist and use the
	 * bump allocator directly.  Each head is a 64-bit tagged pointer:
	 * the low 48 bits hold the address of the most-recently-freed slot
	 * (0 = empty list) and the high 16 bits hold a monotonic version
	 * counter that defeats the ABA race in freelist_pop (see the long
	 * comment above the freelist primitives in utils.c).  The link to the
	 * next free slot is stored in the slot's own first sizeof(uintptr_t)
	 * bytes (safe because the slot is, by definition, not live when the
	 * link is written).  Manipulated by lock-free CAS in freelist_push/pop
	 * in utils.c.
	 */
#define NUM_SHM_FREELIST_BUCKETS 8
	uint64_t shared_str_freelist[NUM_SHM_FREELIST_BUCKETS];

	/* various flags. */
	enum exit_reasons exit_reason;
	/* set by check_uid alongside panic(EXIT_UID_CHANGED) so main can
	 * include the offending uid in the bail message. */
	uid_t uid_at_exit;
	bool dont_make_it_fail;

	/* Set to true once we detect that /proc/self/fail-nth can't be
	 * opened (kernel built without CONFIG_FAULT_INJECTION, etc.).
	 * Lives in shm so the flag propagates across fork(). */
	bool no_fail_nth;
	bool spawn_no_more;
	bool ready;
	bool postmortem_in_progress;

	/* global debug flag.
	 * This is in the shm so we can do things like gdb to the main pid,
	 * and have the children automatically take notice.
	 * This can be useful if for some reason we don't want to gdb to the child.
	 */
	bool debug;

	/* set to true if a child hits an EPERM/EINVAL trying to
	 * unshare(CLONE_NEWPID). Stored in shm so the flag propagates
	 * across fork() — a process-local static would be duplicated
	 * into each child's address space. */
	bool no_pidns;

	/* set to true if a child fails the MS_REC|MS_PRIVATE remount
	 * after unshare(CLONE_NEWNS). Stored in shm so the flag
	 * propagates across fork() — a process-local static would be
	 * duplicated into each child's address space. Used to suppress
	 * log spam over long fuzz runs and to skip the unshare+remount
	 * dance once we know it can't be made private. */
	bool no_private_ns;

	/*
	 * Fleet-wide in-flight count of unshare(CLONE_NEWNET) and the
	 * matching clone()/clone3() flag.  The sanitise hooks for those
	 * three syscalls bump this on admission and the matching post
	 * hooks drop it; calls that find the count already at
	 * MAX_CONCURRENT_NEWNET strip CLONE_NEWNET from the flag arg
	 * instead of admitting another in-flight caller and bump
	 * the unshare_newnet_throttled aggregate counter.  See the long comment on
	 * MAX_CONCURRENT_NEWNET above for the kernel-side reason this
	 * cap exists.  Stored in shm so all children plus any untracked
	 * grandchildren they fork share one counter — a process-local
	 * static would be duplicated across the COW fork tree and let
	 * each subtree run its own unbounded admission rate.
	 */
	int newnet_in_flight;

	/* recipe_runner discovery latches: a recipe whose first invocation
	 * detects an absent kernel feature (ENOSYS, missing config) flips
	 * its slot here so siblings stop probing.  Indexed by the recipe's
	 * slot in the static catalog inside recipe-runner.c. */
	bool recipe_disabled[MAX_RECIPES];

	/* iouring_recipes discovery latches: mirrors recipe_disabled but
	 * scoped to the iouring-recipes childop catalog. */
	bool iouring_recipe_disabled[MAX_IOURING_RECIPES];

	/* Set to true once we confirm io_uring_setup returns ENOSYS.
	 * Avoids repeated failed probes from every child. */
	bool iouring_enosys;

	/* socket_family_chain childop unsupported latch.  Set to true after
	 * an invocation hits a burst of ESRCH/EPERM/ENOPROTOOPT errors,
	 * indicating the kernel was built without CRYPTO_USER_API or AF_ALG
	 * is otherwise locked down.  Siblings then skip the chain entirely. */
	bool socket_family_chain_unsupported;

	/* Per-family latch for the socket-family-grammar dispatcher
	 * (net/socket-family-grammar.c).  sfg_unsupported[family] is set
	 * when can_run() probes fail or when run_grammar_chain() exhausts
	 * its ERR_BURST_LIMIT for that family — siblings then skip the
	 * grammar entry on subsequent picks.  No auto-clear; module load
	 * mid-run takes the hit, same recovery story as the AF_ALG latch
	 * above. */
	bool sfg_unsupported[TRINITY_PF_MAX];

	/*
	 * Multi-strategy syscall picker — see include/strategy.h.
	 *
	 * current_strategy: fleet-wide active strategy enum.  Children read
	 *   it on every syscall pick (relaxed atomic, single int read — cheap).
	 *   Updated only by the CAS-winning child at a rotation boundary.
	 *
	 * syscalls_at_last_switch: shm_published->fleet_op_count at the most
	 *   recent rotation.  Doubles as the CAS guard — a child computes
	 *   (op_count - syscalls_at_last_switch); if that crosses
	 *   STRATEGY_WINDOW it tries to CAS this field forward to op_count.
	 *   The CAS winner performs the strategy switch and emits the stats
	 *   line; losers just continue with the new strategy on their next
	 *   pick.
	 *
	 * pc_edge_calls_at_window_start / pc_edge_count_at_window_start:
	 *   snapshots of pc_edge_calls_by_strategy[prev] and
	 *   pc_edge_count_by_strategy[prev] taken at the previous switch.
	 *   Let the next switch compute the per-window deltas as
	 *   pc_edge_calls_by_strategy[prev] - pc_edge_calls_at_window_start
	 *   (call-count delta), and similarly for the bucket-count series.
	 *   Written only by the CAS-winning child during a switch —
	 *   sequential w.r.t. the CAS, so no atomic needed.
	 *
	 * pc_edge_calls_by_strategy[]: cumulative count of SYSCALL CALLS
	 *   attributed to each strategy whose post-call kcov_collect()
	 *   flipped at least one never-seen bucket bit.  Bumped by +1 per
	 *   such call, NOT by the number of distinct edges that call
	 *   uncovered: a syscall that exposes 50 fresh edges in one shot
	 *   still bumps the call-count series by 1.  This is the historical
	 *   "edges_by_strategy[]" signal renamed to match its actual shape
	 *   (calls-with-≥1-edge, not edges).  It is the signal the UCB1
	 *   learner reads via bandit_reward_calls[] below.
	 *
	 * pc_edge_count_by_strategy[]: cumulative count of REAL bucket-edge
	 *   bits flipped by syscalls attributed to each strategy — the
	 *   per-call new_edge_count from kcov_collect(), summed across all
	 *   contributing calls.  Strictly >= the call-count series, often
	 *   far larger when individual calls uncover deep paths.  Added
	 *   alongside the call-count series so both signals are visible
	 *   without changing the learner's behaviour; a future commit may
	 *   switch UCB1 to consume this series instead, or fold a transform
	 *   of it (e.g. log2(1 + count)) into the reward.
	 *
	 * Cmp-mode runs do not produce a new-edge signal and are not
	 * attributed to either series.
	 */
	int current_strategy;

	/*
	 * current_selection_reason: enum strategy_selection_reason for the
	 *   current_strategy above -- why select_next_strategy() returned
	 *   that arm for this window.  Stored alongside current_strategy
	 *   so the rotation site can read it back at window close and
	 *   decide whether to feed the just-finished window into the UCB
	 *   learner.  Forced-intervention windows (SR_PLATEAU_FORCE) skip
	 *   the learner update so policy-chosen RANDOM windows and
	 *   intervention RANDOM windows do not get conflated in
	 *   bandit_pulls[]/bandit_reward_calls[].  Held as int rather than
	 *   the enum type so the shm layout stays language-stable across
	 *   any future enum reorder.
	 */
	int current_selection_reason;
	unsigned long syscalls_at_last_switch;
	unsigned long pc_edge_calls_at_window_start;
	unsigned long pc_edge_count_at_window_start;
	unsigned long pc_edge_calls_by_strategy[NR_STRATEGIES];
	unsigned long pc_edge_count_by_strategy[NR_STRATEGIES];

	/*
	 * UCB1 bandit picker (Phase 2) — see include/strategy.h.
	 *
	 * picker_mode: arm-selection policy (PICKER_ROUND_ROBIN or
	 *   PICKER_BANDIT_UCB1).  Set once at init_shm time from
	 *   picker_mode_arg, never mutated thereafter.  Read by the
	 *   CAS-winning child on the rotation path.
	 *
	 * bandit_pulls[]: number of windows each arm was selected for.
	 *   Bumped by bandit_record_pull() during the rotation switch,
	 *   which is serialised by the syscalls_at_last_switch CAS, so
	 *   plain integer writes are safe (no concurrent writers).
	 *
	 * bandit_reward_calls[]: cumulative reward attributed to each arm,
	 *   in CALL-COUNT units — sum of per-window
	 *   (pc_edge_calls_by_strategy delta + cmp_term).  Despite the
	 *   historical "reward" name, the PC component here counts CALLS
	 *   that produced at least one new edge, not real bucket edges (see
	 *   the pc_edge_calls_by_strategy comment above).  This is the
	 *   signal the UCB1 picker scores against; renamed from
	 *   bandit_reward[] to make the call-count shape explicit.  Future
	 *   work may switch the learner to consume
	 *   bandit_reward_pc_edge_count[] below (real bucket count) or a
	 *   transform of it; this commit only makes both signals visible.
	 *
	 * bandit_reward_pc_edge_count[]: cumulative PC-edge BUCKET COUNT
	 *   attributed to each arm — sum of per-window
	 *   pc_edge_count_by_strategy deltas, no cmp term folded in.
	 *   Diagnostic-only today: visible alongside the call-count series
	 *   in dump_strategy_stats() so the operator can see how the two
	 *   signals would score the same set of windows differently before
	 *   we commit to flipping the learner.
	 *
	 * Both reward series are written under the same CAS-serialised
	 * rotation path as bandit_pulls[].
	 */
	int picker_mode;
	unsigned long bandit_pulls[NR_STRATEGIES];
	unsigned long bandit_reward_calls[NR_STRATEGIES];
	unsigned long bandit_reward_pc_edge_count[NR_STRATEGIES];

	/*
	 * Per-arm syscall-level exposure counters.  The existing per-arm
	 * series (bandit_pulls[], pc_edge_calls_by_strategy[],
	 * bandit_reward_calls[]) all measure WINDOWS or NEW-EDGE CALLS --
	 * the bandit reward signal -- and leave the denominator side
	 * implicit.  Without an explicit per-arm dispatch count the only
	 * way to derive "how many syscalls actually ran under this arm
	 * this run" is to scale stats.reward_per_fleet_op_window by the
	 * window mix, which mixes in syscall latency, explorer/alt-op
	 * share, blocking behaviour, and rotation drift.  That makes
	 * tuning A/B comparisons across runs hard: a reward delta might
	 * mean the arm is genuinely better, or just that this run's
	 * background changed enough to shift exposure.
	 *
	 * The counters here are the denominators those analyses need:
	 *
	 * strategy_picks[]: every syscall pick credited to an arm,
	 *   bumped in set_syscall_nr() right after the arm is resolved
	 *   for this pick.  Explorer-pool children always run
	 *   STRATEGY_RANDOM and bump strategy_picks[STRATEGY_RANDOM]
	 *   directly; the bandit pool bumps the arm shm->current_strategy
	 *   resolved to.  This is the widest population -- all dispatched
	 *   syscalls.
	 *
	 * strategy_bandit_pool_ops[]: strict subset of strategy_picks --
	 *   bumped only on the bandit-pool path.  Lets the operator
	 *   compute (strategy_picks[a] - strategy_bandit_pool_ops[a]) as
	 *   the explorer-pool contribution per arm (zero for non-RANDOM
	 *   arms, monotonic with explorer_children for RANDOM).  This is
	 *   the population that pairs cleanly with
	 *   pc_edge_calls_by_strategy[] -- both are bandit-pool only and
	 *   exclude explorer contributions.
	 *
	 * strategy_completed_calls[]: bumped at the end of dispatch_step
	 *   after the syscall has returned and post-call bookkeeping has
	 *   run.  Excludes set_syscall_nr() FAIL returns (no syscall
	 *   was dispatched), so the ratio
	 *   strategy_completed_calls[a] / strategy_picks[a] is the
	 *   per-arm dispatch success rate -- a low ratio surfaces an arm
	 *   whose picker policy is repeatedly hitting unsatisfiable
	 *   eligibility / validation gates.
	 *
	 * Multi-producer (every child writes); RELAXED fetch_add on the
	 * write side, RELAXED loads in dump_strategy_stats() at end of
	 * run.  Per-arm cacheline contention is acceptable because these
	 * are diagnostic counters consulted at run-end and by future
	 * intervention classifiers (plateau #5 reads these alongside
	 * pc_edge_calls_by_strategy to decide which arm to force during
	 * a plateau intervention) -- not on the hot pick path.
	 */
	unsigned long strategy_picks[NR_STRATEGIES];
	unsigned long strategy_bandit_pool_ops[NR_STRATEGIES];
	unsigned long strategy_completed_calls[NR_STRATEGIES];

	/*
	 * Per-arm-per-selection-reason reward attribution.  Each window's
	 * outcome is bucketed into [arm][reason] independent of the
	 * learner-facing bandit_pulls[]/bandit_reward_calls[] series above
	 * so the operator and the future intervention classifier can see
	 * how each arm's exposure splits across selection paths:
	 *
	 *   bandit_pulls_by_reason[a][SR_NORMAL_UCB]    -- arm a was
	 *     chosen by the UCB1 scorer (the bandit's policy decision).
	 *   bandit_pulls_by_reason[a][SR_COLD_START]    -- arm a was
	 *     chosen because UCB1 had not seen it pulled yet.
	 *   bandit_pulls_by_reason[a][SR_ROUND_ROBIN]   -- arm a's slot
	 *     in the fixed cycle (round-robin mode only).
	 *   bandit_pulls_by_reason[a][SR_PLATEAU_FORCE] -- arm a (always
	 *     STRATEGY_RANDOM today) was forced by the intervention
	 *     orchestrator over the top of the bandit's pick.  These
	 *     windows are deliberately EXCLUDED from bandit_pulls[] and
	 *     the recent_*_x1000 EMA so the learner's view of RANDOM
	 *     stays uncontaminated, but they ARE recorded here so the
	 *     operator can see the intervention cohort's reward
	 *     separately and a future plateau-rescue classifier can
	 *     read pulls_by_reason[*][SR_PLATEAU_FORCE] +
	 *     pc_edge_calls_by_strategy[*] to decide which arm to force
	 *     next time.
	 *
	 * Three parallel matrices mirror the lifetime series:
	 *
	 *   bandit_pulls_by_reason[a][r]              -- window count
	 *   bandit_reward_calls_by_reason[a][r]       -- combined reward
	 *     (pc_edge_calls + cmp_term), same units as
	 *     bandit_reward_calls[].
	 *   bandit_reward_pc_edge_count_by_reason[a][r] -- real bucket-
	 *     edge count, same units as bandit_reward_pc_edge_count[].
	 *
	 * Same single-writer protocol as bandit_pulls[] (CAS-serialised
	 * rotation path).  dump_strategy_stats() uses RELAXED loads.
	 * 4 strategies * 4 reasons * 3 series * 8 bytes = 384 bytes,
	 * trivial against existing shm consumers.
	 */
	unsigned long bandit_pulls_by_reason[NR_STRATEGIES][NR_SELECTION_REASONS];
	unsigned long bandit_reward_calls_by_reason[NR_STRATEGIES][NR_SELECTION_REASONS];
	unsigned long bandit_reward_pc_edge_count_by_reason[NR_STRATEGIES][NR_SELECTION_REASONS];

	/*
	 * Random-rescue classifier counters -- see classify_random_rescue
	 * in include/strategy.h.  Each new-edge syscall completed during a
	 * SR_PLATEAU_FORCE window is classified into one of the
	 * RRC_* buckets and the corresponding slot here is bumped.  The
	 * cumulative distribution is what the next plateau intervention
	 * reads to decide whether plain RANDOM is still the right rescue
	 * arm or whether the classifier has accumulated enough evidence to
	 * point at a more targeted intervention (cold-skip disable, HEALER,
	 * cmp-hint boost, etc.).
	 *
	 * Multi-producer (every child that completes a rescue increments
	 * its class slot); RELAXED fetch_add on the write side, RELAXED
	 * loads on the orchestrator-side reads in select_next_strategy and
	 * dump_strategy_stats.  Per-class cacheline contention is
	 * acceptable: the writer set is small (only children whose syscall
	 * landed in a forced-intervention window and produced new edges)
	 * and the readers consult these counts at rotation boundaries and
	 * at end-of-run, not on the hot pick path.
	 */
	unsigned long random_rescue_class_count[RRC_NR_CLASSES];

	/*
	 * Discounted "recent" counters that the UCB1 picker scores against
	 * instead of the lifetime bandit_pulls[]/bandit_reward_calls[]
	 * series above.  Kernel coverage discovery is strongly
	 * non-stationary: easy edges are mined out in the first windows of
	 * a run, the surface degrades over time, and any picker that
	 * averages reward over the lifetime of the run lets early-window
	 * wins dominate late-window arm selection forever.  Discounting the
	 * counters with a rolling exponential weight keeps the picker
	 * responsive to recent yield.
	 *
	 * Both arrays are fixed-point parts-per-thousand (suffix _x1000) so
	 * the EMA arithmetic stays in unsigned-long integer math without
	 * dragging a double into shm.  The exact alpha and the EMA update
	 * site live in strategy.c (BANDIT_EMA_ALPHA_X1000); a half-life of
	 * ~10-30 windows is the design target so an arm whose yield
	 * collapses after a configuration change (e.g. cgroup mount,
	 * netns unshare) loses its grip on the picker within minutes
	 * rather than hours.
	 *
	 * recent_pulls_x1000[]: discounted effective sample count.  Each
	 *   non-intervention window decays every arm by (1 - alpha) and
	 *   adds 1.0 (== BANDIT_EMA_SCALE) to the active arm, so the
	 *   asymptote for an always-picked arm is SCALE/alpha (20000 at
	 *   alpha=0.05) and arms that stop being picked decay back toward
	 *   zero over the half-life.
	 * recent_reward_x1000[]: discounted total reward in the same
	 *   fixed-point.  Mean per-window reward is
	 *   recent_reward_x1000[i] / recent_pulls_x1000[i] (the x1000
	 *   cancels) so the UCB1 exploit term works without an explicit
	 *   rescale step.
	 * last_selected_window[]: bandit_window_count snapshot at the last
	 *   pull of each arm.  Diagnostic only — surfaced in
	 *   dump_strategy_stats() so the operator can see how stale each
	 *   arm's recent estimate is.
	 *
	 * Decaying EVERY arm each window (not just the pulled one) is what
	 * keeps the UCB1 exploration term n_i denominator meaningful under
	 * discounting: an arm that stops being picked must see its
	 * effective sample count shrink so the explore bonus grows and the
	 * picker eventually re-tries it.  EMA-on-pull-only (decay only the
	 * pulled arm) would leave un-pulled arms' counts frozen forever,
	 * which breaks the formula.
	 *
	 * SR_PLATEAU_FORCE windows skip both the decay and the increment,
	 * mirroring the lifetime bandit_pulls[] path: an intervention
	 * window is not a learner observation, and bleeding intervention
	 * noise into the discount cadence would shift every arm toward
	 * the post-plateau distribution every time the orchestrator fires.
	 *
	 * Same CAS-serialised single-writer protocol as bandit_pulls[];
	 * dump_strategy_stats() uses RELAXED loads to tolerate the writer
	 * race the same way it does for the lifetime fields.
	 */
	unsigned long recent_pulls_x1000[NR_STRATEGIES];
	unsigned long recent_reward_x1000[NR_STRATEGIES];
	unsigned long last_selected_window[NR_STRATEGIES];

	/*
	 * Monotonic rotation counter, bumped by the CAS-winning child in
	 * maybe_rotate_strategy() once per completed window.  Used as the
	 * generation tag for the cmp_novelty[] bloom decay below: a bloom
	 * entry with window_tag more than CMP_NOVELTY_DECAY_WINDOWS behind
	 * this counter is considered stale and gets cleared on next access.
	 * Stays plain unsigned long with explicit __atomic_* accessors to
	 * match the existing bandit_pulls[]/bandit_reward_calls[] convention.
	 */
	unsigned long bandit_window_count;

	/*
	 * Per-syscall comparison-constant novelty bloom — see include/strategy.h
	 * (bandit_cmp_observe).  Each entry holds a 1024-bit bloom filter over
	 * the comparison constants observed for that syscall in the recent
	 * past, plus a generation tag (the rotation count at which the bloom
	 * was last cleared).  When a child observing a fresh CMP record finds
	 * the entry's tag more than CMP_NOVELTY_DECAY_WINDOWS rotations old it
	 * lazily zeroes the bloom and republishes the tag, so a constant that
	 * stops appearing for K windows is forgotten and counts as novel
	 * again.  Sized 132 bytes per syscall * MAX_NR_SYSCALL ≈ 132 KiB inside
	 * shm — well below other arrays already living here (per_syscall_*).
	 *
	 * bandit_cmp_new_constants[]: per-arm cumulative count of CMP records
	 *   that missed the bloom at observation time.  Bumped by every child
	 *   inside bandit_cmp_observe() (atomic add, multiple producers).  The
	 *   rotation hook turns the per-window delta into a secondary reward
	 *   term inside bandit_record_pull().
	 */
	struct cmp_novelty_entry {
		uint32_t window_tag;
		uint8_t bloom[128];
	} cmp_novelty[MAX_NR_SYSCALL];
	unsigned long bandit_cmp_new_constants[NR_STRATEGIES];

	/*
	 * Snapshot of bandit_cmp_new_constants[active_arm] at the start of
	 * the current window, by symmetry with pc_edge_calls_at_window_start.
	 * The
	 * rotation hook reads bandit_cmp_new_constants[prev] and subtracts
	 * this snapshot to compute the cmp-novelty delta the just-finished
	 * window produced, then reseeds the snapshot from the next arm's
	 * counter.  Single field rather than per-arm because only one arm
	 * is active per window.  Written only by the CAS-winning child.
	 */
	unsigned long bandit_cmp_at_window_start;

	/*
	 * Per-arm cumulative sum of (cmp_term * 1000 / total_reward) across
	 * windows where cmp_term > 0.  Divided by bandit_pulls[arm] at end
	 * of run to print the average per-window CMP contribution share, so
	 * the operator can tune CMP_BANDIT_REWARD_WEIGHT_RECIPROCAL on real
	 * run data.  Written only by the CAS-winning child, same path as
	 * bandit_pulls/bandit_reward_calls.
	 */
	unsigned long bandit_cmp_share_sum_x1000[NR_STRATEGIES];

	/*
	 * Per-syscall frontier-edge ring -- see include/strategy.h.
	 *
	 * frontier_history[nr][slot] counts NEW edges syscall nr produced
	 * during the rotation window mapped to slot.  Slot is an index in
	 * [0, FRONTIER_DECAY_WINDOWS); the slot currently being filled is
	 * (frontier_slot & mask), advanced once per rotation by the
	 * CAS-winning child via frontier_window_advance().  Sum across all
	 * slots is the syscall's "recent frontier-edge count" -- the weight
	 * the coverage-frontier picker biases its uniform pick toward.
	 *
	 * Bumped on the kcov_collect new-edge branch by every child
	 * (multi-producer, atomic add).  Slot rotation zeroes the new slot
	 * before publishing the new index, so a producer racing the rotation
	 * either bumps the previous (still-valid) slot or the freshly cleared
	 * new slot -- both attribute correctly within the K-window decay.
	 *
	 * Sized MAX_NR_SYSCALL * FRONTIER_DECAY_WINDOWS * 4 = 32 KiB, a
	 * rounding error against the cmp_novelty[] block above.
	 */
	uint32_t frontier_history[MAX_NR_SYSCALL][FRONTIER_DECAY_WINDOWS];
	uint32_t frontier_slot;

	/*
	 * Per-syscall cached recent-edge count -- running sum of
	 * frontier_history[nr][*] across the live ring, maintained
	 * incrementally so frontier_recent_count(nr) is a single RELAXED
	 * load instead of an O(FRONTIER_DECAY_WINDOWS) walk.  Producers
	 * fetch_add 1 here in lockstep with the per-slot bump; the window
	 * rotator subtracts the just-zeroed slot's contribution from this
	 * counter in the same pass that clears the slot.  Same RELAXED
	 * race envelope as frontier_history -- a producer add that
	 * interleaves with the rotation's exchange-then-subtract can leave
	 * cached one bump above the live sum, bounded by one window and
	 * folded back in by the next rotation.
	 */
	uint32_t frontier_recent_count_cached[MAX_NR_SYSCALL];

	/*
	 * Cached max of frontier_recent_count() across all syscalls --
	 * the rejection-sampling acceptance ratio in the coverage-frontier
	 * picker uses this as the bias-mass denominator.  Recomputed
	 * authoritatively on each window rotation, and ratcheted upward
	 * on new-edge bumps, so the picker reads it with a single
	 * RELAXED load instead of walking ~MAX_NR_SYSCALL frontier rings
	 * (8 RELAXED loads each) per pick.  Torn / stale values are
	 * acceptable: a slightly low cached max biases the picker toward
	 * heavier-weighted syscalls (under-rejecting cold ones); a
	 * slightly high one biases it toward uniform.  Both errors are
	 * bounded by one window rotation.
	 */
	unsigned int frontier_max_weight_cached;

	/*
	 * EFAULT-probe cache for ioctl arg classification.  Open-addressing
	 * hashmap keyed on (group_idx, request); see ioctls/efault_cache.c
	 * for the slot encoding and the probing protocol.  Lives in shm so
	 * a verdict reached by one child is reused by all the others — the
	 * kernel's ioctl tables are global and the probe has side effects
	 * we want to amortise.  Zero-initialised by create_shm(); packed ==
	 * 0 is the empty-slot sentinel.
	 */
	uint64_t ioctl_efault_cache[IOCTL_EFAULT_CACHE_SIZE];

	/*
	 * The HEALER relation + pair tables that used to live here moved
	 * to a parent-private canonical (struct healer_aggregate) fed by
	 * per-child SPSC observation rings, with two child-RO mirror
	 * pages serving the picker's reads.  See include/healer_ring.h
	 * for the topology and healer-ring.c for the apply / publish
	 * machinery.  The migration removed 5.13 MiB from shm and
	 * eliminated the wild-write attack surface for the largest
	 * region in the shared mapping.
	 */
};
extern struct shm_s *shm;
extern unsigned int shm_size;

/*
 * Low-bit ticket the CLONE_NEWNET throttle stamps onto rec->post_state
 * after a successful admission.  clone3 packs the args pointer in the
 * high bits of post_state; zmalloc returns >=8-byte-aligned pointers,
 * so bit 0 is free.  unshare and clone leave the rest of post_state as
 * zero, so the same bit overlays cleanly there too.
 */
#define NEWNET_INFLIGHT_TICKET	0x1UL

/*
 * Single-CAS admission for the CLONE_NEWNET throttle.  Returns true if
 * the caller now owns one ticket against shm->newnet_in_flight; the
 * caller MUST stamp NEWNET_INFLIGHT_TICKET onto rec->post_state and
 * release with release_newnet_ticket() from the post hook.  Returns
 * false if the cap is full -- caller strips CLONE_NEWNET and bumps the
 * throttled stat.
 *
 * A relaxed load followed by a separate __atomic_fetch_add() (the
 * shape these three call sites used to share) lets several callers
 * all observe the counter below the cap then all increment, over-
 * admitting by an entire wave.  CAS closes that window: the
 * increment only commits if the value we tested against is still
 * what we read.
 *
 * Unconditional fetch-add + rollback is not equivalent -- the
 * transient over-admission still feeds copy_net_ns() and is the whole
 * thing the cap exists to prevent.
 */
static inline bool try_admit_newnet(void)
{
	int old = __atomic_load_n(&shm->newnet_in_flight, __ATOMIC_RELAXED);

	while (old < MAX_CONCURRENT_NEWNET) {
		if (__atomic_compare_exchange_n(&shm->newnet_in_flight,
						&old, old + 1,
						false,
						__ATOMIC_RELAXED,
						__ATOMIC_RELAXED))
			return true;
		/* CAS failure refreshed `old` with the witnessed value;
		 * loop re-checks the cap against the fresh observation. */
	}
	return false;
}

/*
 * Single-RMW ticket release.  Atomically clears NEWNET_INFLIGHT_TICKET
 * on rec->post_state and decrements shm->newnet_in_flight iff the bit
 * was set on entry.  Idempotent: a second caller racing in observes
 * the bit already cleared and skips the decrement.
 *
 * The race this guards against is raw clone()/clone3(): the kernel
 * returns in both the calling task and the newly created one, the
 * syscallrecord lives in shared memory (children[] -> alloc_shared),
 * and both branches run the post hook against the same post_state.
 * A plain check-then-clear-then-decrement lets both branches decrement
 * for one admission, drifting the counter toward negative and
 * permanently disabling the cap.
 *
 * post_state for clone3 carries the args pointer in the high bits;
 * fetch_and(~NEWNET_INFLIGHT_TICKET) clears only bit 0 and leaves
 * the pointer intact for the post handler's downstream
 * deferred_freeptr().
 */
static inline void release_newnet_ticket(struct syscallrecord *rec)
{
	unsigned long old = __atomic_fetch_and(&rec->post_state,
					       ~NEWNET_INFLIGHT_TICKET,
					       __ATOMIC_RELAXED);

	if (old & NEWNET_INFLIGHT_TICKET)
		__atomic_fetch_sub(&shm->newnet_in_flight, 1,
				   __ATOMIC_RELAXED);
}

/*
 * Global pointer to the children array.  Lives in normal data segment
 * (NOT in shm), so each forked process gets its own COW copy.  A stray
 * child write to this pointer corrupts only that one child's copy and
 * cannot zero out the pointer for parent or siblings.  The pointed-to
 * array is mprotected PROT_READ in init_shm() so its contents are
 * also protected.
 */
extern struct childdata **children;

/*
 * Canary copy of each child's fd_event_ring pointer, taken at init time
 * so wild-write damage to the per-child ring pointer can be detected.
 * fd_event_drain_all() compares the live pointer against this array;
 * a mismatch means the pointer was overwritten after init, and we use
 * the known-good value to keep draining while logging the incident.
 */
extern struct fd_event_ring **expected_fd_event_rings;
