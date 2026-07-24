/*
 * Final per-child runtime configuration: kcov bring-up, uniarch
 * active-syscalls pin, explorer-pool slot flag, the A/B-comparison
 * cohort stamps, then post-setup hygiene (heap-bounds re-snapshot,
 * RLIMIT_AS pin, one-shot disable_coredumps).  Split out of
 * child-init.c so make -j can compile the runtime-config phase
 * concurrently with the clean / freeze / isolate / sandbox setup
 * helpers.
 *
 * The internal step helpers (init_child_runtime_basics,
 * init_child_ab_stamps, init_child_finalize) stay static -- only
 * init_child_runtime_config calls them and all four live here.
 * init_child_runtime_config sheds its static linkage so init_child
 * (still in child-init.c during the carve) can call it across the
 * new TU boundary; declaration added to include/child-internal.h.
 * TRINITY_CHILD_AS_CAP_BYTES moves too -- init_child_finalize is
 * the only reader of the macro.
 */

#include <errno.h>
#include <malloc.h>
#include <signal.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/personality.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/capability.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "arch.h"
#include "child.h"
#include "child-internal.h"
#include "fd.h"
#include "futex.h"
#include "fd-event.h"
#include "kcov.h"
#include "maps.h"
#include "minicorpus.h"
#include "objects.h"
#include "params.h"
#include "pids.h"
#include "pre_crash_ring.h"
#include "random.h"
#include "rnd.h"
#include "self_cgroup.h"
#include "shm.h"
#include "signals.h"
#include "stats.h"
#include "stats_ring.h"
#include "syscall.h"
#include "trinity.h"	// ARRAY_SIZE
#include "writer-watch.h"
#include "uid.h"
#include "utils.h"	// zmalloc

#include "kernel/sched.h"
/*
 * Hard per-child virtual-memory cap.  A single runaway mmap/mremap (or the
 * cumulative drift of N children each growing to multi-GiB) can push the
 * machine into global OOM; with memory.oom.group on the user slice that
 * takes out the whole login session (tmux, ssh, the lot).  Pushing past
 * the cap returns ENOMEM at the syscall — itself a fuzz-relevant kernel
 * return path.
 *
 * Sized at 4 GiB.  An earlier 1 GiB cap was below the ~2 GB virtual-memory
 * baseline children inherit at fork(), so kcov_init_child()'s trace_buf
 * mmap (and several childops' init mappings — userfaultfd, iommufd,
 * landlock, pagecache, perf, seccomp-notif) silently EFAULTed; KCOV
 * stayed inactive and recorded zero edges.  4 GiB clears the inherited
 * baseline plus trinity's own fixed-cost mappings (~100 MB of childop
 * init plus a few MB of KCOV buffers) with multi-GiB of headroom for
 * fuzz-driven mmap growth, while still cutting the observed 21 TB
 * single-child runaway by ~5000x.  RLIMIT_AS bounds reserved virtual
 * memory, not RSS — 16 children × 4 GiB = 64 GiB of address-space
 * ceiling, but the bulk stays unmapped and never touches physical RAM.
 */
#define TRINITY_CHILD_AS_CAP_BYTES	(4UL << 30)

/*
 * Per-child kcov state and slot-role identity that downstream A/B and
 * dispatch paths read: kcov fd / buffers, local_stats staging,
 * uniarch active-syscalls pointer, explorer-pool slot flag.
 */
static void init_child_runtime_basics(struct childdata *child, int childno)
{
	kcov_init_child(&child->kcov, child->num);

	/* Per-child staging buffer for the kcov global counters.  calloc
	 * post-fork keeps the allocation child-private (matches kc->dedup);
	 * an alloc failure leaves the pointer NULL and the bumper / flush
	 * paths gate on local_stats != NULL. */
	child->local_stats = calloc(1, sizeof(*child->local_stats));

	/* Uniarch: pin the active-syscalls pointer once.  Biarch leaves
	 * this NULL — the first choose_syscall_table call refreshes it. */
	if (!biarch)
		child->active_syscalls = shm->active_syscalls;

	/* Stamp the explorer-pool flag based on this child's slot index.
	 * Layout: dedicated alt-op slots come first [0, alt_op_children),
	 * explorer slots follow [alt_op_children, alt_op_children +
	 * explorer_children), and the remainder runs the default/bandit
	 * mix.  Keeping the partitions disjoint stops --strategy=bandit
	 * --alt-op-children=N from silently consuming the explorer
	 * baseline.  Both clamps run before the first fork
	 * (clamp_default_explorer_children() in trinity.c) so a single
	 * read here suffices for the child's lifetime. */
	child->is_explorer = (childno >= 0 &&
			      (unsigned int)childno >= alt_op_children &&
			      (unsigned int)childno < alt_op_children + explorer_children);
}

/*
 * Per-child A/B-comparison coin flips for the various experiment
 * cohorts.  Each row stamps one boolean field at fork (rather than
 * rolling per-call) so per-window deltas of the arm counters can be
 * cleanly attributed to a population split that doesn't drift with
 * time-of-day environmental noise.  Rows whose harvest side population-
 * normalises also bump the matching arm-A / arm-B child counter on the
 * relevant shm region.  The axes are stamped independently so they can
 * cross without confounding each other's cohort comparisons.
 */
static void init_child_ab_stamps(struct childdata *child)
{
	/* CMP RedQueen greedy re-exec A/B-comparison stamp.  Only CMP-mode
	 * children produce CMP attribution in the first place (PC-mode kcov
	 * never enables the cmp fd, so kcov_collect_cmp short-circuits), so
	 * stamping false on PC-mode children loses no signal.  Within the
	 * CMP-mode pool, half the children get the re-exec and half are the
	 * control arm -- subsequent reexec_* per-window deltas can be
	 * cleanly attributed to the enabled cohort because the disabled
	 * cohort's gate at the dispatch_step tail short-circuits.  Per-child
	 * stamp at fork rather than a runtime flag means time-of-day
	 * environmental drift (kernel state, mounted fs population, other
	 * system load) is common to both arms and falls out of the
	 * comparison. */
	child->redqueen_enabled = (child->kcov.mode == KCOV_MODE_CMP) && ONE_IN(2);

	/* Plateau burst per-call drain-cap A/B stamp.  Independent axis from
	 * redqueen_enabled so an arm-A control child (drain-all-baseline)
	 * and an arm-B measure child (drain-K-during-plateau) can be paired
	 * inside either redqueen cohort; the burst path itself still gates on
	 * redqueen_enabled at the dispatch_step tail so a burst_drain_arm_b
	 * child that lost the redqueen dice never actually bursts.  Stamped
	 * unconditionally: the flag is moot for children who won't ever reach
	 * a CMP_RISING_PC_FLAT plateau (short-lived children, PC-mode kcov),
	 * but the ONE_IN(2) draw stays uniform across the population so the
	 * arm split is directly readable from any subsequent burst-drain
	 * observability slice. */
	child->burst_drain_arm_b = ONE_IN(2);

	/* Cmp-hint baseline inject denom A/B-comparison stamp.  Half the
	 * children get Arm B (the more aggressive 1-in-12 baseline rate);
	 * the rest stay on Arm A (the historical 1-in-16 baseline).  Stamped
	 * at fork rather than rolled per-call so per-window deltas of the
	 * arm-B fire / divergence counters can be cleanly attributed to a
	 * population split that doesn't drift with time-of-day environmental
	 * noise.  Independent of kcov.mode (PC and CMP children both
	 * participate) -- the baseline cmp-hint injection helpers fire
	 * regardless of the per-child KCOV mode, so gating the A/B split on
	 * the mode would shrink the sample without any matching reduction in
	 * the signal we're measuring. */
	child->cmp_hint_inject_arm_b = ONE_IN(2);
	if (kcov_shm != NULL) {
		if (child->cmp_hint_inject_arm_b)
			__atomic_fetch_add(&kcov_shm->cohorts.cmp_inject_arm_b_children,
					   1U, __ATOMIC_RELAXED);
		else
			__atomic_fetch_add(&kcov_shm->cohorts.cmp_inject_arm_a_children,
					   1U, __ATOMIC_RELAXED);
	}
	/* A/B-comparison stamp for the cmp_hints substitution-pool
	 * "uninteresting constant" drop mask.  Independent of the
	 * redqueen_enabled stamp -- the two A/B axes need to cross so
	 * neither cohort comparison gets confounded by the other.  Stamped
	 * unconditionally (PC-mode children never reach the cmp_hints
	 * collect path so the stamp is moot for them, but stamping anyway
	 * keeps the field semantics uniform with redqueen_enabled and
	 * avoids a mode-conditional read at the harvest site). */
	child->boring_filter_arm_b = ONE_IN(2);

	/* A/B-comparison stamp for the frontier_cold_weight blend
	 * promotion.  Independent of redqueen_enabled / boring_filter_arm_b
	 * / cmp_hint_inject_arm_b so the four A/B axes can cross without
	 * confounding each other's cohort comparisons.  Stamped
	 * unconditionally (the frontier picker reads this through
	 * frontier_cold_weight, which is invoked only under the
	 * STRATEGY_COVERAGE_FRONTIER picker path; the stamp is moot in
	 * runs that never enter that strategy but stamping anyway keeps
	 * the field semantics uniform with the other A/B stamps). */
	child->frontier_blend_arm_b = ONE_IN(2);
	if (kcov_shm != NULL) {
		if (child->frontier_blend_arm_b)
			__atomic_fetch_add(&kcov_shm->cohorts.frontier_blend_arm_b_children,
					   1U, __ATOMIC_RELAXED);
		else
			__atomic_fetch_add(&kcov_shm->cohorts.frontier_blend_arm_a_children,
					   1U, __ATOMIC_RELAXED);
	}

	/* A/B-comparison stamp for the errno-plateau decay at the coverage-
	 * frontier picker's silent-regime accept site.  Independent of the
	 * other A/B axes so the cohort comparisons stay un-confounded; same
	 * unconditional stamp + ONE_IN(2) cohort split + per-arm child count
	 * shape as frontier_blend_arm_b above so the population-normalisation
	 * pattern stays uniform across the frontier-side A/B rows. */
	child->frontier_errno_decay_arm_b = ONE_IN(2);
	if (kcov_shm != NULL) {
		if (child->frontier_errno_decay_arm_b)
			__atomic_fetch_add(&kcov_shm->cohorts.frontier_errno_decay_arm_b_children,
					   1U, __ATOMIC_RELAXED);
		else
			__atomic_fetch_add(&kcov_shm->cohorts.frontier_errno_decay_arm_a_children,
					   1U, __ATOMIC_RELAXED);
	}

	/* A/B-comparison stamp for the silent-streak decay at the coverage-
	 * frontier picker's silent-regime accept site.  Independent of the
	 * sibling frontier_errno_decay_arm_b above so the two decay-axis
	 * cohort comparisons stay un-confounded; same unconditional stamp +
	 * ONE_IN(2) cohort split + per-arm child count shape as
	 * frontier_errno_decay_arm_b above so the population-normalisation
	 * pattern stays uniform across the frontier-side A/B rows. */
	child->frontier_silent_decay_arm_b = ONE_IN(2);
	if (kcov_shm != NULL) {
		if (child->frontier_silent_decay_arm_b)
			__atomic_fetch_add(&kcov_shm->cohorts.frontier_silent_decay_arm_b_children,
					   1U, __ATOMIC_RELAXED);
		else
			__atomic_fetch_add(&kcov_shm->cohorts.frontier_silent_decay_arm_a_children,
					   1U, __ATOMIC_RELAXED);
	}

	/* A/B-comparison stamp for the adaptive remote-KCOV mode decision in
	 * dispatch_step.  Independent of the other A/B axes so the cohort
	 * comparisons stay un-confounded; same unconditional stamp +
	 * ONE_IN(2) cohort split + per-arm child count shape as
	 * frontier_blend_arm_b above so the population-normalisation pattern
	 * stays uniform across the A/B rows.  The shadow disposition counters
	 * bump in lock-step from both arms, so the stamp is meaningful even
	 * on Arm A (the would-be divergence stays observable across the
	 * control cohort). */
	child->remote_adaptive_arm_b = ONE_IN(2);
	if (kcov_shm != NULL) {
		if (child->remote_adaptive_arm_b)
			__atomic_fetch_add(&kcov_shm->cohorts.remote_adaptive_arm_b_children,
					   1U, __ATOMIC_RELAXED);
		else
			__atomic_fetch_add(&kcov_shm->cohorts.remote_adaptive_arm_a_children,
					   1U, __ATOMIC_RELAXED);
	}

	/* A/B-comparison stamp for the prop_ring injection at handle_arg_op's
	 * ARG_OP callsite.  Independent of redqueen_enabled / boring_filter_
	 * arm_b / cmp_hint_inject_arm_b / frontier_blend_arm_b so the five A/B
	 * axes can cross without confounding each other's cohort comparisons.
	 * Stamped unconditionally (the ARG_OP callsite fires on any syscall
	 * argument whose argtype is ARG_OP regardless of KCOV mode -- gating
	 * the stamp on the mode would shrink the sample without any matching
	 * reduction in the signal we're measuring). */
	child->prop_ring_argop_arm_b = ONE_IN(2);
	if (kcov_shm != NULL) {
		if (child->prop_ring_argop_arm_b)
			__atomic_fetch_add(&kcov_shm->cohorts.prop_ring_argop_arm_b_children,
					   1U, __ATOMIC_RELAXED);
		else
			__atomic_fetch_add(&kcov_shm->cohorts.prop_ring_argop_arm_a_children,
					   1U, __ATOMIC_RELAXED);
	}

	/* A/B-comparison stamp for the SHADOW structure-aware arm picker in
	 * mutate_arg (weighted_pick_case_shadow_structured()'s doubled-pool
	 * draw).  Independent of redqueen_enabled / boring_filter_arm_b /
	 * cmp_hint_inject_arm_b / frontier_blend_arm_b / prop_ring_argop_arm_b
	 * so the six A/B axes can cross without confounding each other's
	 * cohort comparisons.  Stamped unconditionally (mutate_arg runs on
	 * every replayed call regardless of KCOV mode -- gating the stamp on
	 * the mode would shrink the sample without any matching reduction in
	 * the signal we're measuring). */
	child->mut_structured_arm_b = ONE_IN(2);
	if (minicorpus_shm != NULL) {
		if (child->mut_structured_arm_b)
			__atomic_fetch_add(&minicorpus_shm->mut_structured_arm_b_children,
					   1U, __ATOMIC_RELAXED);
		else
			__atomic_fetch_add(&minicorpus_shm->mut_structured_arm_a_children,
					   1U, __ATOMIC_RELAXED);
	}

	/* A/B-comparison stamp for the typed prop_ring consumer rows at
	 * the gen_arg_* callsites.  Independent of all preceding A/B
	 * stamps so the axes can cross without confounding each other's
	 * cohort comparisons.  Stamped unconditionally (the gen_arg_*
	 * callsites fire on any syscall whose argtype matches regardless
	 * of KCOV mode -- gating the stamp on the mode would shrink the
	 * sample without any matching reduction in the signal we're
	 * measuring). */
	child->prop_ring_typed_arm_b = ONE_IN(2);
	if (kcov_shm != NULL) {
		if (child->prop_ring_typed_arm_b)
			__atomic_fetch_add(&kcov_shm->cohorts.prop_ring_typed_arm_b_children,
					   1U, __ATOMIC_RELAXED);
		else
			__atomic_fetch_add(&kcov_shm->cohorts.prop_ring_typed_arm_a_children,
					   1U, __ATOMIC_RELAXED);
	}
}

/*
 * Post-setup hygiene and per-lifetime pins, run last so they see the
 * steady state: re-snapshot the heap bounds, cap RLIMIT_AS for the
 * child_process() main loop, disable core dumps once.
 *
 * Order matters: heap_bounds_init must run after the prior setup has
 * materialised its arenas, and the RLIMIT_AS pin must run after
 * heap_bounds_init's fopen() so that fopen() completes under the
 * inherited RLIM_INFINITY ceiling.
 */
static void init_child_finalize(void)
{
	/*
	 * Re-snapshot /proc/self/maps now that init_child's allocator-
	 * heavy setup has settled.  Glibc spawns secondary mmap arenas
	 * on demand (per-thread, under contention, large mallocs that
	 * bypass MMAP_THRESHOLD), and the init_child_mappings / futex
	 * setup / clone_global_objects_to_child / kcov_init_child path
	 * generates enough allocator traffic to materialise arenas that
	 * the parent's pre-fork snapshot doesn't know about.  Without
	 * this refresh, a fuzzed pointer landing in a post-fork arena
	 * passes range_overlaps_libc_heap() and the kernel scribbles
	 * glibc chunk metadata -- the corruption surfaces later as an
	 * arena abort with no obvious proximate cause.  Runs before the
	 * RLIMIT_AS pin so the fopen()'s small allocation completes
	 * under the inherited RLIM_INFINITY ceiling.
	 */
	heap_bounds_init();

	/*
	 * Pin RLIMIT_AS as the LAST thing init_child does, just before the
	 * child_process() main loop takes over.  Applied here — not back at
	 * setsid() time — so the inherited ~2 GB virtual-memory baseline,
	 * init_child_mappings()'s per-child mmaps, kcov_init_child()'s
	 * trace_buf + cmp_buf mmaps, and the various childop init mappings
	 * (userfaultfd, iommufd, landlock, pagecache, perf, seccomp-notif)
	 * all complete under the inherited RLIM_INFINITY ceiling.  Only
	 * fuzz-driven mmap growth from the syscall loop is bound by the cap;
	 * trinity's fixed-cost setup doesn't get silently EFAULTed by it.
	 *
	 * Deterministic — not folded into the random rlim_resources sweep in
	 * munge_process(), which is for fuzz diversity and gets randomly
	 * skipped.  munge_process() ran above us and may have tightened other
	 * limits, but its sweep only ever shrinks them, so running it before
	 * the cap is set is safe.  Both rlim_cur and rlim_max are clamped to
	 * the cap so a fuzzed setrlimit() in the child can't widen it back to
	 * RLIM_INFINITY.
	 *
	 * Skipped under ASAN: the address sanitizer reserves 32-512 GiB of
	 * virtual address space for its shadow memory, far above the 4 GiB
	 * cap.  Without this skip every child's first mmap fails and the run
	 * dies before main_loop with "ERROR: Failed to mmap" in every child
	 * log.  ASAN runs are debug builds where catching the bug matters
	 * more than bounding virtual memory.
	 */
#ifndef __SANITIZE_ADDRESS__
	{
		struct rlimit as_lim = {
			.rlim_cur = TRINITY_CHILD_AS_CAP_BYTES,
			.rlim_max = TRINITY_CHILD_AS_CAP_BYTES,
		};
		if (setrlimit(RLIMIT_AS, &as_lim) != 0)
			perror("setrlimit(RLIMIT_AS)");
	}
#endif

	/*
	 * Disable core dumps once for the child's lifetime.  Previously
	 * bracketed every loop iteration, but in non-debug builds that's
	 * four syscalls per iter (~90K/sec fleet-wide) all restoring the
	 * same steady-state values.  Debug mode still brackets per-iter
	 * via the shm->debug gate at the loop call sites; disable_coredumps()
	 * here takes the debug path too (DUMPABLE=1, RLIM_INFINITY) which
	 * matches the per-iter behaviour.
	 */
	disable_coredumps();
}

/*
 * Final phase of init_child: wire up runtime config that the
 * child_process() main loop relies on, then pin the per-lifetime
 * limits / dumpable state.  Six steps:
 *
 *   - kcov_init_child sets up the per-child coverage buffers,
 *   - the active-syscalls pointer is pinned for the uniarch case
 *     (biarch refreshes it lazily on the first picker call),
 *   - the explorer-pool slot flag is stamped from the child's
 *     slot index within the partition layout,
 *   - heap_bounds_init re-snapshots /proc/self/maps after the
 *     allocator-heavy setup above has settled,
 *   - RLIMIT_AS is pinned (skipped under ASAN whose shadow memory
 *     reservation would otherwise blow the cap),
 *   - disable_coredumps takes the debug-equivalent path once for
 *     the child's lifetime.
 *
 * Order matters: heap_bounds_init must run after the prior setup
 * has materialised its arenas, and the RLIMIT_AS pin must run
 * after heap_bounds_init's fopen() so that fopen() completes
 * under the inherited RLIM_INFINITY ceiling.
 */
void init_child_runtime_config(struct childdata *child, int childno)
{
	init_child_runtime_basics(child, childno);
	init_child_ab_stamps(child);
	init_child_finalize();
}
