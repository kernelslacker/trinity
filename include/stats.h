#pragma once

#include <stdint.h>
#include "child.h"	/* NR_CHILD_OP_TYPES */
#include "syscall.h"	/* MAX_NR_SYSCALL */

/*
 * Adaptive-budget tunables for childop_budget_mult[] / adapt_budget().
 * Q8.8 fixed point: 256 == 1.0x.  Floor and ceiling cap how far the
 * runtime feedback loop can shift any one op away from its hard-coded
 * MAX_ITERATIONS / BUDGET_NS — at the floor a 64-iter op still runs 16
 * iters per invocation, at the ceiling it runs 256.
 */
#define ADAPT_BUDGET_UNITY	256	/* 1.0x */
#define ADAPT_BUDGET_MIN	64	/* 0.25x */
#define ADAPT_BUDGET_MAX	1024	/* 4.0x */

/*
 * Edge-delta floor that classifies an invocation as productive.  Reads
 * the GLOBAL kcov_shm->edges_found counter, so a fleet running with N
 * children adds baseline noise on every dispatch — the threshold has to
 * sit clear of the noise floor or every op gets boosted just by being
 * invoked while siblings are productive.  16 is calibrated for the
 * default fleet size; for very large fleets the noise floor may rise
 * above this value and the boost ratchet effectively stalls (which is
 * the safer failure mode — multipliers stay near 1.0x and behaviour
 * matches the pre-CV.13 fixed budgets).
 */
#define ADAPT_BUDGET_THRESHOLD	16

/*
 * Consecutive sub-threshold invocations required before the shrink
 * ratchet fires.  Hysteresis: a single noisy zero-delta invocation in
 * the middle of a productive streak should not halve the budget.
 */
#define ADAPT_BUDGET_ZERO_STREAK	4

/* Upper bound on the recipe_runner catalog size.  recipe-runner.c
 * asserts at startup that its table fits.  Sized large enough to
 * accommodate future recipes without reshuffling shared memory. */
#define MAX_RECIPES 36

/* Upper bound on the iouring_recipes catalog.  iouring-recipes.c asserts
 * at build time that its table fits. */
#define MAX_IOURING_RECIPES 32

/* Number of distinct slab classes the slab_cache_thrash childop targets,
 * one entry per enum slab_target in childops/slab-cache-thrash.c.  Sized
 * here (rather than in the childop) so the per-target run counter array
 * can live inside struct stats_s.  A static_assert in slab-cache-thrash.c
 * fails the build if the two ever drift. */
#define NR_SLAB_TARGETS 7

/* Coarse syscall categories used by the dispatch-time histogram.  Order
 * is also the dump order; SYSCAT_OTHER is the catch-all for anything not
 * matched by the prefix table in stats.c. */
enum syscall_category {
	SYSCAT_READ = 0,
	SYSCAT_WRITE,
	SYSCAT_OPEN,
	SYSCAT_MMAP,
	SYSCAT_SOCKET,
	SYSCAT_PROCESS,
	SYSCAT_FILE,
	SYSCAT_IPC,
	SYSCAT_OTHER,
	NR_SYSCAT,
};

/* Various statistics.
 *
 * Fields are grouped by access pattern with cacheline padding between
 * groups so that one child's writes to a low-frequency counter do not
 * invalidate the cacheline a sibling is bumping for op_count on every
 * syscall.  At 32 children all incrementing different fields packed
 * into the same cacheline the resulting MESI traffic absorbs a large
 * fraction of fleet syscall throughput; reshaping into the four groups
 * below isolates the hot fast path from the rare-condition counters
 * and the per-childop / parent-side bookkeeping.
 *
 * Group A (hot per-syscall): bumped on every syscall by every child.
 *   Kept first so it lands on the cacheline shm_s already aligns
 *   stats to.  Deliberately small — successive counters a child
 *   touches in a single dispatch_step() should ideally hit the same
 *   line on that child's L1 even if siblings invalidate it.
 *
 * Group B (per-syscall but rare-condition): on the syscall path but
 *   only bumped when an oracle anomaly fires or a corrupted pointer
 *   is detected — most syscalls touch nothing in this group.
 *
 * Group C (per-childop): bumped per childop invocation, which is
 *   orders of magnitude less frequent than per-syscall.
 *
 * Group D (diagnostic / startup / parent-side / one-shot): mostly
 *   parent-bumped or written rarely; kept apart so child writes in
 *   groups A-C never invalidate the parent's line and vice versa.
 */

struct stats_s {
	/* ---- Group A: hot per-syscall ---- */
	unsigned long op_count;
	unsigned long successes;
	unsigned long failures;

	/* Fault injection (/proc/self/fail-nth):
	 *   fault_injected  — number of syscalls we armed fail-nth for
	 *   fault_consumed  — subset that returned -ENOMEM, i.e. the fault
	 *                     actually triggered an allocation failure */
	unsigned long fault_injected;
	unsigned long fault_consumed;

	/* avoid_shared_buffer() caught an output-buffer syscall arg whose
	 * address overlapped one of trinity's alloc_shared() regions and
	 * rewrote it to a non-shared address.  A non-zero count means the
	 * arg-generation path is producing pointers into our own shared
	 * state — without this redirect the kernel would write the syscall
	 * result on top of trinity bookkeeping. */
	unsigned long shared_buffer_redirected;

	/* range_overlaps_shared() rejected an addr/len because it overlapped
	 * one of trinity's tracked alloc_shared regions.  Tells you whether
	 * the wild-write defense is doing meaningful work or trivially
	 * bypassing every input. */
	unsigned long range_overlaps_shared_rejects;

	/* Per-syscall reject counts indexed by syscall.nr, bumped from the
	 * range_overlaps_shared() trip site so dump_stats() can name the top
	 * offenders.  Two arrays so 32/64-bit syscall numbers don't smear
	 * (same nr means a different syscall on each table). */
	unsigned long range_overlaps_shared_rejects_per_syscall_64[MAX_NR_SYSCALL];
	unsigned long range_overlaps_shared_rejects_per_syscall_32[MAX_NR_SYSCALL];

	/* Coarse-grained histogram of which syscall categories the random
	 * picker has been dispatching, bumped per syscall in dispatch_step().
	 * Lets the operator spot when sanitiser/group-bias drift has skewed
	 * the distribution away from the table they expected. */
	unsigned long syscall_category_count[NR_SYSCAT];

	/* ---- Group B: per-syscall, rare-condition ---- */

	/* post-syscall oracle anomaly counts */
	unsigned long fd_oracle_anomalies __attribute__((aligned(64)));
	unsigned long mmap_oracle_anomalies;
	unsigned long cred_oracle_anomalies;
	unsigned long sched_oracle_anomalies;
	unsigned long uid_oracle_anomalies;
	unsigned long gid_oracle_anomalies;
	unsigned long setgroups_oracle_anomalies;
	unsigned long getegid_oracle_anomalies;
	unsigned long getuid_oracle_anomalies;
	unsigned long getgid_oracle_anomalies;
	unsigned long getppid_oracle_anomalies;
	unsigned long getcwd_oracle_anomalies;
	unsigned long getpid_oracle_anomalies;
	unsigned long getpgid_oracle_anomalies;
	unsigned long getpgrp_oracle_anomalies;
	unsigned long geteuid_oracle_anomalies;
	unsigned long getsid_oracle_anomalies;
	unsigned long gettid_oracle_anomalies;
	unsigned long setsid_oracle_anomalies;
	unsigned long setpgid_oracle_anomalies;
	unsigned long sched_getscheduler_oracle_anomalies;
	unsigned long getgroups_oracle_anomalies;
	unsigned long getresuid_oracle_anomalies;
	unsigned long getresgid_oracle_anomalies;
	unsigned long umask_oracle_anomalies;
	unsigned long sched_get_priority_max_oracle_anomalies;
	unsigned long sched_get_priority_min_oracle_anomalies;
	unsigned long sched_yield_oracle_anomalies;
	unsigned long getpagesize_oracle_anomalies;
	unsigned long time_oracle_anomalies;
	unsigned long gettimeofday_oracle_anomalies;
	unsigned long newuname_oracle_anomalies;
	unsigned long rt_sigpending_oracle_anomalies;
	unsigned long sched_getaffinity_oracle_anomalies;
	unsigned long rt_sigprocmask_oracle_anomalies;
	unsigned long sched_getparam_oracle_anomalies;
	unsigned long sched_rr_get_interval_oracle_anomalies;
	unsigned long get_robust_list_oracle_anomalies;
	unsigned long getrlimit_oracle_anomalies;
	unsigned long sysinfo_oracle_anomalies;
	unsigned long times_oracle_anomalies;
	unsigned long clock_getres_oracle_anomalies;
	unsigned long capget_oracle_anomalies;
	unsigned long newlstat_oracle_anomalies;
	unsigned long newstat_oracle_anomalies;
	unsigned long newfstat_oracle_anomalies;
	unsigned long newfstatat_oracle_anomalies;
	unsigned long statx_oracle_anomalies;
	unsigned long fstatfs_oracle_anomalies;
	unsigned long fstatfs64_oracle_anomalies;
	unsigned long statfs_oracle_anomalies;
	unsigned long statfs64_oracle_anomalies;
	unsigned long uname_oracle_anomalies;
	unsigned long lsm_list_modules_oracle_anomalies;
	unsigned long listmount_oracle_anomalies;
	unsigned long statmount_oracle_anomalies;
	unsigned long getsockname_oracle_anomalies;
	unsigned long getpeername_oracle_anomalies;
	unsigned long file_getattr_oracle_anomalies;
	unsigned long sched_getattr_oracle_anomalies;
	unsigned long getrusage_oracle_anomalies;
	unsigned long sigpending_oracle_anomalies;
	unsigned long getcpu_oracle_anomalies;
	unsigned long clock_gettime_oracle_anomalies;
	unsigned long get_mempolicy_oracle_anomalies;
	unsigned long lsm_get_self_attr_oracle_anomalies;
	unsigned long prlimit64_oracle_anomalies;
	unsigned long sigaltstack_oracle_anomalies;
	unsigned long olduname_oracle_anomalies;
	unsigned long lookup_dcookie_oracle_anomalies;
	unsigned long getxattr_oracle_anomalies;
	unsigned long lgetxattr_oracle_anomalies;
	unsigned long fgetxattr_oracle_anomalies;
	unsigned long listxattrat_oracle_anomalies;
	unsigned long flistxattr_oracle_anomalies;
	unsigned long listxattr_oracle_anomalies;
	unsigned long llistxattr_oracle_anomalies;
	unsigned long readlink_oracle_anomalies;
	unsigned long readlinkat_oracle_anomalies;
	unsigned long sysfs_oracle_anomalies;

	/* A post handler caught a pid-scribbled / canonical-out-of-range /
	 * misaligned value in rec->aN (or a struct reachable from it) and
	 * refused to deref or free it.  Bumped by both the per-handler
	 * looks_like_corrupted_ptr() guards and the central guard inside
	 * deferred_free_enqueue().  Non-zero means cluster-1/2/3 scribbles
	 * are still landing in rec-> memory -- the post-handler guard is
	 * doing its job and converting would-be SIGSEGVs into a counter. */
	unsigned long post_handler_corrupt_ptr;

	/* deferred_free_enqueue() saw a pointer that passed the pid-shape
	 * heuristic but landed outside the cached brk arena -- can't be a
	 * real __zmalloc() result.  Defense-in-depth alongside the live-
	 * malloc ring: catches the case where a wholesale stomp scribbles
	 * a snapshot/arg slot with a value pointing into the stack, an
	 * mmap'd library, an executable mapping, or one of trinity's own
	 * MAP_PRIVATE regions.  The ground-truth alloc-track ring catches
	 * heap-region values that weren't malloc'd; this counter catches
	 * non-heap values entirely.  Non-zero means rec-> stomps are
	 * still landing -- the validator converted what would have been
	 * a libc free()-on-non-heap (ASAN bad-free, or silent allocator
	 * corruption on non-ASAN builds) into a counter bump. */
	unsigned long snapshot_non_heap_reject;

	/* deferred_free_tick() saw a sub-page (pid-shaped) pointer in a
	 * ring slot and refused to call free() on it.  Non-zero means the
	 * mprotect guard around the ring is being bypassed somehow, or
	 * the corruption happened before the guard was active. */
	unsigned long deferred_free_corrupt_ptr;

	/* handle_syscall_ret() found rec->_canary != REC_CANARY_MAGIC on
	 * entry — the entire syscallrecord was rewritten between BEFORE
	 * and AFTER, including bookkeeping fields the per-arg snapshot
	 * pattern can't shadow.  Distinct from post_handler_corrupt_ptr,
	 * which only catches scribbled rec->aN pointer slots: a wholesale
	 * stomp from a sibling value-result syscall whose buffer aliased
	 * the rec lands here without tripping the snapshot guards.  Bumped
	 * informationally; the child does NOT abort, since the call has
	 * already returned and the mismatched data is past being trusted
	 * anyway.  See pre_crash_ring entry kind PRE_CRASH_KIND_CANARY for
	 * the matching context capture. */
	unsigned long rec_canary_stomped;

	/* init_child()'s sibling-freeze step issues mprotect(PROT_READ) on
	 * every other child's childdata (and on the shared pids[] array) so
	 * a value-result syscall buffer in one sibling can't scribble over
	 * another sibling's rec->aN.  Each mprotect can fail with -ENOMEM
	 * if the kernel hits a per-mm VMA-count or address-space limit
	 * while splitting the existing mapping.  A non-zero count means at
	 * least one freeze step silently left a sibling's childdata (or
	 * pids[]) writable -- the cross-child scribble vector that the
	 * post-handler / snapshot guards exist to defend against is open
	 * for that sibling pair.  We don't abort the child on a single
	 * failure (best-effort hardening), but the counter lets us tell
	 * whether the failure is rare or a real runtime vector. */
	unsigned long sibling_mprotect_failed;

	/* init_child() bumps shm->sibling_freeze_gen after its for_each_child
	 * mprotect loop completes; each child re-checks the gen at the top of
	 * its child_process loop and, on mismatch, re-runs the mprotect sweep
	 * to pull any newly-spawned sibling into PROT_READ.  This counter
	 * ticks once per refreeze.  Expected pattern: a burst at startup
	 * (max_children-1 refreezes per child as the fleet fills in), then
	 * occasional bumps as replace_child() respawns dead slots.  A
	 * runaway count (e.g. tens of refreezes per second long after
	 * startup) would indicate constant child churn — useful signal when
	 * paired with reaper / SEGV stats. */
	unsigned long sibling_refreeze_count;

	/* periodic_work re-issues a curated set of "should be deterministic
	 * across short windows" syscalls (uname, sysinfo, getrlimit/prlimit64
	 * RLIMIT_NOFILE, sched_getparam(0)) and compares the result against
	 * the previous tick's reading cached in childdata.sentinel_prev.  Any
	 * divergence outside the expected drift fields (loads/uptime/freeram
	 * et al. are excluded) is the fingerprint of a fuzzed value-result
	 * syscall buffer scribbling the cached struct or a kernel-managed
	 * datum: a wild write into the cache surfaces as the live re-read
	 * disagreeing with what we captured previously, and a wild write into
	 * the kernel-managed copy surfaces the same way from the other side.
	 * Bumped per diverging field, so a single sample with multi-field
	 * corruption contributes more than one to the count -- intentional,
	 * to amplify multi-field clobbers above noise from singleton drifts. */
	unsigned long divergence_sentinel_anomalies;

	/* Childop taint-watcher: count of times a /proc/sys/kernel/tainted
	 * bit transition was observed across a non-syscall childop dispatch,
	 * indexed by enum child_op_type.  Surfaces soft taints (lockdep WARN,
	 * RCU stall, reckless module load, etc.) tied to a specific childop
	 * even when no oops is raised.  RELAXED add-fetch: the counter is a
	 * coarse anomaly indicator, not a precise event log — the matching
	 * pre_crash_ring entry holds the full per-event context. */
	unsigned long taint_transitions[NR_CHILD_OP_TYPES];

	/* ---- Group C: per-childop ---- */

	/* procfs_writer childop: per-tree write counts */
	unsigned long procfs_writes __attribute__((aligned(64)));
	unsigned long sysfs_writes;
	unsigned long debugfs_writes;

	/* memory_pressure childop: MADV_PAGEOUT + refault cycles */
	unsigned long memory_pressure_runs;

	/* sched_cycler childop counters */
	unsigned long sched_cycler_runs;	/* total sched_cycler invocations */
	unsigned long sched_cycler_eperm;	/* sched_setattr denied (no CAP_SYS_NICE) */

	/* userns_fuzzer childop counters */
	unsigned long userns_runs;		/* total userns_fuzzer invocations */
	unsigned long userns_inner_crashed;	/* inner child died by signal */
	unsigned long userns_unsupported;	/* CLONE_NEWUSER refused, noop path */

	/* barrier_racer childop counters */
	unsigned long barrier_racer_runs;	/* total barrier_racer invocations */
	unsigned long barrier_racer_inner_crashed; /* inner worker died by signal */

	/* genetlink_fuzzer childop counters */
	unsigned long genetlink_families_discovered;	/* cumulative across children */
	unsigned long genetlink_msgs_sent;		/* successful send() to a family */
	unsigned long genetlink_eperm;			/* family rejected with EPERM/EACCES */

	/* netlink message generator: NLA_F_NESTED containers emitted */
	unsigned long netlink_nested_attrs_emitted;

	/* perf_event_chains childop counters */
	unsigned long perf_chains_runs;		/* total invocations */
	unsigned long perf_chains_groups_created;	/* group leader fd opened successfully */
	unsigned long perf_chains_ioctl_ops;	/* PERF_EVENT_IOC_* calls made */

	/* tracefs_fuzzer childop counters */
	unsigned long tracefs_kprobe_writes;		/* writes to kprobe_events */
	unsigned long tracefs_uprobe_writes;		/* writes to uprobe_events */
	unsigned long tracefs_filter_writes;		/* writes to set_ftrace_filter/notrace/graph */
	unsigned long tracefs_event_enable_writes;	/* writes to events subsystem enable files */
	unsigned long tracefs_misc_writes;		/* trace_options, current_tracer, etc. */

	/* bpf_lifecycle childop counters */
	unsigned long bpf_lifecycle_runs;		/* total bpf_lifecycle invocations */
	unsigned long bpf_lifecycle_progs_loaded;	/* successful BPF_PROG_LOAD */
	unsigned long bpf_lifecycle_verifier_rejects;	/* PROG_LOAD rejected (non-EPERM) */
	unsigned long bpf_lifecycle_attached;		/* successful attach (either combo) */
	unsigned long bpf_lifecycle_attach_failed;	/* attach syscall failed */
	unsigned long bpf_lifecycle_triggered;		/* trigger phase reached */
	unsigned long bpf_lifecycle_eperm;		/* PROG_LOAD/ATTACH denied */

	/* recipe_runner childop counters */
	unsigned long recipe_runs;		/* total recipe_runner invocations */
	unsigned long recipe_completed;		/* full sequence ran without failure */
	unsigned long recipe_partial;		/* at least one step failed */
	unsigned long recipe_unsupported;	/* discovery probe latched recipe off */

	/* fd_stress childop counters, one per stress mode */
	unsigned long fdstress_close_reopen;
	unsigned long fdstress_dup2_replace;
	unsigned long fdstress_type_confusion;
	unsigned long fdstress_cloexec_toggle;

	/* Per-recipe completion counts, indexed by the recipe's slot in the
	 * static catalog inside recipe-runner.c.  Dumped via
	 * recipe_runner_dump_stats() so stats.c stays decoupled from the
	 * catalog layout. */
	unsigned long recipe_completed_per[MAX_RECIPES];

	/* iouring_recipes childop counters */
	unsigned long iouring_recipes_runs;		/* total invocations */
	unsigned long iouring_recipes_completed;	/* recipe completed successfully */
	unsigned long iouring_recipes_partial;		/* at least one step failed */
	unsigned long iouring_recipes_enosys;		/* io_uring_setup returned ENOSYS */

	/* Per-iouring-recipe completion counts, indexed by the recipe's slot in
	 * the static catalog inside iouring-recipes.c.  Dumped via
	 * iouring_recipes_dump_stats() so stats.c stays decoupled from the
	 * catalog layout. */
	unsigned long iouring_recipe_completed_per[MAX_IOURING_RECIPES];

	/* refcount_auditor childop counters */
	unsigned long refcount_audit_runs;
	unsigned long refcount_audit_fd_anomalies;
	unsigned long refcount_audit_mmap_anomalies;
	unsigned long refcount_audit_sock_anomalies;

	/* fs_lifecycle childop counters */
	unsigned long fs_lifecycle_tmpfs;	/* tmpfs, quota, and bind variants */
	unsigned long fs_lifecycle_ramfs;	/* ramfs variant */
	unsigned long fs_lifecycle_rdonly;	/* read-only proc/sysfs traversal */
	unsigned long fs_lifecycle_overlay;	/* overlayfs variant */
	unsigned long fs_lifecycle_unsupported;	/* unshare/mount denied (EPERM) */

	/* signal_storm childop counters */
	unsigned long signal_storm_runs;	/* total signal_storm invocations */
	unsigned long signal_storm_kill;	/* kill() calls issued */
	unsigned long signal_storm_sigqueue;	/* sigqueue() calls issued */
	unsigned long signal_storm_no_targets;	/* no live siblings to signal */

	/* futex_storm childop counters */
	unsigned long futex_storm_runs;		/* total futex_storm invocations */
	unsigned long futex_storm_inner_crashed; /* inner worker died by signal */
	unsigned long futex_storm_iters;	/* cumulative inner-worker futex syscalls */

	/* pipe_thrash childop counters */
	unsigned long pipe_thrash_runs;		/* total pipe_thrash invocations */
	unsigned long pipe_thrash_pipes;	/* successful pipe()/pipe2() calls */
	unsigned long pipe_thrash_socketpairs;	/* successful socketpair() calls */
	unsigned long pipe_thrash_alloc_failed;	/* create syscall returned -1 */

	/* flock_thrash childop counters */
	unsigned long flock_thrash_runs;	/* total flock_thrash invocations */
	unsigned long flock_thrash_locks;	/* successful flock() calls */
	unsigned long flock_thrash_failed;	/* flock() returned -1 (EWOULDBLOCK/EINTR/...) */

	/* xattr_thrash childop counters */
	unsigned long xattr_thrash_runs;	/* total xattr_thrash invocations */
	unsigned long xattr_thrash_set;		/* successful set/fsetxattr calls */
	unsigned long xattr_thrash_get;		/* successful get/fgetxattr calls */
	unsigned long xattr_thrash_remove;	/* successful remove/fremovexattr calls */
	unsigned long xattr_thrash_list;	/* successful list/flistxattr calls */
	unsigned long xattr_thrash_failed;	/* any xattr syscall returned -1 */

	/* epoll_volatility childop counters */
	unsigned long epoll_volatility_runs;		/* total epoll_volatility invocations */
	unsigned long epoll_volatility_ctl_calls;	/* total epoll_ctl ADD/MOD/DEL calls (success + fail) */
	unsigned long epoll_volatility_failed;		/* epoll_ctl returned -1 (EEXIST/ENOENT/EINVAL/...) */

	/* cgroup_churn childop counters */
	unsigned long cgroup_churn_runs;	/* total cgroup_churn invocations */
	unsigned long cgroup_mkdirs;		/* successful mkdir() under /sys/fs/cgroup/ */
	unsigned long cgroup_rmdirs;		/* successful rmdir() under /sys/fs/cgroup/ */
	unsigned long cgroup_failed;		/* mkdir or rmdir returned -1 */

	/* mount_churn childop counters */
	unsigned long mount_churn_runs;		/* total mount_churn invocations */
	unsigned long mount_churn_mounts;	/* successful mount() in private ns */
	unsigned long mount_churn_umounts;	/* successful umount2() */
	unsigned long mount_churn_failed;	/* mkdir/mount/umount returned -1 */

	/* fork_storm childop counters */
	unsigned long fork_storm_runs;		/* total fork_storm invocations */
	unsigned long fork_storm_forks;		/* grandchildren successfully forked */
	unsigned long fork_storm_failed;	/* fork() returned -1 (e.g. EAGAIN) */
	unsigned long fork_storm_nested;	/* depth-1 nested forks completed */
	unsigned long fork_storm_reaped_signal;	/* grandchildren reaped that died by signal */

	/* pidfd_storm childop counters */
	unsigned long pidfd_storm_runs;		/* total pidfd_storm invocations */
	unsigned long pidfd_storm_signals;	/* successful pidfd_send_signal calls */
	unsigned long pidfd_storm_getfds;	/* successful pidfd_getfd calls */
	unsigned long pidfd_storm_failed;	/* pidfd_open/send_signal/getfd returned -1 */

	/* madvise_cycler childop counters */
	unsigned long madvise_cycler_runs;	/* total madvise_cycler invocations */
	unsigned long madvise_cycler_calls;	/* total madvise() calls issued */
	unsigned long madvise_cycler_failed;	/* madvise() returned -1 */

	/* keyring_spam childop counters */
	unsigned long keyring_spam_runs;	/* total keyring_spam invocations */
	unsigned long keyring_spam_calls;	/* total add_key/keyctl ops attempted */
	unsigned long keyring_spam_failed;	/* add_key/keyctl returned -1 */

	/* vdso_mremap_race childop counters */
	unsigned long vdso_race_runs;		/* total vdso_mremap_race invocations */
	unsigned long vdso_race_mutations;	/* mutator-side mremap/mprotect/madvise/munmap issued */
	unsigned long vdso_race_helper_segvs;	/* spinner helper killed by SIGSEGV/SIGBUS */

	/* numa_migration_churn childop counters */
	unsigned long numa_migration_runs;	/* total numa_migration_churn invocations */
	unsigned long numa_migration_calls;	/* total mbind/migrate/move/set_mempolicy calls issued */
	unsigned long numa_migration_failed;	/* migration syscall returned -1 */
	unsigned long numa_migration_no_numa;	/* attempted invocations skipped (single-node host) */

	/* cpu_hotplug_rider childop counters */
	unsigned long cpu_hotplug_runs;			/* total cpu_hotplug_rider invocations */
	unsigned long cpu_hotplug_affinity_calls;	/* sched_setaffinity/sched_setattr issued */
	unsigned long cpu_hotplug_sysfs_writes;		/* attempted writes to cpuN online file */
	unsigned long cpu_hotplug_eperm;		/* sysfs writes that hit -EACCES/-EPERM */
	unsigned long cpu_hotplug_actual_offlines;	/* real offline+online cycles (root only) */

	/* uffd_churn childop counters */
	unsigned long uffd_runs;		/* total uffd_churn invocations */
	unsigned long uffd_registers;		/* successful UFFDIO_REGISTER */
	unsigned long uffd_unregisters;		/* successful UFFDIO_UNREGISTER */
	unsigned long uffd_failed;		/* userfaultfd/UFFDIO_API/mmap/REGISTER/UNREGISTER returned -1 */

	/* iouring_flood childop counters */
	unsigned long iouring_runs;		/* total iouring_flood invocations */
	unsigned long iouring_submits;		/* SQEs successfully submitted via io_uring_enter */
	unsigned long iouring_reaped;		/* CQEs drained from the completion ring */
	unsigned long iouring_failed;		/* setup/mmap/submit_burst/io_uring_enter returned -1 */

	/* sanitise_io_uring_enter bailed out because the kernel-shared SQ ring
	 * mask read back larger than ring->sq_entries -- a sibling op had
	 * stomped the mask, which would have steered fill_sqe past the SQE
	 * array and faulted on an unmapped page. */
	unsigned long iouring_enter_mask_corrupt;

	/* close_racer childop counters */
	unsigned long close_racer_runs;			/* total close_racer invocations */
	unsigned long close_racer_pairs;		/* cycles where close+join completed */
	unsigned long close_racer_failed;		/* socketpair/pipe2 returned -1 */
	unsigned long close_racer_thread_spawn_fail;	/* pthread_create returned non-zero */

	/* socket_family_chain childop counters */
	unsigned long socket_family_chain_runs;			/* total invocations */
	unsigned long socket_family_chain_completed;		/* >=1 inner cycle reached recv */
	unsigned long socket_family_chain_failed;		/* every inner cycle bailed early */
	unsigned long socket_family_chain_authencesn_attempts;	/* authencesn name forced */
	unsigned long socket_family_chain_splice_attempts;	/* splice path replaced sendmsg data leg */

	/* slab_cache_thrash childop: per-target burst invocation count,
	 * indexed by enum slab_target (defined in slab-cache-thrash.c, kept
	 * private to the childop since nothing else needs the symbolic
	 * names).  NR_SLAB_TARGETS is asserted equal to the enum tail at
	 * build time inside the childop, so a future target added there
	 * without resizing this array is caught by the assert. */
	unsigned long slab_cache_thrash_runs[NR_SLAB_TARGETS];

	/* Per-childop adaptive-budget multiplier, indexed by enum
	 * child_op_type.  Q8.8 fixed point: 256 == 1.0x.  Updated post-
	 * invocation by adapt_budget() based on the kcov_shm->edges_found
	 * delta observed during dispatch.  Read by the BUDGETED() macro
	 * inside opt-in childops so productive ops get more inner-loop
	 * iterations and dud ops shrink toward the floor.  Values clamp to
	 * [ADAPT_BUDGET_MIN, ADAPT_BUDGET_MAX]; a 0 entry means "uninit,
	 * fall back to 1.0x" so a wild-write to this region degrades to
	 * the existing fixed-budget behaviour rather than zeroing the loop. */
	uint16_t childop_budget_mult[NR_CHILD_OP_TYPES];

	/* Consecutive invocations of an op_type whose edge delta did not
	 * clear ADAPT_BUDGET_THRESHOLD.  Reset to 0 on a productive
	 * invocation; once the streak hits ADAPT_BUDGET_ZERO_STREAK the
	 * shrink ratchet fires and the streak resets.  The hysteresis
	 * keeps a single noise dip from immediately halving the budget. */
	uint16_t childop_zero_streak[NR_CHILD_OP_TYPES];

	/* ---- Group D: diagnostic / parent-side / one-shot ---- */

	/* Counts to tell if we're making progress or not. */
	unsigned long previous_op_count __attribute__((aligned(64)));	/* combined total of all children */

	/* fd lifecycle tracking */
	unsigned long fd_stale_detected;
	unsigned long fd_stale_by_generation;
	unsigned long fd_closed_tracked;
	unsigned long fd_regenerated;
	unsigned long fd_duped;
	unsigned long fd_events_processed;
	unsigned long fd_events_dropped;

	/* Number of fds the generic ret_objtype post-hook auto-registered
	 * into a per-type OBJ_LOCAL pool because no syscall-specific .post
	 * had already done so. */
	unsigned long fd_runtime_registered;

	/* fds/bpf provisioning counters: cumulative count of fds we
	 * successfully published into the global object pool, including
	 * regenerations after stale-fd teardown.  Tells you how much of
	 * trinity's fd-providing infrastructure BPF actually contributes
	 * — zero means the kernel rejected every load and the BPF cross-
	 * subsystem surface (SO_ATTACH_BPF, PERF_EVENT_IOC_SET_BPF, etc.)
	 * is unreachable. */
	unsigned long bpf_maps_provided;
	unsigned long bpf_progs_provided;

	/* Slots held in zombie-pending state because the kernel still has
	 * the unkillable D-state task around and may yet wake it to write
	 * into childdata.  Reusing a slot before the kernel tears the task
	 * down lets the post-wake writes corrupt the replacement child. */
	unsigned long zombie_slots_pending;	/* current count (gauge) */
	unsigned long zombies_reaped;		/* total successfully reaped */
	unsigned long zombies_timed_out;	/* force-reused after timeout */

	/* Times we caught a child's local_op_count above LOCAL_OP_FLUSH_BATCH,
	 * which is impossible during normal operation (the child flushes and
	 * resets at that threshold).  Indicates a stray write into childdata
	 * from somebody other than the slot's current owner. */
	unsigned long local_op_count_corrupted;

	/* fd_event_drain_all() found a child->fd_event_ring pointer that
	 * failed the canonical-address / minimum-address sanity check.
	 * Defense-in-depth against D-state zombie write-after-reap. */
	unsigned long fd_event_ring_corrupted;

	/* fd_event_drain_all() found a live child->fd_event_ring that
	 * differed from the mprotected canary copy taken at init time.
	 * Indicates the pointer was overwritten after init. */
	unsigned long fd_event_ring_overwritten;

	/* Shared obj-heap pressure counters: cumulative successful allocs
	 * and frees through alloc_shared_obj() / free_shared_obj().  Read
	 * by dump_stats() under -v to print a one-line utilisation summary
	 * — a busy run with many allocs but few frees flags a leak before
	 * the heap actually exhausts. */
	unsigned long obj_heap_allocs;
	unsigned long obj_heap_frees;
};

unsigned int stats_syscall_category(const char *name);

void dump_stats(void);

/* Per-tick scan: emits a WARNING when shm->stats.post_handler_corrupt_ptr
 * advances by a threshold count over a one-minute window. */
void corrupt_ptr_spike_check(void);

/* Per-tick scan: every 10 minutes, emits per-second rates for the defense
 * counters surfaced once-per-run by dump_stats(), so an operator watching
 * a long fuzz run can tell which guards are catching real wild writes vs
 * sitting at noise without waiting for the run to finish. */
void defense_counters_periodic_dump(void);

/* Implemented in childops/recipe-runner.c; emits per-recipe completion
 * counts so the catalog layout stays private to that file. */
void recipe_runner_dump_stats(void);

/* Implemented in childops/iouring-recipes.c; emits per-recipe completion
 * counts so the catalog layout stays private to that file. */
void iouring_recipes_dump_stats(void);
