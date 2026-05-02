#pragma once

#include "syscall.h"	/* MAX_NR_SYSCALL */

/* Upper bound on the recipe_runner catalog size.  recipe-runner.c
 * asserts at startup that its table fits.  Sized large enough to
 * accommodate future recipes without reshuffling shared memory. */
#define MAX_RECIPES 36

/* Upper bound on the iouring_recipes catalog.  iouring-recipes.c asserts
 * at build time that its table fits. */
#define MAX_IOURING_RECIPES 32

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

/* Various statistics. */

struct stats_s {
	unsigned long op_count;
	unsigned long successes;
	unsigned long failures;

	/* Counts to tell if we're making progress or not. */
	unsigned long previous_op_count;	/* combined total of all children */

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

	/* Fault injection (/proc/self/fail-nth):
	 *   fault_injected  — number of syscalls we armed fail-nth for
	 *   fault_consumed  — subset that returned -ENOMEM, i.e. the fault
	 *                     actually triggered an allocation failure */
	unsigned long fault_injected;
	unsigned long fault_consumed;

	/* post-syscall oracle anomaly counts */
	unsigned long fd_oracle_anomalies;
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

	/* procfs_writer childop: per-tree write counts */
	unsigned long procfs_writes;
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

	/* fds/bpf provisioning counters: cumulative count of fds we
	 * successfully published into the global object pool, including
	 * regenerations after stale-fd teardown.  Tells you how much of
	 * trinity's fd-providing infrastructure BPF actually contributes
	 * — zero means the kernel rejected every load and the BPF cross-
	 * subsystem surface (SO_ATTACH_BPF, PERF_EVENT_IOC_SET_BPF, etc.)
	 * is unreachable. */
	unsigned long bpf_maps_provided;
	unsigned long bpf_progs_provided;

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

	/* avoid_shared_buffer() caught an output-buffer syscall arg whose
	 * address overlapped one of trinity's alloc_shared() regions and
	 * rewrote it to a non-shared address.  A non-zero count means the
	 * arg-generation path is producing pointers into our own shared
	 * state — without this redirect the kernel would write the syscall
	 * result on top of trinity bookkeeping. */
	unsigned long shared_buffer_redirected;

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

/* Implemented in childops/recipe-runner.c; emits per-recipe completion
 * counts so the catalog layout stays private to that file. */
void recipe_runner_dump_stats(void);

/* Implemented in childops/iouring-recipes.c; emits per-recipe completion
 * counts so the catalog layout stays private to that file. */
void iouring_recipes_dump_stats(void);
