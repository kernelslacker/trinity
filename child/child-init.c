/*
 * Per-child setup: forked-process bring-up, sandboxing, and the
 * helpers that pin the lifetime-constant state child_process()
 * relies on.  Split out of child.c so make -j can compile this
 * concurrently with the alt-op picker and the main loop.
 *
 * Functions that crossed the TU boundary back into child.c
 * (freeze_sibling_childdata, disable_coredumps, enable_coredumps,
 * read_tainted_mask) shed their `static` linkage and are now
 * declared in include/child-internal.h.
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
 * For the child processes, we don't want core dumps (unless we're running with -D)
 * This is because it's not uncommon for us to get segfaults etc when we're doing
 * syscalls with garbage for arguments.
 */
void disable_coredumps(void)
{
	struct rlimit limit = { .rlim_cur = 0, .rlim_max = 0 };

	if (shm->debug == true) {
		struct sigaction sa;
		struct rlimit unlim = {
			.rlim_cur = RLIM_INFINITY,
			.rlim_max = RLIM_INFINITY
		};

		sa.sa_handler = SIG_DFL;
		sa.sa_flags = 0;
		sigemptyset(&sa.sa_mask);
		(void)sigaction(SIGABRT, &sa, NULL);
		(void)sigaction(SIGSEGV, &sa, NULL);

		/*
		 * Force core dumps on regardless of inherited RLIMIT_CORE.
		 * Without this, a parent shell with the typical `ulimit -c 0`
		 * silently propagates to children — segfaults appear in dmesg
		 * (which always logs SIGSEGV) but no core file lands, defeating
		 * the whole point of -D for post-mortem debugging.
		 */
		if (setrlimit(RLIMIT_CORE, &unlim) != 0)
			perror("setrlimit(RLIMIT_CORE)");
		prctl(PR_SET_DUMPABLE, true);
		return;
	}

	if (setrlimit(RLIMIT_CORE, &limit) != 0)
		perror( "setrlimit(RLIMIT_CORE)" );

	prctl(PR_SET_DUMPABLE, false);
}

void enable_coredumps(void)
{
	struct rlimit limit = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY
	};

	if (shm->debug == true)
		return;

	prctl(PR_SET_DUMPABLE, true);

	(void) setrlimit(RLIMIT_CORE, &limit);
}
/*
 * Enable kernel fault injection for this child.  Caller must have completed
 * child setup and installed the expected procfs/debugfs context.
 */
static void set_make_it_fail(void)
{
	int fd;
	const char *buf = "1";

	/* If we failed last time, it's probably because we don't
	 * have fault-injection enabled, so don't bother trying in future.
	 */
	if (__atomic_load_n(&shm->dont_make_it_fail, __ATOMIC_RELAXED))
		return;

	fd = open("/proc/self/make-it-fail", O_WRONLY);
	if (fd == -1) {
		__atomic_store_n(&shm->dont_make_it_fail, true, __ATOMIC_RELAXED);
		return;
	}

	if (write(fd, buf, 1) == -1) {
		if (errno != EPERM)
			outputerr("writing to /proc/self/make-it-fail failed! (%s)\n", strerror(errno));
		__atomic_store_n(&shm->dont_make_it_fail, true, __ATOMIC_RELAXED);
	}

	close(fd);
}

/*
 * Open /proc/self/fail-nth so we can later arm allocation-failure injection
 * for individual syscalls.  Requires CONFIG_FAULT_INJECTION (and typically
 * CONFIG_FAILSLAB / CONFIG_FAIL_PAGE_ALLOC) on the running kernel; the
 * actual failslab=N tunable must be set up out-of-band via debugfs.
 *
 * If the open fails (kernel built without fault injection, perms, etc.)
 * leave fail_nth_fd at -1 so all later code becomes a no-op, and remember
 * the result in shm so siblings stop probing too.
 */
static void open_fail_nth(struct childdata *child)
{
	int fd;

	/* Shared latch: load atomically so a sibling that already proved
	 * the open() impossible (kernel built without CONFIG_FAULT_INJECTION,
	 * /proc not mounted, etc.) is observed without relying on tearing-
	 * free plain reads.  The store is __atomic_store_n rather than
	 * __atomic_exchange_n because the transition has no observable side
	 * effect beyond the bool itself -- there is no log to gate on the
	 * first failer, so we mirror the iouring_enosys pattern
	 * (childops/io_uring/recipes.c) rather than the no_private_ns pattern. */
	if (__atomic_load_n(&shm->no_fail_nth, __ATOMIC_RELAXED))
		return;

	fd = open("/proc/self/fail-nth", O_WRONLY);
	if (fd == -1) {
		__atomic_store_n(&shm->no_fail_nth, true, __ATOMIC_RELAXED);
		return;
	}

	child->fail_nth_fd = fd;
}

/*
 * Read /proc/sys/kernel/tainted via a cached fd.  Procfs returns the
 * mask as ASCII decimal followed by '\n'.  lseek(0) is required because
 * the procfs handler reports "no more data" on a second read of the
 * same open without a rewind.  Errors return 0 (mask unknown) so the
 * caller's XOR delta degrades to "no change" rather than spuriously
 * firing the watcher.
 */
unsigned long read_tainted_mask(int fd)
{
	char buf[32];
	ssize_t n;

	if (fd < 0)
		return 0;
	if (lseek(fd, 0, SEEK_SET) == (off_t) -1)
		return 0;
	n = read(fd, buf, sizeof(buf) - 1);
	if (n <= 0)
		return 0;
	buf[n] = '\0';
	return strtoul(buf, NULL, 10);
}

/*
 * Cache an fd to /proc/sys/kernel/tainted for the per-childop taint
 * watcher.  -1 disables the watcher (e.g. on kernels where the file is
 * unreadable).  Sibling probes don't share state via shm because the
 * file is world-readable on every supported kernel — a per-child failure
 * is almost certainly local (fd exhaustion) and not worth latching off
 * fleet-wide.
 */
static void open_tainted_fd(struct childdata *child)
{
	int fd;

	fd = open("/proc/sys/kernel/tainted", O_RDONLY);
	if (fd == -1) {
		child->tainted_fd = -1;
		child->last_tainted = 0;
		return;
	}
	child->tainted_fd = fd;
	child->last_tainted = read_tainted_mask(fd);
}

/*
 * We call this occasionally to set some FPU state, in the hopes that we
 * might tickle some weird FPU/scheduler related bugs
 */
static void use_fpu(void)
{
	double x = 0;
	asm volatile("":"+m" (x));
	x += 1;
	asm volatile("":"+m" (x));
}

/*
 * Drop the previous occupant's __BUG() stamp and signal-time fault-beacon
 * latches in lock-step with their parent-side dumper flags, so the fresh
 * occupant's first BUG / fault re-triggers the dump path instead of being
 * suppressed by the prior child's idempotency flag, and so the dumpers
 * never observe stale backtrace / ip / sp / addr fields.
 */
static void reset_child_fault_beacons(struct childdata *child)
{
	child->hit_bug = false;
	child->bug_dumped = false;
	__atomic_store_n(&child->bug_backtrace.count, 0, __ATOMIC_RELAXED);
	child->bug_text = NULL;
	child->bug_func = NULL;
	child->bug_lineno = 0;

	__atomic_store_n(&child->fault_beacon.written, 0U, __ATOMIC_RELAXED);
	child->fault_beacon_dumped = false;
}

/*
 * Wipe out any state left from a previous child running in this slot.
 */
void clean_childdata(struct childdata *child)
{
	memset(&child->syscall, 0, sizeof(struct syscallrecord));
	child->seed = 0;
	__atomic_store_n(&child->kill_count, 0, __ATOMIC_RELAXED);
	child->kill_in_flight = false;
	child->dstate_diag_dumped = false;
	child->wedge_accounted = false;
	child->wedge_do32 = false;
	child->wedge_nr = 0;
	child->wedge_start_tp = (struct timespec){ .tv_sec = 0, .tv_nsec = 0 };
	child->dontkillme = false;
	child->xcpu_count = 0;
	child->op_nr = 0;
	child->current_fd = -1;
	child->fd_lifetime = 0;
	child->cached_fd_generation = 0;
	child->last_group = GROUP_NONE;
	child->in_chain_mid_step = false;
	child->op_type = CHILD_OP_SYSCALL;
	/* SHADOW-ONLY topology-pair latch.
	 * NR_CHILD_OP_TYPES is the "no setup observed yet" sentinel so the
	 * first productive event on a freshly-spawned child bumps the
	 * no_setup denominator rather than crediting a stale setup that
	 * belonged to the previous occupant of this slot.  Paired stamp
	 * in child_process() at the start of every is_alt_op dispatch. */
	child->last_setup_op = NR_CHILD_OP_TYPES;
	child->last_setup_op_nr = 0;
	child->stall_count = 0;
	child->stall_last = 0;
	child->fd_created = 0;
	child->fd_closed = 0;
	memset(child->fd_created_by_group, 0, sizeof(child->fd_created_by_group));
	/* F-RSEQ group-pin damper state -- per-pin streak + watermark + fd-
	 * warm counter.  Zeroed on every fresh occupant of this slot so the
	 * predicate starts with no streak history; the dispatch_step
	 * bookkeeping (gated on frontier_group_antilock_mode != OFF AND
	 * group_bias) advances them per pick.  Under default mode=OFF
	 * these fields are never read or written -- the clear here is the
	 * one-shot init pattern the sibling fd_created* fields above use,
	 * not a per-call cost. */
	child->group_streak_len = 0;
	child->last_cov_at_streak = 0;
	child->group_fd_created_in_streak = 0;
	clock_gettime(CLOCK_MONOTONIC, &child->tp);

	/* -1 sentinel = "no syscall picked yet on this child".  Reward
	 * attribution gates on (strat >= 0 && strat < NR_STRATEGIES), so an
	 * unstamped slot naturally skips attribution.  Explorer children
	 * never write this field (they bypass the strategy switch entirely
	 * in set_syscall_nr), so the sentinel persists for their lifetime;
	 * the PC and CMP reward sites also gate on !is_explorer ahead of the
	 * stamp read for clarity. */
	child->strategy_at_pick = -1;

	/* Pair with the per-call top-of-set_syscall_nr() reset that gates
	 * non-frontier strategy picks out of the post-call attribution.  A
	 * fresh slot occupant must start from NONE so the first post-call
	 * read after fork does not credit the previous occupant's stale
	 * regime to its own attribution. */
	child->frontier_pick_regime = FRONTIER_PICK_NONE;

	/* Reset per-child storm-containment counters and reseed the
	 * sliding-window snapshot to "right now, all zeros" so the first
	 * check after fork has a clean baseline rather than measuring a
	 * rate against the previous occupant of this slot. */
	child->local_post_handler_corrupt_ptr = 0;
	child->maps_local_refill_credit = 0;
	/* Reset the per-child writable-pool bump cursor so a recycled
	 * slot restarts allocation at pool offset 0 rather than
	 * continuing from wherever the previous occupant left off. */
	child->writable_pool_cursor = 0;
	child->mmap_pool_nonempty_mask = 0;
	child->storm_check_last_time = child->tp;
	child->storm_check_last_post_handler = 0;

	/* Reset per-child corruption-attribution shards so a fresh
	 * occupant's first dump-window samples are not contaminated by
	 * the previous occupant's accumulated counts. */
	memset(child->local_corrupt_ptr_attr, 0,
	       sizeof(child->local_corrupt_ptr_attr));
	memset(child->local_corrupt_ptr_pc, 0,
	       sizeof(child->local_corrupt_ptr_pc));
	memset(child->local_deferred_free_reject_pc, 0,
	       sizeof(child->local_deferred_free_reject_pc));

	/* Reset breadcrumb ring; .valid=false in zeroed slots keeps the
	 * parent dumper from picking up a previous occupant's leftover
	 * payload as if it belonged to the fresh child. */
	memset(&child->breadcrumb_ring, 0, sizeof(child->breadcrumb_ring));

	/* Drop the previous occupant's socket-family-grammar illegal-step
	 * label so a fresh child that never fires an illegal step is not
	 * misattributed with a stale precondition-violation record at
	 * post-mortem time.  Zero maps to {SFG_ILLEGAL_NONE, SFG_CONN_INIT,
	 * 0} which the post-mortem dumper reads as "no illegal step
	 * fired". */
	memset(&child->last_sfg_illegal, 0, sizeof(child->last_sfg_illegal));

	/* Reset live fd ring: -1 marks all slots as empty. */
	for (int i = 0; i < CHILD_FD_RING_SIZE; i++)
		child->live_fds.fds[i] = -1;
	child->live_fds.head = 0;

	/* Reset propagation ring; slot.valid=false in zeroed entries
	 * keeps prop_ring_try_get from picking ungenerated history if
	 * the consumer probe ever happens before any capture. */
	memset(&child->prop_ring, 0, sizeof(child->prop_ring));

	/* Reset syscall ring; UNKNOWN state in zeroed slots is filtered
	 * by the post-mortem reader so a freshly-spawned child contributes
	 * nothing until it has actually completed a syscall. */
	memset(child->syscall_ring.recent, 0, sizeof(child->syscall_ring.recent));
	__atomic_store_n(&child->syscall_ring.head, 0, __ATOMIC_RELAXED);

	/* Reset pre-crash rolling-history ring; the post-mortem dumper
	 * walks back at most head slots, so zeroing the struct means the
	 * fresh occupant contributes no entries from the previous slot's
	 * child until it publishes its first event. */
	memset(&child->pre_crash, 0, sizeof(child->pre_crash));
	__atomic_store_n(&child->pre_crash.base.head, 0, __ATOMIC_RELAXED);

	child->fail_nth_fd = -1;
	child->tainted_fd = -1;
	child->last_tainted = 0;
	child->current_recipe_name = NULL;

	/* Drop any sentinel reading from the previous occupant of this slot
	 * so the first periodic_work tick re-populates without comparing
	 * against state captured under a different child's environment.
	 * Reset the staggered-capture tick index too so the first post-
	 * populate tick starts at parity 0 (uname) deterministically. */
	child->sentinel_prev.valid = false;
	child->sentinel_tick_ix = 0;

	/* Reset the per-child cmp_hints seen-bloom so a fresh occupant of
	 * the slot does not inherit dedup-refresh skips that belong to the
	 * previous child's tuple-emission history.  Both arch slots reset
	 * in lockstep -- a single iteration of the [2] array keeps the
	 * uniarch case branch-free and matches the per-arch indexing used
	 * by cmp_hints_collect(). */
	{
		unsigned int a;

		for (a = 0; a < 2; a++) {
			memset(child->cmp_hints_seen[a].bits, 0,
			       sizeof(child->cmp_hints_seen[a].bits));
			child->cmp_hints_seen[a].records = 0;
		}
	}

	/* Reset the CMP RedQueen attribution scratch and the recursion guard
	 * for the fresh slot occupant.  redqueen_enabled is the CMP RedQueen A/B-comparison stamp
	 * and is (re)decided per-child in init_child_runtime_config after
	 * kcov_init_child has picked the per-child KCOV mode -- zero here so
	 * the fresh occupant defaults to "re-exec off" until the stamp lands. */
	memset(child->reexec_pending, 0, sizeof(child->reexec_pending));
	child->reexec_pending_count = 0;
	child->in_reexec = false;
	child->fuzz_shm_count = 0;	/* fresh occupant: no tracked shm segments yet */
	child->fuzz_msg_count = 0;	/* fresh occupant: no tracked msg queues yet */
	child->fuzz_sem_count = 0;	/* fresh occupant: no tracked sem sets yet */
	child->redqueen_enabled = false;
	child->boring_filter_arm_b = false;
	child->frontier_blend_arm_b = false;
	/* Errno-plateau decay A/B stamp -- (re)decided per-child in
	 * init_child_runtime_config below; zero here so the fresh occupant
	 * defaults to Arm A (shadow-only, no live reject) until the stamp
	 * lands.  Matches the frontier_blend_arm_b clear above. */
	child->frontier_errno_decay_arm_b = false;
	/* Silent-streak decay A/B stamp -- (re)decided per-child in
	 * init_child_runtime_config below; zero here so the fresh occupant
	 * defaults to Arm A (shadow-only, no live reject) until the stamp
	 * lands.  Matches the frontier_errno_decay_arm_b clear above. */
	child->frontier_silent_decay_arm_b = false;
	/* Adaptive remote-KCOV mode A/B stamp -- (re)decided per-child in
	 * init_child_runtime_config below; zero here so the fresh occupant
	 * defaults to Arm A (static remote-mode policy, byte-identical to
	 * the pre-row baseline) until the stamp lands.  Matches the
	 * frontier_errno_decay_arm_b clear above. */
	child->remote_adaptive_arm_b = false;
	child->reexec_count_window = 0;
	child->reexec_window_start_op = 0;
	child->cmp_hint_injected_this_call = false;
	/* --blob-ab-mode per-call stamp: a fresh slot occupant starts
	 * with no prior blob_fill mode recorded so the dispatch-site
	 * credit block cannot attribute the previous occupant's stale
	 * pick.  Set from blob_fill()'s ab-mode branch on subsequent
	 * calls, drained at the credit block in
	 * random_syscall/dispatch.c, and re-cleared at the top of
	 * generate_syscall_args() every call. */
	child->blob_ab_mode_last = BLOB_AB_MODE_NONE;
	/* Cmp-hint baseline inject denom A/B stamp -- (re)decided per-child
	 * in init_child_runtime_config below; zero here so the fresh occupant
	 * defaults to Arm A (current 1-in-16 baseline) until the stamp lands. */
	child->cmp_hint_inject_arm_b = false;
	/* handle_arg_op prop_ring A/B stamp -- (re)decided per-child in
	 * init_child_runtime_config below; zero here so the fresh occupant
	 * defaults to Arm A (no prop_ring pull at the ARG_OP callsite) until
	 * the stamp lands. */
	child->prop_ring_argop_arm_b = false;
	/* mutate_arg SHADOW structure-aware picker A/B stamp -- (re)decided
	 * per-child in init_child_runtime_config below; zero here so the fresh
	 * occupant defaults to Arm A (no shadow draw, mutate_arg RNG byte-
	 * identical to pre-shadow control) until the stamp lands. */
	child->mut_structured_arm_b = false;
	/* Typed prop_ring consumer A/B stamp -- (re)decided per-child in
	 * init_child_runtime_config below; zero here so the fresh occupant
	 * defaults to Arm A (no typed pull at the gen_arg_* callsites, RNG
	 * byte-identical to pre-typing baseline) until the stamp lands. */
	child->prop_ring_typed_arm_b = false;
	/* SHADOW cmp-hint feedback scoring stash starts empty for a fresh
	 * child occupant ([11-feedback-loop]); generate_syscall_args also
	 * resets at every call boundary, but a fresh-fork clear here means
	 * the child's very first call sees a clean buffer regardless of
	 * what bytes the slot held under the prior occupant. */
	memset(child->cmp_hints_consumed_stash, 0,
	       sizeof(child->cmp_hints_consumed_stash));
	child->cmp_hints_consumed_count = 0;

	reset_child_fault_beacons(child);

	if (child->fd_event_ring)
		fd_event_ring_init(child->fd_event_ring);

	if (child->stats_ring)
		stats_ring_init(child->stats_ring);
}
static void bind_child_to_cpu(struct childdata *child, int childno)
{
	cpu_set_t set;
	unsigned int cpudest;
	pid_t pid = __atomic_load_n(&pids[childno], __ATOMIC_RELAXED);

	if (no_bind_to_cpu == true)
		return;

	if (sched_getaffinity(pid, sizeof(set), &set) != 0)
		return;

	if (child->num >= num_online_cpus)
		cpudest = child->num % num_online_cpus;
	else
		cpudest = child->num;

	CPU_ZERO(&set);
	CPU_SET(cpudest, &set);
	sched_setaffinity(pid, sizeof(set), &set);
}

/*
 * Randomise process context before the child starts fuzzing syscalls.
 * Called once per child from init_child().  Best-effort — errors are
 * silently ignored so a failed operation never wedges the child.
 *
 * Deliberately omits CLONE_NEWPID (doesn't move us, affects future forks
 * unpredictably) and CLONE_NEWUSER (drops caps, breaks privileged paths).
 */
#define CHILD_MEMLOCK_CAP	(256UL << 20)	/* per-child locked-memory cap (see munge_process) */

static void munge_process(void)
{
	static const int extra_ns_flags[] = {
		CLONE_NEWUTS,
		CLONE_SYSVSEM,
#ifdef CLONE_NEWCGROUP
		CLONE_NEWCGROUP,
#endif
#ifdef CLONE_NEWTIME
		CLONE_NEWTIME,
#endif
	};
	static const unsigned long personas[] = {
		PER_LINUX,
		PER_LINUX | ADDR_NO_RANDOMIZE,
		PER_LINUX | READ_IMPLIES_EXEC,
		PER_LINUX | ADDR_COMPAT_LAYOUT,
		PER_LINUX | MMAP_PAGE_ZERO,
		PER_LINUX32,
	};
	static const int rlim_resources[] = {
		RLIMIT_DATA,
		RLIMIT_FSIZE,
		RLIMIT_MSGQUEUE,
		RLIMIT_NICE,
	};
	char cgpath[64];
	unsigned int i;
	int fd;

	/*
	 * Deterministic cap on locked memory (NOT part of the random sweep
	 * below).  A fuzzed mlockall(MCL_FUTURE) locks every subsequent mmap
	 * in this child; left unbounded that grows into the cgroup
	 * memory.high throttle and the child wedges in
	 * __mem_cgroup_handle_over_high instead of fuzzing.  Capping
	 * RLIMIT_MEMLOCK makes the over-cap locked alloc fail -EAGAIN, which
	 * trips __zmalloc's munlockall()+retry fallback (utils/zmalloc.c) --
	 * so a runaway self-bounds and mlockall coverage (including the
	 * failure path) is preserved.  Only lower it; setting rlim_max blocks
	 * a fuzzed setrlimit from lifting it back up.
	 */
	{
		struct rlimit ml;

		if (getrlimit(RLIMIT_MEMLOCK, &ml) == 0) {
			if (ml.rlim_max == RLIM_INFINITY || ml.rlim_max > CHILD_MEMLOCK_CAP)
				ml.rlim_max = CHILD_MEMLOCK_CAP;
			if (ml.rlim_cur == RLIM_INFINITY || ml.rlim_cur > CHILD_MEMLOCK_CAP)
				ml.rlim_cur = CHILD_MEMLOCK_CAP;
			(void) setrlimit(RLIMIT_MEMLOCK, &ml);
		}
	}

	/* Additional namespace diversity on top of what init_child already does. */
	for (i = 0; i < ARRAY_SIZE(extra_ns_flags); i++) {
		if (RAND_BOOL())
			(void) unshare(extra_ns_flags[i]);
	}

	/* Random personality — stay within PER_LINUX family to remain sane. */
	(void) personality(RAND_ARRAY(personas));

	/*
	 * Best-effort cgroup migration.  Trinity can pre-create numbered
	 * cgroups (/sys/fs/cgroup/trinity0..7) as writable directories;
	 * if they don't exist we skip silently.
	 */
	snprintf(cgpath, sizeof(cgpath), "/sys/fs/cgroup/trinity%u/cgroup.procs",
		 rnd_modulo_u32(8));
	fd = open(cgpath, O_WRONLY);
	if (fd >= 0) {
		char pidbuf[16];
		int len = snprintf(pidbuf, sizeof(pidbuf), "%d", mypid());
		ssize_t ret __attribute__((unused));
		ret = write(fd, pidbuf, (size_t) len);
		(void) close(fd);
	}

	/* Randomly tighten a subset of resource limits. */
	for (i = 0; i < ARRAY_SIZE(rlim_resources); i++) {
		struct rlimit lim;

		if (!RAND_BOOL())
			continue;
		if (getrlimit(rlim_resources[i], &lim) != 0)
			continue;
		if (lim.rlim_cur == RLIM_INFINITY || lim.rlim_cur < 2)
			continue;
		/* Reduce to a random value in [50%, 100%) of current soft limit. */
		lim.rlim_cur = lim.rlim_cur / 2 + rnd_modulo_u64(lim.rlim_cur / 2);
		(void) setrlimit(rlim_resources[i], &lim);
	}

	/* Random umask. */
	umask((mode_t)(rnd_u32() & 0777));
}

/*
 * Mprotect every sibling's childdata to PROT_READ in our address space.
 *
 * Called from init_child for the initial sweep, and from the top of the
 * child_process loop as a catch-up sweep when shm->sibling_freeze_gen
 * has bumped (a new sibling joined since we last ran).  Idempotent:
 * mprotect on an already-PROT_READ region is a cheap no-op for slots
 * that haven't changed protection.
 *
 * Uses my_childno (caller's stack value) rather than child->num so a
 * sibling's stray write that corrupted our own num field can't trick
 * us into mprotecting our own region and then SIGSEGV'ing on the next
 * write.
 *
 * mprotect can return -ENOMEM if the kernel runs out of VMA slots
 * splitting the mapping that covers a sibling's childdata.  Best-effort
 * hardening — count the failure and keep going rather than aborting,
 * which would turn a transient kernel limit into a fleet-wide outage.
 */
void freeze_sibling_childdata(int my_childno)
{
	unsigned int i;
	size_t len = childdata_mapping_len;

	/*
	 * childdata_mapping_len is stamped by init_shm_per_child_rings()
	 * during parent init, before any child forks -- a zero here means
	 * a caller reached this site before init_shm ran, which is a
	 * setup bug rather than a runtime condition.  Refuse to mprotect
	 * a zero span: the kernel would round it up to the containing
	 * page, but mprotect(len=0) is a documented no-op that would
	 * silently leave the freeze off (the same failure mode the
	 * end-aligned pointer bug had) instead of loudly flagging it.
	 */
	if (len == 0) {
		outputerr("freeze_sibling_childdata: childdata_mapping_len uninitialised\n");
		__atomic_add_fetch(&shm->stats.diag.sibling_mprotect_failed, 1,
				   __ATOMIC_RELAXED);
		return;
	}

	for_each_child(i) {
		if ((unsigned int)my_childno == i)
			continue;
		if (children[i] == NULL)
			continue;
#ifdef CONFIG_GUARD_SHARED
		/*
		 * Investigation hook: warn if this internal protect's
		 * range happens to overlap a registered kcov buffer.  An
		 * internal-mprotect path that strips a kcov buffer's
		 * PROT_WRITE is a distinct mechanism for the trace_buf
		 * reset-fault from the externally-fuzzed mm-sanitiser
		 * route, and the spec calls this site out explicitly.
		 */
		internal_mprotect_audit_kcov("freeze_sibling_childdata",
			(unsigned long)children[i],
			len, PROT_READ);
#endif
		if (mprotect(children[i], len, PROT_READ) != 0) {
			int saved_errno = errno;

			/*
			 * Route through the shared mprotect-failure logger so
			 * the resolved caller PC lands in the same format as
			 * every other internal mprotect failure -- the prior
			 * bare-outputerr line was too easy to lose in the
			 * fleet log stream and hid the persistent EINVAL
			 * cluster that came from the end-aligned childdata
			 * pointer.  Keep the counter bump for the stats view
			 * that surfaces the failure rate over time.
			 */
			log_mprotect_failure(children[i], len, PROT_READ,
					     __builtin_return_address(0),
					     saved_errno);
			outputerr("freeze_sibling_childdata: mprotect(sibling %u childdata, %zu) failed: %s\n",
				  i, len, strerror(saved_errno));
			__atomic_add_fetch(&shm->stats.diag.sibling_mprotect_failed, 1,
					   __ATOMIC_RELAXED);
		}
	}
}

/*
 * Isolate this child's stdio + controlling terminal before any
 * syscall fuzzing starts.  Three steps, all about keeping fuzzed
 * I/O off the operator's terminal: redirect fd 0/1/2 to /dev/null
 * so splice/sendfile/vmsplice/write can't spew to the tty, drop the
 * inherited --stats-log-file fd so a fuzzed fchmod/ftruncate/write
 * can't smash the operator's log, and setsid() to sever the
 * controlling terminal so a later open("/dev/tty") can't re-acquire
 * it.  Bundled here so the I/O-isolation contract is self-contained
 * -- subsequent init phases assume stderr is /dev/null and rely on
 * the no-controlling-tty invariant.
 */
static void init_child_isolate_io(void)
{
	int devnull;

	/* Redirect stdin/stdout/stderr to /dev/null so no syscall
	 * (splice, sendfile, vmsplice, write to fd 0, etc.) can spew to
	 * the operator's terminal.  fd 0 must be redirected too: ptys
	 * are bidirectional and writing to the inherited stdin (which
	 * is the operator's pty) lands on their shell.  Open O_RDWR so
	 * fuzzed reads against fd 0 also succeed (with EOF) instead of
	 * EBADF'ing — keeps the syscall behaviour realistic. */
	/* If /dev/null can't be opened (absent, inaccessible, EMFILE,
	 * chroot without /dev bind-mounted) fd 0/1/2 would remain pointed
	 * at the operator tty / inherited log fd -- exactly the hazard
	 * this redirect exists to prevent -- so bail hard rather than
	 * proceed to fuzzing with poisoned stdio. */
	devnull = open("/dev/null", O_RDWR);
	if (devnull < 0)
		_exit(EXIT_FAILURE);

	/* On dup2 failure the std fd would remain pointing at the
	 * operator tty or an inherited log fd -- exactly the hazard
	 * this redirect exists to prevent -- so bail hard rather than
	 * proceed to fuzzing with a poisoned fd 0/1/2. */
	while (dup2(devnull, STDIN_FILENO) < 0) {
		if (errno == EINTR)
			continue;
		_exit(EXIT_FAILURE);
	}
	while (dup2(devnull, STDOUT_FILENO) < 0) {
		if (errno == EINTR)
			continue;
		_exit(EXIT_FAILURE);
	}
	while (dup2(devnull, STDERR_FILENO) < 0) {
		if (errno == EINTR)
			continue;
		_exit(EXIT_FAILURE);
	}
	if (devnull > STDERR_FILENO)
		close(devnull);

	/* Drop the inherited --stats-log-file fd before any syscall fuzzing
	 * starts: it's a parent-only writer, but children would otherwise
	 * reach it numerically via fchmod / ftruncate / write at random
	 * offset, smashing the operator's log mid-run. */
	stats_log_drop_in_child();
	stats_timeseries_drop_in_child();

	/* Same hazard, different fds: the parent's self-cgroup fds (the
	 * memory.events file fd, its inotify watch fd, and the workload
	 * cgroup O_DIRECTORY fd handed to clone3(CLONE_INTO_CGROUP)) were
	 * created IN_CLOEXEC, but CLOEXEC only fires on exec(), and our
	 * children fork-and-fuzz without exec.  A fuzzed fcntl on the
	 * inherited inotify fd can clear O_NONBLOCK on the shared OFD,
	 * wedging the parent's drain-read in self_cgroup_events_check()
	 * and stalling the main loop (no child reap -> zombie pileup).  A
	 * fuzzed dup2 onto the workload-cgroup dirfd redirects subsequent
	 * spawns into the wrong cgroup, breaking memory.max + oom.group
	 * containment.  Drop all three. */
	self_cgroup_drop_fds_in_child();

	/* And the parent's /proc/<pid>/stat fds for liveness polling.  They
	 * are opened post-fork as each child is spawned, so every later
	 * child inherits earlier slots' fds.  Only the parent reads them;
	 * leaving them open in the child lets a fuzzed close/dup2 corrupt
	 * the parent's get_pid_state view and blind stuck-detection. */
	pidstatfiles_drop_in_child();

	/* Detach from the controlling terminal so a fuzzed
	 * open("/dev/tty", O_WRONLY) followed by write() can't reach the
	 * operator's shell.  The dup2 above only covers fds 0/1/2; this
	 * closes the wider class of paths that re-acquire the tty (open of
	 * /dev/tty itself, ioctl(TIOCSCTTY), etc.).  setsid() makes us our
	 * own session leader without a controlling terminal — subsequent
	 * /dev/tty opens fail with ENXIO. */
	(void) setsid();
}

/*
 * Freeze the shared-memory regions this child relies on so that a
 * sibling's stray kernel-side write can't scribble them mid-run.
 * Four PROT_READ pulls, each independently justified by its
 * inline comment:
 *
 *   - the per-sibling childdata regions (initial sweep + freeze_gen
 *     bump so existing siblings re-sweep on their next loop top
 *     check),
 *   - the shared pids[] array (a single allocation that doesn't
 *     grow, hence the one-shot mprotect here rather than the
 *     per-loop catch-up),
 *   - the stats published mirror.
 *
 * Also re-publishes child->num from the stack-based childno before
 * the freeze so the freeze itself observes a known-good num field.
 */
static void init_child_freeze_shared(struct childdata *child, int childno)
{
	unsigned int new_gen;

	/* Re-set num from the stack-based childno in case shared memory
	 * was corrupted by a sibling's stray write. */
	child->num = childno;

	/* Initial sibling-childdata freeze.  See freeze_sibling_childdata
	 * for the per-mprotect rationale.  After it returns we publish a
	 * fresh sibling_freeze_gen so existing siblings refreeze on their
	 * next loop top check and pull our own region into PROT_READ —
	 * closing the startup-race window where a faster sibling's value-
	 * result kernel write could land in our not-yet-frozen childdata.
	 *
	 * RELEASE on the bump pairs with the ACQUIRE load on the loop top
	 * check so any sibling that observes the new gen also observes the
	 * children[] entries this child relies on.  Cache last_seen with
	 * the just-bumped value so we don't immediately self-trigger a
	 * refreeze on our first loop iteration. */
	freeze_sibling_childdata(childno);
	new_gen = __atomic_add_fetch(&shm->sibling_freeze_gen, 1, __ATOMIC_RELEASE);
	child->last_seen_freeze_gen = new_gen;

	/* Same rationale for the shared pids[] array: a stray sibling write
	 * into pids[] could spoof a child's pid, breaking pid_alive() / the
	 * watchdog reaper.  Done here (not in freeze_sibling_childdata)
	 * because pids[] is a single allocation that doesn't grow — one
	 * mprotect at init time is enough; the per-loop refreeze path only
	 * needs to chase newly-spawned childdata regions. */
#ifdef CONFIG_GUARD_SHARED
	internal_mprotect_audit_kcov("init_child:pids",
		(unsigned long)pids, max_children * sizeof(*pids), PROT_READ);
#endif
	if (mprotect(pids, max_children * sizeof(*pids), PROT_READ) != 0) {
		int saved_errno = errno;

		log_mprotect_failure(pids, max_children * sizeof(*pids), PROT_READ,
				     __builtin_return_address(0), saved_errno);
		outputerr("init_child: mprotect(pids[]) failed: %s\n", strerror(saved_errno));
		__atomic_add_fetch(&shm->stats.diag.sibling_mprotect_failed, 1,
				   __ATOMIC_RELAXED);
	}

	/* Same shape for the shm_published stats mirror: children read
	 * fleet_op_count off it on the cold path (maybe_rotate_strategy()'s
	 * rotation clock, syscalls_todo termination); the parent's
	 * stats_publish_locked() inside stats_ring_drain_all() is the
	 * sole writer.  The integrity check in shm_is_corrupt() already
	 * documents the PROT_READ contract, but the matching mprotect()
	 * call was missing -- a wild kernel write through a fuzzed syscall
	 * arg pointer could scribble fleet_op_count between publishes and
	 * perturb rotation / termination behavior. */
	stats_published_freeze();
}

/*
 * Synchronise with the parent and bring up this child's private
 * per-process state.  Two phases bundled here because they share
 * the same precondition (the parent must have published our pid in
 * pids[childno]) and the same liveness requirement (no
 * outputerr-able path -- stderr is already /dev/null at this
 * point):
 *
 *   - Block until the parent stamps pids[childno] = our pid,
 *     panicking via the shm survivor counter if the parent dies
 *     under us.
 *   - Once the rendezvous resolves, cache our (childno, pid, child)
 *     in the this_child fast path, seed the child PRNG, and bring
 *     up the per-child object pools (OBJ_LOCAL list, cloned
 *     OBJ_GLOBAL snapshot, mappings, futexes, dirty mapping,
 *     optional CPU pin).
 *
 * The local pid migrates into this helper -- it has no consumer
 * outside this section, and getpid() is invariant within a
 * process lifetime, so the call-site move is semantically a no-op.
 */
static void init_child_rendezvous_parent(struct childdata *child, int childno)
{
	pid_t pid = getpid();

	/* Wait for parent to set our childno */
	while (__atomic_load_n(&pids[childno], __ATOMIC_ACQUIRE) != pid) {
		sched_yield();
		/* Make sure parent is actually alive to wait for us.
		 * stderr was redirected to /dev/null at the top of this
		 * function, so an outputerr here would be lost -- bump a
		 * survivor counter in shm instead so a post-mortem reader
		 * can tell this path actually fired. */
		if (pid_alive(mainpid) == false) {
			__atomic_add_fetch(&shm->stats.diag.child_dead_parent_observed,
					   1, __ATOMIC_RELAXED);
			panic(EXIT_SHM_CORRUPTION);
			_exit(EXIT_SHM_CORRUPTION);
		}
	}

	/* Cache our childno/pid for O(1) lookups in this_child()/find_childno().
	 * Pass the child pointer directly — don't re-derive it from
	 * children[] which sits in mprotected shared memory but accessing
	 * via the cached argument avoids the indirection on the hot path. */
	set_child_cache(childno, pid, child);

	set_seed(child);

	init_object_lists(OBJ_LOCAL, child);

	/*
	 * Take the fork-time snapshot of the parent's OBJ_GLOBAL pool into
	 * this child's private heap before any caller below resolves an
	 * OBJ_GLOBAL objhead (init_child_mappings walks OBJ_MMAP_ANON,
	 * init_child_futexes walks OBJ_FUTEX).  Subsequent get_objhead()
	 * calls in this child return the local copy.
	 */
	clone_global_objects_to_child(child);

	init_child_mappings();
	init_child_futexes();

	dirty_random_mapping();

	if (RAND_BOOL())
		bind_child_to_cpu(child, childno);
}

/*
 * Sandbox / namespace bring-up.  Runs after the parent has
 * rendezvoused with us and the per-child object pools are up; runs
 * before any fuzz-driven runtime config (kcov, syscall picker,
 * etc.) so munge_process() can freely tighten rlimits without
 * tripping setup-time allocations.
 *
 * Phase shape:
 *   - block on shm->ready so every child enters the post-init
 *     world at roughly the same moment,
 *   - turn on the make-it-fail / fail-nth / tainted-fd fault
 *     injectors,
 *   - optionally dirty FPU state and always mask child signals,
 *   - randomly unshare into a private mount/ipc/io/net ns (with
 *     the MS_PRIVATE remount + no_private_ns latch dance) and a
 *     PID ns (with the no_pidns latch),
 *   - if we started as root, drop_privs() lowers the child to
 *     nobody so subsequent fuzz syscalls run unprivileged,
 *   - munge_process() applies the random rlimit / umask sweep.
 */
static void init_child_setup_sandbox(struct childdata *child, int childno)
{
	/* Wait for all the children to start up.  Mirror the parent-death
	 * guard from the pids[childno] rendezvous loop above: if the parent
	 * dies before publishing shm->ready we would otherwise sleep here
	 * indefinitely, and the mainpid slot risks pid reuse. */
	while (!__atomic_load_n(&shm->ready, __ATOMIC_ACQUIRE)) {
		if (pid_alive(mainpid) == false) {
			__atomic_add_fetch(&shm->stats.diag.child_dead_parent_observed,
					   1, __ATOMIC_RELAXED);
			panic(EXIT_SHM_CORRUPTION);
			_exit(EXIT_SHM_CORRUPTION);
		}
		sleep(1);
	}

	set_make_it_fail();

	open_fail_nth(child);

	open_tainted_fd(child);

	if (RAND_BOOL())
		use_fpu();

	mask_signals_child();

	if (RAND_BOOL()) {
		/*
		 * Per-child IPC/IO unshares always run on the coin flip; they
		 * are cheap, scoped to this child, and require no parent
		 * provisioning -- the isolation spine deliberately leaves them
		 * alone.  The net + mount per-child unshares are gated on
		 * shm->isolation.*_ready: when the parent already provisioned
		 * (root-started, --no-startup-isolation unset, both syscalls
		 * succeeded) we inherit the parent's ns via fork() and the
		 * per-child unshare is redundant.  When either latch is false
		 * (non-root, EPERM/ENOSYS at parent setup, or operator opt-out)
		 * we fall back to today's per-child path -- behaviour matches
		 * a pre-isolation trinity run exactly.
		 *
		 * unshare(CLONE_NEWNS) plus the MS_PRIVATE remount: if the
		 * remount is rejected (EPERM in some sandboxed configs) we
		 * can't undo the unshare, so latch shm->no_private_ns to skip
		 * future attempts and log only the first failure -- the child
		 * is still usable, just not isolated for mount fuzzing.
		 */
		if (!__atomic_load_n(&shm->isolation.mnt_ready, __ATOMIC_RELAXED)) {
			if (!__atomic_load_n(&shm->no_private_ns, __ATOMIC_RELAXED)) {
				if (unshare(CLONE_NEWNS) == 0) {
					if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
						if (!__atomic_exchange_n(&shm->no_private_ns, true, __ATOMIC_RELAXED))
							outputerr("child %d: MS_PRIVATE remount failed (errno=%d) "
							          "after unshare(CLONE_NEWNS); mounts in this child "
							          "may propagate to host mount table\n",
							          childno, errno);
					}
				}
			}
		}
		unshare(CLONE_NEWIPC);
		unshare(CLONE_IO);
		if (!__atomic_load_n(&shm->isolation.net_ready, __ATOMIC_RELAXED))
			unshare(CLONE_NEWNET);
	}

	/*
	 * Optionally enter a new PID namespace.  unshare(CLONE_NEWPID)
	 * doesn't move *us* into the new namespace — it means our next
	 * fork() creates pid 1 in a fresh pidns.  This exercises kernel
	 * pidns code paths when EXTRA_FORK syscalls (like execve) run.
	 *
	 * Skip if we already know it'll fail (EPERM on unprivileged
	 * kernels without user_namespaces, or missing CONFIG_PID_NS).
	 *
	 * Set to true once we detect that unprivileged pidns isn't available.
	 * Lives in shared memory (shm->no_pidns) so the flag propagates across
	 * fork() — see init_child() below.
	 */
#ifdef CLONE_NEWPID
	if (RAND_BOOL() && !__atomic_load_n(&shm->no_pidns, __ATOMIC_RELAXED)) {
		if (unshare(CLONE_NEWPID) == -1) {
			if (errno == EPERM || errno == EINVAL)
				__atomic_store_n(&shm->no_pidns, true, __ATOMIC_RELAXED);
		}
	}
#endif

	if (orig_uid == 0)
		drop_privs();

	/*
	 * Drop every capability before the fuzz loop.  The trinity binary
	 * may carry CAP_SYS_ADMIN as a file capability (granted via
	 * `make setcap` so the parent/watchdog can read /proc/<pid>/stack);
	 * fork() preserves that across the permitted+effective sets, so a
	 * naive child would fuzz with CAP_SYS_ADMIN — a broader, more
	 * privileged surface than the deliberate non-root model.  Clear
	 * permitted+effective+inheritable here, unconditionally: the
	 * non-root path is exactly the one that inherits the file cap.
	 * Bare syscall(__NR_capset, ...) on purpose — trinity_raw_syscall()
	 * honours -x exclusions, which must not skip a security op.
	 * Ambient is already empty (file caps never populate it).
	 *
	 * Enforcement is asymmetric: the root path is the only one that
	 * can actually enter the fuzz loop still holding CAP_SYS_ADMIN
	 * (or more) if the drop is silently skipped, so a failure there
	 * is fatal -- the isolation invariant above must not be broken.
	 * On the non-root path a failure is a genuine no-op (the child
	 * was never privileged); log it and continue.
	 */
	{
		struct __user_cap_header_struct hdr = {
			.version = _LINUX_CAPABILITY_VERSION_3,
			.pid = 0,
		};
		struct __user_cap_data_struct data[2] = { {0}, {0} };

		if (syscall(__NR_capset, &hdr, data) != 0) {
			int saved_errno = errno;

			if (orig_uid == 0) {
				outputerr("child: capset(empty) failed on root path: %s\n",
					  strerror(saved_errno));
				_exit(EXIT_FAILURE);
			}
			outputerr("child: capset(empty) failed (non-root, continuing): %s\n",
				  strerror(saved_errno));
		}
	}

	/*
	 * Stamp the per-child (st_dev, st_ino) of /proc/self/ns/{user,mnt,
	 * net} as the cap-drop oracle's "init ns" anchors.  Done here, co-
	 * located with the capset()-to-empty drop, so the anchors capture
	 * the namespace identity the child was sandboxed in -- after the
	 * per-child unshare() dance above and before the fuzz loop runs any
	 * alt-op that may legitimately unshare again.  The oracle's
	 * capget/mount/net_admin probes consult these anchors to skip ticks
	 * during which the child has transitioned into a bootstrapped
	 * userns/mntns/netns (statmount-idmap-overflow's in-place unshare,
	 * the transient-fork capdrop helper) and would otherwise false-fire.
	 * The bpf(KPROBE) probe stays unconditional -- its cap check pins to
	 * the init userns and so remains correct across legitimate ns
	 * transitions.
	 */
	capdrop_oracle_capture_init_ns_anchors();

	munge_process();
}

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
static void init_child_runtime_config(struct childdata *child, int childno)
{
	init_child_runtime_basics(child, childno);
	init_child_ab_stamps(child);
	init_child_finalize();
}

/*
 * Called from the fork_children loop in the main process.
 */
void init_child(struct childdata *child, int childno)
{
	init_child_isolate_io();

	/*
	 * Override init_child_isolate_io()'s stderr -> /dev/null
	 * baseline with a per-child memfd buffer so glibc's
	 * malloc_printerr / __libc_message / __fortify_fail family
	 * writes survive long enough for child_fault_handler() to
	 * flush them into the on-disk bug log on a real crash.
	 * Clean exits discard the memfd with the process so trinity's
	 * own outputerr() noise never reaches disk.  Falls back to
	 * /dev/null on memfd_create() failure (see signals.c).
	 */
	init_stderr_memfd();

	init_child_freeze_shared(child, childno);

	init_child_rendezvous_parent(child, childno);

	init_child_setup_sandbox(child, childno);

	/*
	 * Post-fork per-provider bring-up.  Providers whose kernel-side
	 * resource lifecycle is tied to the creating task's mm (KVM VM /
	 * vCPU fds most obviously) must create their objects here rather
	 * than in the parent-side .init hook, otherwise every child
	 * inherits a parent-owned object that the kernel refuses from
	 * child context.  Sequenced after init_child_setup_sandbox() so
	 * per-child unshare/drop_privs/rlimit tightening are already in
	 * effect and the child's kernel-object view matches what the
	 * fuzz loop will actually see; sequenced before
	 * init_child_runtime_config() so the RLIMIT_AS 4 GiB pin does
	 * not clip legitimate per-provider mmaps at bring-up time.
	 * No-op today for every existing provider (child_init == NULL);
	 * providers opt in explicitly.
	 */
	run_fd_provider_child_init(child);

	init_child_runtime_config(child, childno);

	/*
	 * Turn on glibc's verbose heap-corruption abort path.  Without
	 * this, malloc_printerr emits a short "<assertion>" string on a
	 * silent abort(); with M_CHECK_ACTION=3 it formats a fuller
	 * message ("free(): double free detected in tcache 2",
	 * "malloc(): unsorted double linked list corrupted", &c) into
	 * __abort_msg before raising SIGABRT.  The fault handler in
	 * signals.c reads that pointer (cached at init_abort_msg_capture
	 * time below) and writes it into the per-pid bug log, which is
	 * what lets the post-mortem bucket aborts by corruption mode
	 * rather than landing them all under malloc+0x150.
	 *
	 * Use mallopt() rather than MALLOC_CHECK_=3 in the environment:
	 * trinity fuzzes execve, and any leaked MALLOC_CHECK_ in the
	 * inherited envp would perturb the child-of-child's malloc
	 * behaviour.  mallopt() is in-process only and inherited across
	 * fork, so this single call covers the child and any further
	 * children it forks for fuzzing.
	 *
	 * Cost is a 5-15%% malloc-path overhead -- acceptable for the
	 * bucketing payoff, and the syscall fuzzer is not malloc-bound.
	 *
	 * Paired with init_abort_msg_capture(), which resolves glibc's
	 * __abort_msg via dlsym(RTLD_DEFAULT, ...) and caches the
	 * pointer for the signal-safe read in the SIGABRT handler.
	 * Placed at the bottom of init_child so RTLD_DEFAULT's symbol
	 * table is fully populated by the time dlsym runs.
	 */
	(void)mallopt(M_CHECK_ACTION, 3);

	/*
	 * Pin glibc to a single arena so heap_bounds_init()'s one-shot
	 * /proc/self/maps snapshot covers ALL glibc allocations.  Glibc
	 * normally spawns secondary mmap'd arenas on demand (per-thread,
	 * under allocation pressure, large mallocs that bypass
	 * MMAP_THRESHOLD); range_overlaps_libc_heap() only sees the
	 * snapshotted brk + the arenas present at snapshot time and has
	 * a live re-test for the brk arm but not the mmap-arena arm, so
	 * a post-snapshot secondary arena is a blind spot.  A fuzzed
	 * pointer landing in that arena then passes the sanitiser, the
	 * kernel writes through it and scribbles glibc chunk metadata,
	 * surfacing later as `free(): invalid size` / check_uid aborts
	 * with no obvious proximate cause.  M_ARENA_MAX=1 forbids
	 * spawning a second arena and M_ARENA_TEST=1 disables the
	 * contention-growth heuristic that would otherwise try.  The
	 * child is effectively single-threaded in the syscall loop, so
	 * arena-contention cost is ~zero.
	 */
	(void)mallopt(M_ARENA_MAX, 1);
	(void)mallopt(M_ARENA_TEST, 1);

	init_abort_msg_capture();

	/*
	 * Arm the Stage-2 writer-pinning canary hardware breakpoint last.
	 * Default-OFF: writer_watch_arm_child() short-circuits when
	 * --writer-watch was not passed (writer_watch_addr == 0).  Runs
	 * after mask_signals_child() has installed the SIGTRAP handler
	 * (mask_signals_child is called earlier via init_child_setup_sandbox
	 * -> ... -> the child fork-side init path), so a trap delivered
	 * to this thread immediately after arming is dispatched to
	 * writer_trap_handler instead of the kernel-default core-dump
	 * behaviour. */
	writer_watch_arm_child();

	/*
	 * --self-corrupt-canary sentinel allocation (default OFF).  The
	 * init helper short-circuits when the flag was not passed, so
	 * an operator not opting in pays no zmalloc, no memset, and no
	 * per-child heap footprint.  When the flag is on, allocates the
	 * 64-byte magic-filled buffer whose bytes the pre/post-dispatch
	 * signature loop folds into its XOR checksum. */
	self_corrupt_canary_init_child();
}
