/*
 * Per-child clean-slate helpers: coredump toggles, fault-injection fd
 * setup (make-it-fail, fail-nth), the tainted-mask fd, an FPU dirtier,
 * and the per-slot occupant reset run when a fresh child moves into a
 * childdata slot.  Split out of child-init.c so make -j can compile
 * the reset path concurrently with the sandbox / freeze / runtime
 * setup helpers.
 *
 * set_make_it_fail, open_fail_nth, open_tainted_fd, and use_fpu shed
 * their `static` linkage here so init_child_setup_sandbox (now in
 * child-init-sandbox.c) can reach them across the TU boundary;
 * declarations are in include/child-internal.h.
 * disable_coredumps, enable_coredumps, read_tainted_mask, and
 * clean_childdata were already exposed via child-internal.h /
 * child-api.h.
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
#include "taint.h"
#include "trinity.h"	// ARRAY_SIZE
#include "writer-watch.h"
#include "uid.h"
#include "utils.h"	// zmalloc

#include "kernel/sched.h"

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
void set_make_it_fail(void)
{
	int fd;
	const char *buf = "1";

	/* If we failed last time, it's probably because we don't
	 * have fault-injection enabled, so don't bother trying in future.
	 */
	if (__atomic_load_n(&shm->dont_make_it_fail, __ATOMIC_RELAXED))
		return;

	fd = open("/proc/self/make-it-fail", O_WRONLY | O_CLOEXEC);
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
void open_fail_nth(struct childdata *child)
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

	fd = open("/proc/self/fail-nth", O_WRONLY | O_CLOEXEC);
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
void open_tainted_fd(struct childdata *child)
{
	int fd;

	/* Release the parent's cached tainted fd inherited via fork.
	 * The child's own get_taint() calls (from is_tainted() in the
	 * syscall-exec hot path) would otherwise read through that
	 * inherited fd number, which the child's own close()/dup2()
	 * fuzzing can rewire to point at an unrelated file — exactly
	 * the fd-reuse false-taint race that killed the original
	 * startup-cache attempt. */
	close_parent_tainted_fd();

	fd = open("/proc/sys/kernel/tainted", O_RDONLY | O_CLOEXEC);
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
void use_fpu(void)
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

	/* Baseline runs pick under the init-user context on every call;
	 * the axis exists as infrastructure for a follow-up that keys
	 * per-arm state on (context_id, strategy_at_pick).  No hot-path
	 * site reads this field yet, so the stamp is a pure-add. */
	child->context_id = PICKER_CTX_INIT;

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
