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
 * disable_coredumps, read_tainted_mask, and clean_childdata were
 * already exposed via child-internal.h / child-api.h.
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
		struct rlimit unlim = {
			.rlim_cur = RLIM_INFINITY,
			.rlim_max = RLIM_INFINITY
		};

		/*
		 * child_fault_handler (installed via health/signals-policy.c) already
		 * handles the debug-mode re-raise with inline backtrace, shm fault
		 * beacon, psiginfo, and per-pid bug log before re-raising to produce
		 * a core.  No sigaction override to SIG_DFL is needed here; adding
		 * one would silently displace the handler and drop the beacon under -D.
		 */

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
	 * first failer, unlike no_private_ns. */
	if (__atomic_load_n(&shm->no_fail_nth, __ATOMIC_RELAXED))
		return;

	fd = open("/proc/self/fail-nth", O_WRONLY | O_CLOEXEC);
	if (fd == -1) {
		__atomic_store_n(&shm->no_fail_nth, true, __ATOMIC_RELAXED);
		return;
	}

	/* Relocate up out of the low ARG_FD picker range.  Best-effort:
	 * if the dup fails (EMFILE, no free slot above the base), keep
	 * the low fd and let fds-protected catch subsequent attempts on
	 * it.  Mirrors the open_tainted_fd relocation. */
	fd = fd_relocate_high(fd);

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
	 * startup-cache attempt.  get_taint() now also gates its cache
	 * on this_child()==NULL so child hot-path calls never re-cache
	 * a fresh slot here; this close plus that gate together keep
	 * the child's fd table clear of the parent's tainted slot. */
	close_parent_tainted_fd();

	fd = open("/proc/sys/kernel/tainted", O_RDONLY | O_CLOEXEC);
	if (fd == -1) {
		child->tainted_fd = -1;
		child->last_tainted = 0;
		return;
	}

	/* Relocate up out of the low ARG_FD picker range.  Best-effort:
	 * if the dup fails (EMFILE, no free slot above the base), keep
	 * the low fd and let fds-protected catch subsequent attempts on
	 * it. */
	fd = fd_relocate_high(fd);

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
 * The slot's rings are not touched here: reaching them safely takes the
 * slot number, which childdata cannot vouch for.  See reset_child_rings().
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
	/* NR_CHILD_OP_TYPES means "no setup observed yet": the first
	 * productive event bumps the no_setup denominator instead of
	 * crediting the previous occupant's setup.  Paired with the stamp
	 * in child_process() at every is_alt_op dispatch. */
	child->last_setup_op = NR_CHILD_OP_TYPES;
	child->last_setup_op_nr = 0;
	child->stall_count = 0;
	child->stall_last = 0;
	child->fd_created = 0;
	child->fd_closed = 0;
	memset(child->fd_created_by_group, 0, sizeof(child->fd_created_by_group));
	/* F-RSEQ group-pin damper state: a fresh occupant starts with no
	 * streak history. */
	child->group_streak_len = 0;
	child->last_cov_at_streak = 0;
	child->group_fd_created_in_streak = 0;
	clock_gettime(CLOCK_MONOTONIC, &child->tp);

	/* -1 = no syscall picked yet; reward attribution gates on
	 * 0 <= strat < NR_STRATEGIES, so an unstamped slot skips it.
	 * Explorer children bypass the strategy switch and never stamp it,
	 * so it stays -1 for their lifetime. */
	child->strategy_at_pick = -1;

	/* Baseline runs pick under the init-user context on every call. */
	child->context_id = PICKER_CTX_INIT;

	/* Pairs with the per-call reset at the top of set_syscall_nr(): the
	 * first post-call read after fork must not credit the previous
	 * occupant's regime. */
	child->frontier_pick_regime = FRONTIER_PICK_NONE;

	/* Storm-containment counters, with the sliding-window snapshot
	 * reseeded to "now, all zeros" so the first check after fork does
	 * not measure a rate against the previous occupant. */
	child->local_post_handler_corrupt_ptr = 0;
	child->maps_local_refill_credit = 0;
	/* Bump cursors restart at offset 0 in a recycled slot.  Inheriting
	 * the objpool arena's high-water mark would exhaust it early and
	 * force the zmalloc_tracked fallback path sooner. */
	child->writable_pool_cursor = 0;
	child->objpool_arena_cursor = 0;
	child->mmap_pool_nonempty_mask = 0;
	child->storm_check_last_time = child->tp;
	child->storm_check_last_post_handler = 0;

	/* Corruption-attribution shards: a fresh occupant's first dump
	 * window must not carry the previous occupant's counts. */
	memset(child->local_corrupt_ptr_attr, 0,
	       sizeof(child->local_corrupt_ptr_attr));
	memset(child->local_corrupt_ptr_pc, 0,
	       sizeof(child->local_corrupt_ptr_pc));
	memset(child->local_deferred_free_reject_pc, 0,
	       sizeof(child->local_deferred_free_reject_pc));

	/* Zeroed slots are .valid == false, so the parent dumper cannot
	 * mistake the previous occupant's payload for the fresh child's. */
	memset(&child->breadcrumb_ring, 0, sizeof(child->breadcrumb_ring));

	/* -1 marks a live-fd slot empty. */
	for (int i = 0; i < CHILD_FD_RING_SIZE; i++)
		child->live_fds.fds[i] = -1;
	child->live_fds.head = 0;

	/* Zeroed entries are slot.valid == false, so prop_ring_try_get
	 * cannot pick history this occupant never captured. */
	memset(&child->prop_ring, 0, sizeof(child->prop_ring));

	/* UNKNOWN (zeroed) slots are filtered by the post-mortem reader,
	 * so a fresh child contributes nothing until it completes a
	 * syscall. */
	memset(child->syscall_ring.recent, 0, sizeof(child->syscall_ring.recent));
	__atomic_store_n(&child->syscall_ring.head, 0, __ATOMIC_RELAXED);

	/* The post-mortem dumper walks back at most head slots, so a zero
	 * head leaves the previous occupant's events unreachable. */
	memset(&child->pre_crash, 0, sizeof(child->pre_crash));
	__atomic_store_n(&child->pre_crash.base.head, 0, __ATOMIC_RELAXED);

	child->fail_nth_fd = -1;
	child->tainted_fd = -1;
	child->last_tainted = 0;
	child->current_recipe_name = NULL;

	/* Drop the previous occupant's sentinel reading so the first
	 * periodic_work tick re-populates instead of comparing against
	 * state captured in a different child's environment.  The
	 * staggered-capture tick index restarts too, so the first
	 * post-populate tick is at parity 0 (uname). */
	child->sentinel_prev.valid = false;
	child->sentinel_tick_ix = 0;

	/* Clear the cmp_hints seen-bloom so a fresh occupant does not
	 * inherit the previous child's dedup-refresh skips.  Both arch
	 * slots reset together, matching cmp_hints_collect()'s per-arch
	 * indexing. */
	{
		unsigned int a;

		for (a = 0; a < 2; a++) {
			memset(child->cmp_hints_seen[a].bits, 0,
			       sizeof(child->cmp_hints_seen[a].bits));
			child->cmp_hints_seen[a].records = 0;
		}
	}

	memset(child->reexec_pending, 0, sizeof(child->reexec_pending));
	child->reexec_pending_count = 0;
	child->in_reexec = false;
	child->fuzz_shm_count = 0;	/* fresh occupant: no tracked shm segments yet */
	child->fuzz_msg_count = 0;	/* fresh occupant: no tracked msg queues yet */
	child->fuzz_sem_count = 0;	/* fresh occupant: no tracked sem sets yet */
	/* The A/B stamps below (redqueen_enabled and the *_arm_b flags) are
	 * (re)decided per child in init_child_ab_stamps() once
	 * kcov_init_child() has picked the KCOV mode.  Until then a fresh
	 * occupant is on Arm A, the baseline behaviour. */
	child->redqueen_enabled = false;
	child->boring_filter_arm_b = false;
	child->frontier_blend_arm_b = false;
	child->frontier_errno_decay_arm_b = false;
	child->frontier_silent_decay_arm_b = false;
	child->remote_adaptive_arm_b = false;
	child->reexec_count_window = 0;
	child->reexec_window_start_op = 0;
	child->cmp_hint_injected_this_call = false;
	/* --blob-ab-mode per-call stamp: the dispatch-site credit block
	 * must not attribute the previous occupant's pick.  Re-cleared at
	 * the top of generate_syscall_args() every call. */
	child->blob_ab_mode_last = BLOB_AB_MODE_NONE;
	child->cmp_hint_inject_arm_b = false;
	child->prop_ring_argop_arm_b = false;
	child->mut_structured_arm_b = false;
	child->prop_ring_typed_arm_b = false;
	/* generate_syscall_args() also resets the cmp-hint feedback stash
	 * at every call; clearing it here keeps the first call after fork
	 * from seeing the previous occupant's entries. */
	memset(child->cmp_hints_consumed_stash, 0,
	       sizeof(child->cmp_hints_consumed_stash));
	child->cmp_hints_consumed_count = 0;

	reset_child_fault_beacons(child);
}
