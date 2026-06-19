/*
 * Each process that gets forked runs this code.
 */

#include <fcntl.h>
#include <errno.h>
#include <malloc.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/personality.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/capability.h>

#include "arch.h"
#include "child.h"
#include "fd.h"
#include "futex.h"
#include "fd-event.h"
#include "kcov.h"
#include "list.h"
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
#include "strategy.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"	// ARRAY_SIZE
#include "uid.h"
#include "deferred-free.h"
#include "sanitise.h"
#include "sequence.h"
#include "utils.h"	// zmalloc
#include "vma-pressure.h"

/*
 * Pin op_nr — the trailing field of the per-syscall hot block — to an
 * offset under 64 so a future field reorder that moves any of the hot
 * block (kcov, last_group, op_nr) past the leading cacheline boundary
 * fails the build instead of silently regressing the per-call
 * cache-miss budget the layout was tuned for.
 */
_Static_assert(offsetof(struct childdata, op_nr) < 64,
	"struct childdata: op_nr (per-syscall hot field) escaped the leading cacheline");

/*
 * Pin the syscallrecord (and therefore its trailing seq counter, mutated
 * by every writer via srec_publish_begin / srec_publish_end) to an
 * offset >= 64 so a future field reorder that drags the cold per-call
 * record into the hot cacheline fails the build instead of silently
 * blowing the per-call cache-miss budget the layout was tuned for.
 */
_Static_assert(offsetof(struct childdata, syscall) >= 64,
	"struct childdata: syscallrecord drifted into the hot cacheline");

/*
 * Pin the kcov local-stats staging pointer (a cold field, touched
 * only on the periodic-flush path) outside the leading hot cacheline
 * so a future field reorder that drags it into the per-syscall hot
 * block fails the build instead of silently shrinking the budget the
 * kcov / last_group / op_nr triplet was tuned to fit.
 */
_Static_assert(offsetof(struct childdata, local_stats) >= 64,
	"struct childdata: local_stats drifted into the hot cacheline");

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
 * Temporarily exempt a child from reaper kills while it is in a critical
 * section that may legitimately exceed the normal timeout, such as lock
 * recovery or crash-log dumping.
 */
void set_dontkillme(struct childdata *child, bool state)
{
	if (child == NULL)	/* possible, we might be the mainpid */
		return;
	child->dontkillme = state;

	/* bump the progress indicator */
	clock_gettime(CLOCK_MONOTONIC, &child->tp);
}

void child_fd_ring_push(struct child_fd_ring *ring, int fd)
{
	ring->fds[ring->head % CHILD_FD_RING_SIZE] = fd;
	ring->head++;
}

/*
 * Sentinel-out any occurrences of `fd` in the ring.  Called from
 * close-like post handlers when the child knows an fd has just been
 * closed, so subsequent get_child_live_fd() picks don't waste an
 * fcntl(F_GETFD) syscall validating a known-dead entry.  Scans all 16
 * slots — bounded constant work; cheaper than the avoided fcntl.
 */
void child_fd_ring_remove(struct child_fd_ring *ring, int fd)
{
	int i;

	if (fd <= 2)
		return;
	for (i = 0; i < CHILD_FD_RING_SIZE; i++) {
		if (ring->fds[i] == fd)
			ring->fds[i] = -1;
	}
}

/*
 * Sentinel-out any ring entries whose fd falls within [lo, hi].
 * For close_range() post handlers — one pass over the ring instead of
 * `hi - lo + 1` calls to child_fd_ring_remove().
 */
void child_fd_ring_remove_range(struct child_fd_ring *ring, int lo, int hi)
{
	int i;

	for (i = 0; i < CHILD_FD_RING_SIZE; i++) {
		int fd = ring->fds[i];

		if (fd > 2 && fd >= lo && fd <= hi)
			ring->fds[i] = -1;
	}
}

/*
 * Single-producer push: extract the structured fields the post-mortem
 * reader consumes into the chronicle slot, then publish the new head
 * with a release-store so the reader observes a fully-written entry
 * when it sees the matching head value.  Field-by-field instead of a
 * struct copy because struct syscallrecord is dominated by the 4 KiB
 * pre-rendered prebuffer the post-mortem path doesn't need.
 */
void child_syscall_ring_push(struct child_syscall_ring *ring,
			     const struct syscallrecord *rec)
{
	struct chronicle_slot *slot;
	uint32_t head;

	head = __atomic_load_n(&ring->head, __ATOMIC_RELAXED);
	slot = &ring->recent[head & (CHILD_SYSCALL_RING_SIZE - 1)];

	slot->tp = rec->tp;
	slot->a1 = rec->a1;
	slot->a2 = rec->a2;
	slot->a3 = rec->a3;
	slot->a4 = rec->a4;
	slot->a5 = rec->a5;
	slot->a6 = rec->a6;
	slot->retval = rec->retval;
	slot->nr = rec->nr;
	slot->errno_post = rec->errno_post;
	slot->do32bit = rec->do32bit;
	slot->valid = true;

	__atomic_store_n(&ring->head, head + 1, __ATOMIC_RELEASE);
}

/*
 * For the child processes, we don't want core dumps (unless we're running with -D)
 * This is because it's not uncommon for us to get segfaults etc when we're doing
 * syscalls with garbage for arguments.
 */
static void disable_coredumps(void)
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

static void enable_coredumps(void)
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
	 * (childops/iouring-recipes.c) rather than the no_private_ns pattern. */
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
static unsigned long read_tainted_mask(int fd)
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
 * Tweak the oom_score_adj setting for our child so that there's a higher
 * chance that the oom-killer kills our processes rather than something
 * more important.
 */
void oom_score_adj(int adj)
{
	FILE *fp;

	fp = fopen("/proc/self/oom_score_adj", "w");
	if (!fp)
		return;

	fprintf(fp, "%d", adj);
	fclose(fp);
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
	child->dontkillme = false;
	child->xcpu_count = 0;
	child->op_nr = 0;
	child->current_fd = -1;
	child->fd_lifetime = 0;
	child->cached_fd_generation = 0;
	child->last_group = GROUP_NONE;
	child->in_chain_mid_step = false;
	child->op_type = CHILD_OP_SYSCALL;
	child->stall_count = 0;
	child->stall_last = 0;
	child->fd_created = 0;
	child->fd_closed = 0;
	memset(child->fd_created_by_group, 0, sizeof(child->fd_created_by_group));
	clock_gettime(CLOCK_MONOTONIC, &child->tp);

	/* -1 sentinel = "no syscall picked yet on this child".  Reward
	 * attribution gates on (strat >= 0 && strat < NR_STRATEGIES), so an
	 * unstamped slot naturally skips attribution.  Explorer children
	 * never write this field (they bypass the strategy switch entirely
	 * in set_syscall_nr), so the sentinel persists for their lifetime;
	 * the PC and CMP reward sites also gate on !is_explorer ahead of the
	 * stamp read for clarity. */
	child->strategy_at_pick = -1;

	/* Reset per-child storm-containment counters and reseed the
	 * sliding-window snapshot to "right now, all zeros" so the first
	 * check after fork has a clean baseline rather than measuring a
	 * rate against the previous occupant of this slot. */
	child->local_post_handler_corrupt_ptr = 0;
	child->local_scribbled_slots_caught = 0;
	child->maps_local_refill_credit = 0;
	child->mmap_pool_nonempty_mask = 0;
	child->storm_check_last_time = child->tp;
	child->storm_check_last_post_handler = 0;
	child->storm_check_last_scribbled = 0;

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

	/* Clear any __BUG() stamp left by the prior occupant of this slot
	 * so the parent's zombie-pending warning doesn't mis-attribute the
	 * fresh child's eventual exit to the previous one's assertion.
	 * bug_dumped + bug_backtrace.count must clear in lock-step so the
	 * fresh occupant's first BUG re-triggers the parent's dump path
	 * instead of being suppressed by the previous occupant's latched
	 * flag, and so dump_child_bug doesn't see stale frames if the
	 * fresh occupant BUGs before its own backtrace stamp lands. */
	child->hit_bug = false;
	child->bug_dumped = false;
	__atomic_store_n(&child->bug_backtrace.count, 0, __ATOMIC_RELAXED);
	child->bug_text = NULL;
	child->bug_func = NULL;
	child->bug_lineno = 0;

	/* Same teardown for the signal-time fault beacon: clear the
	 * .written edge-trigger and the parent-side fault_beacon_dumped
	 * latch in lock-step so the fresh occupant's first fault
	 * re-triggers dump_child_fault_beacon instead of being suppressed
	 * by the previous occupant's idempotency flag, and so the dumper
	 * doesn't observe stale ip/sp/addr fields. */
	__atomic_store_n(&child->fault_beacon.written, 0U, __ATOMIC_RELAXED);
	child->fault_beacon_dumped = false;

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

	/* Additional namespace diversity on top of what init_child already does. */
	for (i = 0; i < ARRAY_SIZE(extra_ns_flags); i++) {
		if (RAND_BOOL())
			unshare(extra_ns_flags[i]);
	}

	/* Random personality — stay within PER_LINUX family to remain sane. */
	personality(RAND_ARRAY(personas));

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
		close(fd);
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
static void freeze_sibling_childdata(int my_childno)
{
	unsigned int i;

	for_each_child(i) {
		if ((unsigned int)my_childno == i)
			continue;
		if (children[i] == NULL)
			continue;
		if (mprotect(children[i], sizeof(struct childdata), PROT_READ) != 0) {
			outputerr("freeze_sibling_childdata: mprotect(sibling %u childdata) failed: %s\n",
				  i, strerror(errno));
			__atomic_add_fetch(&shm->stats.sibling_mprotect_failed, 1,
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
	devnull = open("/dev/null", O_RDWR);
	if (devnull >= 0) {
		dup2(devnull, STDIN_FILENO);
		dup2(devnull, STDOUT_FILENO);
		dup2(devnull, STDERR_FILENO);
		if (devnull > STDERR_FILENO)
			close(devnull);
	}

	/* Drop the inherited --stats-log-file fd before any syscall fuzzing
	 * starts: it's a parent-only writer, but children would otherwise
	 * reach it numerically via fchmod / ftruncate / write at random
	 * offset, smashing the operator's log mid-run. */
	stats_log_drop_in_child();

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
	if (mprotect(pids, max_children * sizeof(*pids), PROT_READ) != 0) {
		outputerr("init_child: mprotect(pids[]) failed: %s\n", strerror(errno));
		__atomic_add_fetch(&shm->stats.sibling_mprotect_failed, 1,
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
			__atomic_add_fetch(&shm->stats.child_dead_parent_observed,
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
	/* Wait for all the children to start up. */
	while (!__atomic_load_n(&shm->ready, __ATOMIC_ACQUIRE))
		sleep(1);

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
	 * Best-effort: ignore the return; if no file cap was applied the
	 * child has no caps anyway and this is a harmless no-op.
	 */
	{
		struct __user_cap_header_struct hdr = {
			.version = _LINUX_CAPABILITY_VERSION_3,
			.pid = 0,
		};
		struct __user_cap_data_struct data[2] = { {0}, {0} };
		(void) syscall(__NR_capset, &hdr, data);
	}

	munge_process();
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
	kcov_init_child(&child->kcov, child->num);

	/* Per-child staging buffer for the kcov global counters.  Pure
	 * plumbing in this commit -- nothing bumps these fields yet and
	 * kcov_child_flush_stats() is a no-op stub.  calloc post-fork
	 * keeps the allocation child-private (matches kc->dedup); an
	 * alloc failure leaves the pointer NULL and the future bumpers
	 * / flush path will gate on local_stats != NULL. */
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
			__atomic_fetch_add(&kcov_shm->cmp_inject_arm_b_children,
					   1U, __ATOMIC_RELAXED);
		else
			__atomic_fetch_add(&kcov_shm->cmp_inject_arm_a_children,
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
			__atomic_fetch_add(&kcov_shm->frontier_blend_arm_b_children,
					   1U, __ATOMIC_RELAXED);
		else
			__atomic_fetch_add(&kcov_shm->frontier_blend_arm_a_children,
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
			__atomic_fetch_add(&kcov_shm->frontier_errno_decay_arm_b_children,
					   1U, __ATOMIC_RELAXED);
		else
			__atomic_fetch_add(&kcov_shm->frontier_errno_decay_arm_a_children,
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
			__atomic_fetch_add(&kcov_shm->frontier_silent_decay_arm_b_children,
					   1U, __ATOMIC_RELAXED);
		else
			__atomic_fetch_add(&kcov_shm->frontier_silent_decay_arm_a_children,
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
			__atomic_fetch_add(&kcov_shm->remote_adaptive_arm_b_children,
					   1U, __ATOMIC_RELAXED);
		else
			__atomic_fetch_add(&kcov_shm->remote_adaptive_arm_a_children,
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
			__atomic_fetch_add(&kcov_shm->prop_ring_argop_arm_b_children,
					   1U, __ATOMIC_RELAXED);
		else
			__atomic_fetch_add(&kcov_shm->prop_ring_argop_arm_a_children,
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
			__atomic_fetch_add(&kcov_shm->prop_ring_typed_arm_b_children,
					   1U, __ATOMIC_RELAXED);
		else
			__atomic_fetch_add(&kcov_shm->prop_ring_typed_arm_a_children,
					   1U, __ATOMIC_RELAXED);
	}

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
 * Called from the fork_children loop in the main process.
 */
static void init_child(struct childdata *child, int childno)
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
	init_abort_msg_capture();
}

/*
 * Sanity check to make sure that the main process is still around
 * to wait for us.
 */
static void check_parent_pid(void)
{
	pid_t pid, ppid;

	ppid = getppid();
	if (ppid == mainpid)
		return;

	pid = mypid();

	/*
	 * Inside a PID namespace our parent may legitimately be pid 1
	 * (the namespace init) or we ourselves may be pid 1.  Either
	 * case is expected when CLONE_NEWPID is in play — just bail
	 * out of this child quietly rather than triggering a panic.
	 */
	if (pid == 1 || ppid == 1) {
		debugf("pidns detected (pid=%d ppid=%d), exiting child.\n", pid, ppid);
		_exit(EXIT_REPARENT_PROBLEM);
	}

	if (pid == ppid) {
		debugf("pid became ppid! exiting child.\n");
		_exit(EXIT_REPARENT_PROBLEM);
	}

	if (ppid < 2) {
		debugf("ppid == %d. pidns? exiting child.\n", ppid);
		_exit(EXIT_REPARENT_PROBLEM);
	}

	lock(&shm->buglock);

	if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) == EXIT_REPARENT_PROBLEM)
		goto out;

	output(0, "BUG!: CHILD (pid:%d) GOT REPARENTED! "
		"main pid:%d. ppid=%d\n",
		pid, mainpid, ppid);

	if (pid_alive(mainpid) == false)
		output(0, "main pid %d is dead.\n", mainpid);

	panic(EXIT_REPARENT_PROBLEM);

out:
	unlock(&shm->buglock);
	_exit(EXIT_REPARENT_PROBLEM);
}

/*
 * Here we call various functions that perform checks/changes that
 * we don't want to happen on every iteration of the child loop.
 *
 * The caller gates entry on (op_nr & 15) == 0, so reaching here is
 * already the "every 16 iterations" event — check_parent_pid and the
 * divergence sentinel run unconditionally.  The deeper 128-iteration
 * gate is folded into the op_nr argument so this function carries no
 * static state at all.
 */
static void periodic_work(struct childdata *child, unsigned long op_nr)
{
	check_parent_pid();

	divergence_sentinel_tick(child);

	/* Sampled invariant asserting the init_child_setup_sandbox()
	 * capset()-to-empty drop held.  Self-gates on ONE_IN(N) so the
	 * four bare-syscall probes (bpf, mount, setsockopt, capget) pay
	 * their cost only on the sample tick.  See child-capdrop-oracle.c. */
	capdrop_oracle_tick();

	/* Global VMA-pressure watchdog: sample the child's live VMA count
	 * every VMA_PRESSURE_SAMPLE_PERIOD ops and latch a per-child
	 * flag the heavy-VMA childops poll at iteration top.  Cadence and
	 * cost are documented in mm/vma-pressure.c; cheap when latched
	 * LOW, bounded when latched HIGH (only the backoff regime pays). */
	vma_pressure_sample_maybe(op_nr);

	/* Every 128 iterations.  Skip the maps-dirty + fd-provider fuzzing
	 * passes under -c/-r/-g so a targeted-syscall run stays isolated to
	 * the syscall set the user asked for; the picker gate in
	 * child_process() handles the per-iteration alt-op leak, this
	 * handles the periodic-work leak that lives outside that picker.
	 * check_parent_pid + divergence_sentinel + vma_pressure stay
	 * unconditional -- those are watchdog / diagnostic work, not
	 * fuzzing. */
	if ((op_nr & 127) == 0 &&
	    !do_specific_syscall && !random_selection &&
	    desired_group == GROUP_NONE) {
		dirty_random_mapping();
		run_fd_provider_child_ops();
	}
}

/*
 * Per-op-type stall thresholds.  Syscalls are fast, so 10 missed
 * progress checks means something is stuck.  Future op types that do
 * heavier work (fault injection, fd lifecycle stress) get more slack.
 */
static unsigned int stall_threshold(enum child_op_type op_type)
{
	switch (op_type) {
	case CHILD_OP_MMAP_LIFECYCLE:	return 30;
	case CHILD_OP_MPROTECT_SPLIT:	return 30;
	case CHILD_OP_MLOCK_PRESSURE:	return 50;
	case CHILD_OP_INODE_SPEWER:		return 40;
	case CHILD_OP_PROCFS_WRITER:		return 60;
	case CHILD_OP_MEMORY_PRESSURE:		return 30;
	case CHILD_OP_USERNS_FUZZER:		return 60;
	case CHILD_OP_SCHED_CYCLER:		return 30;
	case CHILD_OP_BARRIER_RACER:		return 30;
	case CHILD_OP_GENETLINK_FUZZER:		return 30;
	case CHILD_OP_PERF_CHAINS:		return 30;
	case CHILD_OP_TRACEFS_FUZZER:		return 60;
	case CHILD_OP_BPF_LIFECYCLE:		return 40;
	case CHILD_OP_FAULT_INJECTOR:		return 20;
	case CHILD_OP_RECIPE_RUNNER:		return 40;
	case CHILD_OP_IOURING_RECIPES:		return 40;
	case CHILD_OP_FD_STRESS:		return 30;
	case CHILD_OP_FS_LIFECYCLE:		return 60;
	case CHILD_OP_FLOCK_THRASH:		return 30;
	case CHILD_OP_PIDFD_STORM:		return 30;
	case CHILD_OP_MADVISE_CYCLER:		return 30;
	case CHILD_OP_KEYRING_SPAM:		return 30;
	case CHILD_OP_VDSO_MREMAP_RACE:		return 30;
	case CHILD_OP_NUMA_MIGRATION:		return 40;
	case CHILD_OP_CPU_HOTPLUG_RIDER:	return 50;
	case CHILD_OP_CGROUP_CHURN:		return 30;
	case CHILD_OP_MOUNT_CHURN:		return 40;
	case CHILD_OP_NAT_T_CHURN:		return 40;
	case CHILD_OP_UFFD_CHURN:		return 30;
	case CHILD_OP_IOURING_FLOOD:		return 30;
	case CHILD_OP_CLOSE_RACER:		return 30;
	case CHILD_OP_XATTR_THRASH:		return 30;
	case CHILD_OP_EPOLL_VOLATILITY:		return 30;
	case CHILD_OP_SLAB_CACHE_THRASH:	return 30;
	case CHILD_OP_TLS_ROTATE:		return 30;
	case CHILD_OP_SOCK_ULP_SOCKMAP_LAYERING:	return 30;
	case CHILD_OP_PACKET_FANOUT_THRASH:	return 30;
	case CHILD_OP_SPLICE_PROTOCOLS:		return 30;
	case CHILD_OP_RXRPC_KEY_INSTALL:	return 30;
	case CHILD_OP_AF_ALG_WEAK_CIPHER_PROBE:	return 20;
	case CHILD_OP_AF_ALG_TEMPLATE_PROBE:	return 20;
	case CHILD_OP_TTY_LDISC_CHURN:		return 30;
	default:				return 10;
	}
}

/*
 * Stall detection: count consecutive alarm timeouts without the child
 * making forward progress (op_nr advancing).  If the child is stuck,
 * exit it so the parent can respawn a fresh one.
 */
static bool check_stall(struct childdata *child)
{
	if (child->op_nr == child->stall_last) {
		child->stall_count++;
	} else {
		child->stall_count = 0;
		child->stall_last = child->op_nr;
	}
	if (child->stall_count >= stall_threshold(child->op_type)) {
		output(1, "no progress for %u tries (op_type=%d), exiting child.\n",
			child->stall_count, child->op_type);
		return true;
	}
	return false;
}


#define FD_LEAK_THRESHOLD 50

static void check_fd_leaks(struct childdata *child)
{
	static const char * const group_names[NR_GROUPS] = {
		[GROUP_NONE] = "none",
		[GROUP_VM] = "vm",
		[GROUP_VFS] = "vfs",
		[GROUP_NET] = "net",
		[GROUP_IPC] = "ipc",
		[GROUP_PROCESS] = "process",
		[GROUP_SIGNAL] = "signal",
		[GROUP_IO_URING] = "io_uring",
		[GROUP_BPF] = "bpf",
		[GROUP_SCHED] = "sched",
		[GROUP_TIME] = "time",
		[GROUP_XATTR] = "xattr",
	};
	long delta;
	unsigned int i;

	if (child->fd_created < child->fd_closed)
		return;

	delta = (long)(child->fd_created - child->fd_closed);
	if (delta <= FD_LEAK_THRESHOLD)
		return;

	output(0, "fd leak: child %d created %lu closed %lu (delta %ld, %lu ops)\n",
		child->num, child->fd_created, child->fd_closed,
		delta, child->op_nr);

	for (i = 0; i < NR_GROUPS; i++) {
		if (child->fd_created_by_group[i] > 0)
			output(0, "  group %-10s: %lu fds created\n",
				group_names[i], child->fd_created_by_group[i]);
	}
}

/*
 * Startup snapshot of the dormant-op gate consulted by init_altop_dispatch()
 * to build the dense enabled_altops[] vector.  Mutated at runtime by the
 * parent's queue transition path (enter_canarying / close_window_and_decide);
 * to check what's CURRENTLY active, read the periodic `canary queue:` log
 * lines and see canary_queue_init() in child-canary.c, not this table.
 *
 * Slot ordering matches pick_op_type_table[]; the _Static_assert below
 * pins ARRAY_SIZE equality between the two.
 */
static int dormant_op_disabled[117] = {
	0, 0, 0, 0, 0,
	0, 1, 1, 1, 1,
	1, 1, 1, 0, 1,
	1, 0, 0, 1, 1,
	1, 1, 1, 1, 1,
	1, 1, 1, 1, 1,
	1, 1, 1, 1, 1,
	1, 1, 1, 0, 1,
	1, 1, 1, 1, 1,
	1, 1, 1, 1, 1,
	1, 1, 1, 1, 1,
	1, 1, 1, 1, 1,
	1, 1, 1, 1, 1,
	1, 1, 1, 1, 0,
	1, 1,
	1, 1, 1, 1, 1, 1,
	0,	/* pagecache_canary_check stays active: it's an in-tree verifier, not a fuzz target the queue should ever demote. */
	1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1,
	0,	/* eth_emitter is lightweight (one socket per child, fixed-size sendto) — promote at startup. */
	1,	/* sysfs_string_race: dormant until canary-queue load-tests the .store() race burst. */
	1,	/* pci_bind: dormant until canary-queue load-tests the driver attach/detach path on the conservative allowlist. */
	1,	/* iscsi_login_walker: dormant until canary-queue load-tests the LIO Login state-machine walk. */
	1,	/* vma_split_storm: dormant until canary-queue load-tests the heavy VMA-split mm pressure burst. */
	1,	/* af_unix_peek_race: dormant until canary-queue load-tests the SO_PEEK_OFF + MSG_PEEK/recv/shutdown race burst. */
	1,	/* sysv_shm_orphan_race: dormant until canary-queue load-tests the SysV SHM orphan-destroy attach/RMID race burst. */
	1,	/* qrtr_bind_race: dormant until canary-queue load-tests the AF_QRTR same-port bind/close race burst. */
	1,	/* tc_mirred_blockcast: dormant until canary-queue load-tests the clsact + shared egress block + mirred blockcast recursion burst. */
	1,	/* pfkey_spd_walk: dormant until canary-queue load-tests the PF_KEYv2 SPDDUMP-vs-SPDADD walk-race burst. */
	1,	/* l2tp_ifname_race: dormant until canary-queue load-tests the L2TP SESSION_CREATE same-ifname race burst. */
	1,	/* statmount_idmap_overflow: dormant until canary-queue load-tests the statmount() idmap seq-buffer overflow sweep. */
	1,	/* sock_ulp_sockmap_layering: dormant until canary-queue load-tests the TCP_ULP "tls" + sockmap STREAM_VERDICT layering burst. */
	1,	/* umount_race: dormant until canary-queue load-tests the umount2(MNT_DETACH)-vs-accessor race against scratch_block-published mounts. */
};

/*
 * Round-robin rotation for dedicated alt-op children.  The slow,
 * pressure-style ops are listed first (mmap_lifecycle, mprotect_split,
 * mlock_pressure, inode_spewer) because those are the paths the design
 * brief explicitly calls out as too expensive to mix into the syscall
 * hot loop even at 1%.  fork/futex/signal/pipe/flock storms come next,
 * then the cgroup/mount/uffd/io_uring churners, and finally the heavier
 * subsystem fuzzers (perf, tracefs, bpf, fault-injector, recipes).  The
 * dispatch in child_process() already has cases for every entry below,
 * so a dedicated child stamped with any of these op types runs straight
 * through the existing per-op function on every iteration.
 *
 * Bypasses the dormant_op_disabled[] gate by design: random pickers stay
 * gated until each op has been load-tested, but a child reserved for a
 * specific op runs it deliberately.
 */
static const enum child_op_type alt_op_rotation[] = {
	CHILD_OP_MMAP_LIFECYCLE,
	CHILD_OP_MPROTECT_SPLIT,
	CHILD_OP_VMA_SPLIT_STORM,
	CHILD_OP_MADVISE_CYCLER,
	CHILD_OP_NUMA_MIGRATION,
	CHILD_OP_MLOCK_PRESSURE,
	CHILD_OP_INODE_SPEWER,
	CHILD_OP_FORK_STORM,
	CHILD_OP_CPU_HOTPLUG_RIDER,
	CHILD_OP_PIDFD_STORM,
	CHILD_OP_FUTEX_STORM,
	CHILD_OP_SIGNAL_STORM,
	CHILD_OP_PIPE_THRASH,
	CHILD_OP_FLOCK_THRASH,
	CHILD_OP_XATTR_THRASH,
	CHILD_OP_CGROUP_CHURN,
	CHILD_OP_MOUNT_CHURN,
	CHILD_OP_UFFD_CHURN,
	CHILD_OP_IOURING_FLOOD,
	CHILD_OP_CLOSE_RACER,
	CHILD_OP_EPOLL_VOLATILITY,
	CHILD_OP_KEYRING_SPAM,
	CHILD_OP_VDSO_MREMAP_RACE,
	CHILD_OP_MEMORY_PRESSURE,
	CHILD_OP_SLAB_CACHE_THRASH,
	CHILD_OP_TLS_ROTATE,
	CHILD_OP_SOCK_ULP_SOCKMAP_LAYERING,
	CHILD_OP_PACKET_FANOUT_THRASH,
	CHILD_OP_ETH_EMITTER,
	CHILD_OP_USERNS_FUZZER,
	CHILD_OP_SCHED_CYCLER,
	CHILD_OP_BARRIER_RACER,
	CHILD_OP_GENETLINK_FUZZER,
	CHILD_OP_PERF_CHAINS,
	CHILD_OP_TRACEFS_FUZZER,
	CHILD_OP_BPF_LIFECYCLE,
	CHILD_OP_FAULT_INJECTOR,
	CHILD_OP_RECIPE_RUNNER,
	CHILD_OP_IOURING_RECIPES,
	CHILD_OP_FD_STRESS,
	CHILD_OP_REFCOUNT_AUDITOR,
	CHILD_OP_FS_LIFECYCLE,
	CHILD_OP_PROCFS_WRITER,
	CHILD_OP_SOCKET_FAMILY_CHAIN,
	CHILD_OP_IOURING_NET_MULTISHOT,
	CHILD_OP_TCP_AO_ROTATE,
	CHILD_OP_VRF_FIB_CHURN,
	CHILD_OP_NETLINK_MONITOR_RACE,
	CHILD_OP_TIPC_LINK_CHURN,
	CHILD_OP_TLS_ULP_CHURN,
	CHILD_OP_VXLAN_ENCAP_CHURN,
	CHILD_OP_BRIDGE_FDB_STP,
	CHILD_OP_NFTABLES_CHURN,
	CHILD_OP_TC_QDISC_CHURN,
	CHILD_OP_XFRM_CHURN,
	CHILD_OP_BPF_CGROUP_ATTACH,
	CHILD_OP_SCTP_ASSOC_CHURN,
	CHILD_OP_MPTCP_PM_CHURN,
	CHILD_OP_NL80211_CHURN,
	CHILD_OP_NAT_T_CHURN,
	CHILD_OP_SOCK_DIAG_WALKER,
	CHILD_OP_ALTNAME_THRASH,
	CHILD_OP_OVS_TUNNEL_VPORT_CHURN,
	CHILD_OP_TTY_LDISC_CHURN,
	CHILD_OP_UMOUNT_RACE,
};
#define NR_ALT_OP_ROTATION	ARRAY_SIZE(alt_op_rotation)

/*
 * KCOV bracketing opt-in.  Read by the childop dispatcher.
 * Defaults to true for every op.
 * CHILD_OP_SYSCALL falls through to run_sequence_chain
 * which brackets per-syscall internally.  CHILD_OP_SCHED_CYCLER
 * (childops/sched-cycler.c) calls random_syscall(child) in
 * a tight loop; an outer bracket would double-call
 * ioctl(KCOV_ENABLE) and the kernel returns -EBUSY which
 * kcov_enable_trace currently treats as fatal.
 *
 * Expressed as an accessor so new enum members default to
 * eligible without per-table maintenance and without the
 * [0 ... N-1] = true designated-init override idiom, which
 * trips -Woverride-init on this codebase's -Wextra build.
 * Compiler folds the switch into a constant-time check at
 * the future call site.
 */
static bool op_uses_outer_bracket(enum child_op_type op)
{
	switch (op) {
	case CHILD_OP_SYSCALL:
	case CHILD_OP_SCHED_CYCLER:
		return false;
	default:
		return true;
	}
}

const char *alt_op_name(enum child_op_type op)
{
	switch (op) {
	case CHILD_OP_SYSCALL:		return "syscall";
	case CHILD_OP_MMAP_LIFECYCLE:	return "mmap_lifecycle";
	case CHILD_OP_MPROTECT_SPLIT:	return "mprotect_split";
	case CHILD_OP_MLOCK_PRESSURE:	return "mlock_pressure";
	case CHILD_OP_INODE_SPEWER:	return "inode_spewer";
	case CHILD_OP_PROCFS_WRITER:	return "procfs_writer";
	case CHILD_OP_MEMORY_PRESSURE:	return "memory_pressure";
	case CHILD_OP_USERNS_FUZZER:	return "userns_fuzzer";
	case CHILD_OP_SCHED_CYCLER:	return "sched_cycler";
	case CHILD_OP_BARRIER_RACER:	return "barrier_racer";
	case CHILD_OP_GENETLINK_FUZZER:	return "genetlink_fuzzer";
	case CHILD_OP_PERF_CHAINS:	return "perf_chains";
	case CHILD_OP_TRACEFS_FUZZER:	return "tracefs_fuzzer";
	case CHILD_OP_BPF_LIFECYCLE:	return "bpf_lifecycle";
	case CHILD_OP_FAULT_INJECTOR:	return "fault_injector";
	case CHILD_OP_RECIPE_RUNNER:	return "recipe_runner";
	case CHILD_OP_IOURING_RECIPES:	return "iouring_recipes";
	case CHILD_OP_FD_STRESS:	return "fd_stress";
	case CHILD_OP_REFCOUNT_AUDITOR:	return "refcount_auditor";
	case CHILD_OP_FS_LIFECYCLE:	return "fs_lifecycle";
	case CHILD_OP_SIGNAL_STORM:	return "signal_storm";
	case CHILD_OP_FUTEX_STORM:	return "futex_storm";
	case CHILD_OP_PIPE_THRASH:	return "pipe_thrash";
	case CHILD_OP_FORK_STORM:	return "fork_storm";
	case CHILD_OP_FLOCK_THRASH:	return "flock_thrash";
	case CHILD_OP_CGROUP_CHURN:	return "cgroup_churn";
	case CHILD_OP_MOUNT_CHURN:	return "mount_churn";
	case CHILD_OP_UFFD_CHURN:	return "uffd_churn";
	case CHILD_OP_IOURING_FLOOD:	return "iouring_flood";
	case CHILD_OP_CLOSE_RACER:	return "close_racer";
	case CHILD_OP_SOCKET_FAMILY_CHAIN:	return "socket_family_chain";
	case CHILD_OP_XATTR_THRASH:	return "xattr_thrash";
	case CHILD_OP_PIDFD_STORM:	return "pidfd_storm";
	case CHILD_OP_MADVISE_CYCLER:	return "madvise_cycler";
	case CHILD_OP_EPOLL_VOLATILITY:	return "epoll_volatility";
	case CHILD_OP_KEYRING_SPAM:	return "keyring_spam";
	case CHILD_OP_VDSO_MREMAP_RACE:	return "vdso_mremap_race";
	case CHILD_OP_NUMA_MIGRATION:	return "numa_migration";
	case CHILD_OP_CPU_HOTPLUG_RIDER: return "cpu_hotplug_rider";
	case CHILD_OP_SLAB_CACHE_THRASH: return "slab_cache_thrash";
	case CHILD_OP_TLS_ROTATE:	return "tls_rotate";
	case CHILD_OP_SOCK_ULP_SOCKMAP_LAYERING:	return "sock_ulp_sockmap_layering";
	case CHILD_OP_PACKET_FANOUT_THRASH:	return "packet_fanout_thrash";
	case CHILD_OP_IOURING_NET_MULTISHOT:	return "iouring_net_multishot";
	case CHILD_OP_TCP_AO_ROTATE:	return "tcp_ao_rotate";
	case CHILD_OP_VRF_FIB_CHURN:	return "vrf_fib_churn";
	case CHILD_OP_NETLINK_MONITOR_RACE:	return "netlink_monitor_race";
	case CHILD_OP_TIPC_LINK_CHURN:	return "tipc_link_churn";
	case CHILD_OP_TLS_ULP_CHURN:	return "tls_ulp_churn";
	case CHILD_OP_VXLAN_ENCAP_CHURN:	return "vxlan_encap_churn";
	case CHILD_OP_BRIDGE_FDB_STP:	return "bridge_fdb_stp";
	case CHILD_OP_NFTABLES_CHURN:	return "nftables_churn";
	case CHILD_OP_TC_QDISC_CHURN:	return "tc_qdisc_churn";
	case CHILD_OP_XFRM_CHURN:	return "xfrm_churn";
	case CHILD_OP_BPF_CGROUP_ATTACH:	return "bpf_cgroup_attach";
	case CHILD_OP_SCTP_ASSOC_CHURN:	return "sctp_assoc_churn";
	case CHILD_OP_MPTCP_PM_CHURN:	return "mptcp_pm_churn";
	case CHILD_OP_DEVLINK_PORT_CHURN:	return "devlink_port_churn";
	case CHILD_OP_HANDSHAKE_REQ_ABORT:	return "handshake_req_abort";
	case CHILD_OP_NF_CONNTRACK_HELPER:	return "nf_conntrack_helper_churn";
	case CHILD_OP_AF_UNIX_SCM_RIGHTS_GC:	return "af_unix_scm_rights_gc_churn";
	case CHILD_OP_NETNS_TEARDOWN_CHURN:	return "netns_teardown_churn";
	case CHILD_OP_TCP_ULP_SWAP_CHURN:	return "tcp_ulp_swap_churn";
	case CHILD_OP_MSG_ZEROCOPY_CHURN:	return "msg_zerocopy_churn";
	case CHILD_OP_IOURING_SEND_ZC_CHURN:	return "iouring_send_zc_churn";
	case CHILD_OP_VSOCK_TRANSPORT_CHURN:	return "vsock_transport_churn";
	case CHILD_OP_BRIDGE_VLAN_CHURN:	return "bridge_vlan_churn";
	case CHILD_OP_IGMP_MLD_SOURCE_CHURN:	return "igmp_mld_source_churn";
	case CHILD_OP_PSP_KEY_ROTATE:	return "psp_key_rotate";
	case CHILD_OP_AFXDP_CHURN:	return "afxdp_churn";
	case CHILD_OP_KVM_RUN_CHURN:	return "kvm_run_churn";
	case CHILD_OP_NL80211_CHURN:	return "nl80211_churn";
	case CHILD_OP_NAT_T_CHURN:	return "nat_t_churn";
	case CHILD_OP_SPLICE_PROTOCOLS:	return "splice_protocols";
	case CHILD_OP_RXRPC_KEY_INSTALL:	return "rxrpc_key_install";
	case CHILD_OP_INPLACE_CRYPTO_ORACLE:	return "inplace_crypto_oracle";
	case CHILD_OP_AF_ALG_WEAK_CIPHER_PROBE:	return "af_alg_weak_cipher_probe";
	case CHILD_OP_AF_ALG_TEMPLATE_PROBE:	return "af_alg_template_probe";
	case CHILD_OP_AF_ALG_RECVMSG_CHURN:	return "af_alg_recvmsg_churn";
	case CHILD_OP_IOURING_CMD_PASSTHROUGH:	return "iouring_cmd_passthrough";
	case CHILD_OP_PAGECACHE_CANARY_CHECK:	return "pagecache_canary_check";
	case CHILD_OP_MPLS_ROUTE_CHURN:	return "mpls_route_churn";
	case CHILD_OP_SOCK_DIAG_WALKER:	return "sock_diag_walker";
	case CHILD_OP_ALTNAME_THRASH:	return "altname_thrash";
	case CHILD_OP_IPMR_CACHE_REPORT:	return "ipmr_cache_report";
	case CHILD_OP_UBLK_LIFECYCLE:	return "ublk_lifecycle";
	case CHILD_OP_VETH_ASYMMETRIC_XDP:	return "veth_asymmetric_xdp";
	case CHILD_OP_IP6ERSPAN_NETNS_MIGRATE:	return "ip6erspan_netns_migrate";
	case CHILD_OP_IPVS_SYSCTL_WRITER:	return "ipvs_sysctl_writer";
	case CHILD_OP_TCP_MD5_LISTENER_RACE:	return "tcp_md5_listener_race";
	case CHILD_OP_IPV6_NDISC_PROXY:	return "ipv6_ndisc_proxy";
	case CHILD_OP_IPFRAG_SOURCE_CHURN:	return "ipfrag_source_churn";
	case CHILD_OP_RTNL_VF_BROADCAST_GETLINK:	return "rtnl_vf_broadcast_getlink";
	case CHILD_OP_OBSCURE_AF_CHURN:	return "obscure_af_churn";
	case CHILD_OP_BRIDGE_CT_CHURN:	return "bridge_conntrack_churn";
	case CHILD_OP_ATM_VCC_CHURN:	return "atm_vcc_churn";
	case CHILD_OP_IP6GRE_BOND_LAPB_STACK:	return "ip6gre_bond_lapb_stack";
	case CHILD_OP_FLOWTABLE_ENCAP_VLAN:	return "flowtable_encap_vlan";
	case CHILD_OP_IPV6_PMTU_TEARDOWN_RACE:	return "ipv6_pmtu_teardown_race";
	case CHILD_OP_RXRPC_SENDMSG_CMSG_CHURN:	return "rxrpc_sendmsg_cmsg_churn";
	case CHILD_OP_OVS_TUNNEL_VPORT_CHURN:	return "ovs_tunnel_vport_churn";
	case CHILD_OP_TTY_LDISC_CHURN:	return "tty_ldisc_churn";
	case CHILD_OP_WIREGUARD_DECRYPT_FLOOD:	return "wireguard_decrypt_flood";
	case CHILD_OP_BLKDEV_LIFECYCLE_RACE:	return "blkdev_lifecycle_race";
	case CHILD_OP_ISCSI_TARGET_PROBE:	return "iscsi_target_probe";
	case CHILD_OP_ISCSI_LOGIN_WALKER:	return "iscsi_login_walker";
	case CHILD_OP_ETH_EMITTER:	return "eth_emitter";
	case CHILD_OP_VMA_SPLIT_STORM:	return "vma_split_storm";
	case CHILD_OP_SYSFS_STRING_RACE:	return "sysfs_string_race";
	case CHILD_OP_PCI_BIND:		return "pci_bind";
	case CHILD_OP_AF_UNIX_PEEK_RACE:	return "af_unix_peek_race";
	case CHILD_OP_SYSV_SHM_ORPHAN_RACE:	return "sysv_shm_orphan_race";
	case CHILD_OP_QRTR_BIND_RACE:	return "qrtr_bind_race";
	case CHILD_OP_TC_MIRRED_BLOCKCAST:	return "tc_mirred_blockcast";
	case CHILD_OP_PFKEY_SPD_WALK:	return "pfkey_spd_walk";
	case CHILD_OP_L2TP_IFNAME_RACE:	return "l2tp_ifname_race";
	case CHILD_OP_STATMOUNT_IDMAP_OVERFLOW:	return "statmount_idmap_overflow";
	case CHILD_OP_UMOUNT_RACE:	return "umount_race";
	case NR_CHILD_OP_TYPES:		break;
	}
	return "unknown";
}

/*
 * Reverse of alt_op_name(): looks up an op by its string form (as
 * emitted by alt_op_name) and returns the matching enum value.  Used
 * by the --canary-seed CLI flag parser to translate operator-supplied
 * op names into an override seed list.  Linear scan over
 * NR_CHILD_OP_TYPES; called at most a few times at startup, never on
 * the hot path.  Returns NR_CHILD_OP_TYPES when no match is found so
 * the caller can distinguish "unknown name" from any real enum value.
 */
enum child_op_type alt_op_lookup_by_name(const char *name)
{
	unsigned int i;

	if (name == NULL || *name == '\0')
		return NR_CHILD_OP_TYPES;

	for (i = 0; i < NR_CHILD_OP_TYPES; i++) {
		const char *n = alt_op_name((enum child_op_type)i);
		if (n != NULL && strcmp(n, name) == 0)
			return (enum child_op_type)i;
	}
	return NR_CHILD_OP_TYPES;
}

void assign_dedicated_alt_op(struct childdata *child, int childno)
{
	if (alt_op_children == 0 || childno < 0)
		return;
	if ((unsigned int)childno >= alt_op_children)
		return;

	/* Canary slots are carved from the FRONT of the alt-op pool: the
	 * first canary_slots slots get the canary queue's currently-
	 * canarying op stamped here at spawn time, instead of the
	 * alt_op_rotation[] entry they would otherwise use.  The
	 * remaining alt-op slots continue with the rotation, shifted past
	 * the canary carve so the rotation walk stays stable.  When the
	 * queue is disabled (--no-canary-queue or canary_slots=0), or
	 * before the first canarying op has been selected,
	 * canary_slot_active() returns false and the rotation handles
	 * every slot from index 0 as it did pre-queue. */
	if (canary_slot_active(childno)) {
		child->op_type = canary_active_op();
		return;
	}

	unsigned int rotation_idx = (unsigned int)childno;
	if (canary_slots > 0 && rotation_idx >= canary_slots)
		rotation_idx -= canary_slots;
	child->op_type = alt_op_rotation[rotation_idx % NR_ALT_OP_ROTATION];
}

void log_alt_op_config(void)
{
	char buf[512];
	size_t off = 0;
	unsigned int i;
	unsigned int show;

	if (alt_op_children == 0)
		return;

	/* Show the head of the rotation at -v so the assignment for the
	 * first few slots is eyeballable.  Cap at 5 (or fewer if
	 * alt_op_children itself is smaller) and append an ellipsis when
	 * there are more rotation entries left. */
	show = alt_op_children < 5 ? alt_op_children : 5;
	if (show > NR_ALT_OP_ROTATION)
		show = NR_ALT_OP_ROTATION;

	for (i = 0; i < show; i++) {
		int n = snprintf(buf + off, sizeof(buf) - off, "%s%s",
				 off ? ", " : "",
				 alt_op_name(alt_op_rotation[i]));
		if (n <= 0 || (size_t)n >= sizeof(buf) - off)
			break;
		off += (size_t)n;
	}
	if (show < NR_ALT_OP_ROTATION && off < sizeof(buf) - 1)
		(void) snprintf(buf + off, sizeof(buf) - off, ", ...");

	output(1, "alt-op children: %u reserved, rotation = %s\n",
		alt_op_children, buf);
}

/*
 * Slot -> alt-op mapping.  Same indexing as dormant_op_disabled[]: slot N
 * is enabled iff dormant_op_disabled[N] == 0.  Slot 53 was previously a hole
 * left by a removed op; it now holds CHILD_OP_MPLS_ROUTE_CHURN.  The
 * CHILD_OP_SYSCALL sentinel filter in init_altop_dispatch() stays as
 * defensive coding for any future hole.
 */
static const enum child_op_type pick_op_type_table[117] = {
	[0]  = CHILD_OP_MMAP_LIFECYCLE,
	[1]  = CHILD_OP_MPROTECT_SPLIT,
	[2]  = CHILD_OP_MLOCK_PRESSURE,
	[3]  = CHILD_OP_INODE_SPEWER,
	[4]  = CHILD_OP_PROCFS_WRITER,
	[5]  = CHILD_OP_MEMORY_PRESSURE,
	[6]  = CHILD_OP_USERNS_FUZZER,
	[7]  = CHILD_OP_SCHED_CYCLER,
	[8]  = CHILD_OP_BARRIER_RACER,
	[9]  = CHILD_OP_GENETLINK_FUZZER,
	[10] = CHILD_OP_PERF_CHAINS,
	[11] = CHILD_OP_TRACEFS_FUZZER,
	[12] = CHILD_OP_BPF_LIFECYCLE,
	[13] = CHILD_OP_FAULT_INJECTOR,
	[14] = CHILD_OP_RECIPE_RUNNER,
	[15] = CHILD_OP_IOURING_RECIPES,
	[16] = CHILD_OP_FD_STRESS,
	[17] = CHILD_OP_REFCOUNT_AUDITOR,
	[18] = CHILD_OP_FS_LIFECYCLE,
	[19] = CHILD_OP_SIGNAL_STORM,
	[20] = CHILD_OP_FUTEX_STORM,
	[21] = CHILD_OP_PIPE_THRASH,
	[22] = CHILD_OP_FORK_STORM,
	[23] = CHILD_OP_FLOCK_THRASH,
	[24] = CHILD_OP_CGROUP_CHURN,
	[25] = CHILD_OP_MOUNT_CHURN,
	[26] = CHILD_OP_UFFD_CHURN,
	[27] = CHILD_OP_IOURING_FLOOD,
	[28] = CHILD_OP_CLOSE_RACER,
	[29] = CHILD_OP_SOCKET_FAMILY_CHAIN,
	[30] = CHILD_OP_XATTR_THRASH,
	[31] = CHILD_OP_PIDFD_STORM,
	[32] = CHILD_OP_MADVISE_CYCLER,
	[33] = CHILD_OP_EPOLL_VOLATILITY,
	[34] = CHILD_OP_KEYRING_SPAM,
	[35] = CHILD_OP_VDSO_MREMAP_RACE,
	[36] = CHILD_OP_NUMA_MIGRATION,
	[37] = CHILD_OP_CPU_HOTPLUG_RIDER,
	[38] = CHILD_OP_SLAB_CACHE_THRASH,
	[39] = CHILD_OP_TLS_ROTATE,
	[40] = CHILD_OP_PACKET_FANOUT_THRASH,
	[41] = CHILD_OP_IOURING_NET_MULTISHOT,
	[42] = CHILD_OP_TCP_AO_ROTATE,
	[43] = CHILD_OP_VRF_FIB_CHURN,
	[44] = CHILD_OP_NETLINK_MONITOR_RACE,
	[45] = CHILD_OP_TIPC_LINK_CHURN,
	[46] = CHILD_OP_TLS_ULP_CHURN,
	[47] = CHILD_OP_VXLAN_ENCAP_CHURN,
	[48] = CHILD_OP_BRIDGE_FDB_STP,
	[49] = CHILD_OP_NFTABLES_CHURN,
	[50] = CHILD_OP_TC_QDISC_CHURN,
	[51] = CHILD_OP_XFRM_CHURN,
	[52] = CHILD_OP_BPF_CGROUP_ATTACH,
	[53] = CHILD_OP_MPLS_ROUTE_CHURN,
	[54] = CHILD_OP_SCTP_ASSOC_CHURN,
	[55] = CHILD_OP_MPTCP_PM_CHURN,
	[56] = CHILD_OP_DEVLINK_PORT_CHURN,
	[57] = CHILD_OP_HANDSHAKE_REQ_ABORT,
	[58] = CHILD_OP_NF_CONNTRACK_HELPER,
	[59] = CHILD_OP_AF_UNIX_SCM_RIGHTS_GC,
	[60] = CHILD_OP_NETNS_TEARDOWN_CHURN,
	[61] = CHILD_OP_TCP_ULP_SWAP_CHURN,
	[62] = CHILD_OP_MSG_ZEROCOPY_CHURN,
	[63] = CHILD_OP_IOURING_SEND_ZC_CHURN,
	[64] = CHILD_OP_VSOCK_TRANSPORT_CHURN,
	[65] = CHILD_OP_BRIDGE_VLAN_CHURN,
	[66] = CHILD_OP_IGMP_MLD_SOURCE_CHURN,
	[67] = CHILD_OP_PSP_KEY_ROTATE,
	[68] = CHILD_OP_AFXDP_CHURN,
	[69] = CHILD_OP_KVM_RUN_CHURN,
	[70] = CHILD_OP_NL80211_CHURN,
	[71] = CHILD_OP_NAT_T_CHURN,
	[72] = CHILD_OP_SPLICE_PROTOCOLS,
	[73] = CHILD_OP_RXRPC_KEY_INSTALL,
	[74] = CHILD_OP_INPLACE_CRYPTO_ORACLE,
	[75] = CHILD_OP_AF_ALG_WEAK_CIPHER_PROBE,
	[76] = CHILD_OP_AF_ALG_TEMPLATE_PROBE,
	[77] = CHILD_OP_IOURING_CMD_PASSTHROUGH,
	[78] = CHILD_OP_PAGECACHE_CANARY_CHECK,
	[79] = CHILD_OP_SOCK_DIAG_WALKER,
	[80] = CHILD_OP_ALTNAME_THRASH,
	[81] = CHILD_OP_IPMR_CACHE_REPORT,
	[82] = CHILD_OP_UBLK_LIFECYCLE,
	[83] = CHILD_OP_VETH_ASYMMETRIC_XDP,
	[84] = CHILD_OP_IP6ERSPAN_NETNS_MIGRATE,
	[85] = CHILD_OP_IPVS_SYSCTL_WRITER,
	[86] = CHILD_OP_TCP_MD5_LISTENER_RACE,
	[87] = CHILD_OP_IPV6_NDISC_PROXY,
	[88] = CHILD_OP_IPFRAG_SOURCE_CHURN,
	[89] = CHILD_OP_RTNL_VF_BROADCAST_GETLINK,
	[90] = CHILD_OP_OBSCURE_AF_CHURN,
	[91] = CHILD_OP_AF_ALG_RECVMSG_CHURN,
	[92] = CHILD_OP_BRIDGE_CT_CHURN,
	[93] = CHILD_OP_ATM_VCC_CHURN,
	[94] = CHILD_OP_IP6GRE_BOND_LAPB_STACK,
	[95] = CHILD_OP_FLOWTABLE_ENCAP_VLAN,
	[96] = CHILD_OP_IPV6_PMTU_TEARDOWN_RACE,
	[97] = CHILD_OP_RXRPC_SENDMSG_CMSG_CHURN,
	[98] = CHILD_OP_OVS_TUNNEL_VPORT_CHURN,
	[99] = CHILD_OP_TTY_LDISC_CHURN,
	[100] = CHILD_OP_WIREGUARD_DECRYPT_FLOOD,
	[101] = CHILD_OP_BLKDEV_LIFECYCLE_RACE,
	[102] = CHILD_OP_ISCSI_TARGET_PROBE,
	[103] = CHILD_OP_ETH_EMITTER,
	[104] = CHILD_OP_SYSFS_STRING_RACE,
	[105] = CHILD_OP_PCI_BIND,
	[106] = CHILD_OP_ISCSI_LOGIN_WALKER,
	[107] = CHILD_OP_VMA_SPLIT_STORM,
	[108] = CHILD_OP_AF_UNIX_PEEK_RACE,
	[109] = CHILD_OP_SYSV_SHM_ORPHAN_RACE,
	[110] = CHILD_OP_QRTR_BIND_RACE,
	[111] = CHILD_OP_TC_MIRRED_BLOCKCAST,
	[112] = CHILD_OP_PFKEY_SPD_WALK,
	[113] = CHILD_OP_L2TP_IFNAME_RACE,
	[114] = CHILD_OP_STATMOUNT_IDMAP_OVERFLOW,
	[115] = CHILD_OP_SOCK_ULP_SOCKMAP_LAYERING,
	[116] = CHILD_OP_UMOUNT_RACE,
};
_Static_assert(ARRAY_SIZE(pick_op_type_table) == ARRAY_SIZE(dormant_op_disabled),
	"pick_op_type_table and dormant_op_disabled must have matching slot counts");
/* One slot per non-sentinel child_op_type.  Adding a new CHILD_OP_* without
 * also adding its slot to pick_op_type_table[] (and dormant_op_disabled[])
 * leaves the op invisible to the random picker + canary queue; fail the
 * build instead of silently dropping coverage. */
_Static_assert(ARRAY_SIZE(pick_op_type_table) == NR_CHILD_OP_TYPES - 1,
	"pick_op_type_table missing a slot for a CHILD_OP_* enum value");

/*
 * Reverse of pick_op_type_table[]: given a child_op_type, find the
 * slot index in dormant_op_disabled[] whose pick_op_type_table[]
 * entry points to that op.  Returns -1 if no slot matches (slot-53
 * sentinel for CHILD_OP_SYSCALL would return -1 in current builds;
 * the canary queue never asks for that mapping).  Linear scan over
 * ~100 entries; called once per state transition, never on the hot
 * path.
 *
 * Exists so child-canary.c can flip the gate for a specific op
 * without taking a direct reference to pick_op_type_table[] / the
 * dormant_op_disabled[] storage.  Keeps both arrays file-static.
 */
int dormant_op_slot_for(enum child_op_type op)
{
	unsigned int i;

	if (op == CHILD_OP_SYSCALL || op >= NR_CHILD_OP_TYPES)
		return -1;
	for (i = 0; i < ARRAY_SIZE(pick_op_type_table); i++) {
		if (pick_op_type_table[i] == op)
			return (int)i;
	}
	return -1;
}

/*
 * Mutate the dormant-op gate for `op` and rebuild the dense vector.
 * Called from the canary queue's promote / demote transitions.
 * Single store on the parent path (the parent is the sole writer);
 * children re-read the rebuilt enabled_altops[] on their next pick.
 * See the design note in init_altop_dispatch() about the deliberately
 * non-atomic rebuild -- both gate states are safe to dispatch on.
 *
 * Phase 1 propagation contract: both dormant_op_disabled[] and
 * enabled_altops[] are parent-private after fork() (COW), so the
 * "children re-read" above means children spawned AFTER this call,
 * not children already running.  Already-forked random children
 * continue to consult their fork-time snapshot until the slot turns
 * over.  Dedicated canary slots are re-stamped on respawn and so see
 * the new state immediately on the next spawn cycle.  See the header
 * block in child-canary.c for the full scope statement; the shm-
 * published variant is Phase 2 work.
 */
void dormant_op_set(enum child_op_type op, bool dormant)
{
	int slot = dormant_op_slot_for(op);

	if (slot < 0)
		return;
	dormant_op_disabled[slot] = dormant ? 1 : 0;
	init_altop_dispatch();
}

/*
 * Read-only view used by the canary queue's startup pass: it walks
 * the dormant gate to figure out which ops are already promoted
 * (gate == 0) at startup so the queue's PROMOTED state matches what
 * the dispatcher will actually pick from t=0.
 */
bool dormant_op_is_active(enum child_op_type op)
{
	int slot = dormant_op_slot_for(op);

	if (slot < 0)
		return false;
	return dormant_op_disabled[slot] == 0;
}

/*
 * Dense vector of currently-enabled alt-ops, derived from
 * dormant_op_disabled[] + pick_op_type_table[] by init_altop_dispatch().
 *
 * The previous implementation re-rolled into the full 71-slot space and
 * rejected dormant slots inline, which collapsed the EFFECTIVE altop rate
 * well below the nominal 5% (effective ≈ 5% × enabled/71).  Picking from
 * the dense vector keeps effective ≈ nominal regardless of how many slots
 * are gated off, while keeping dormant_op_disabled[] as the source of truth.
 *
 * Sized at NR_CHILD_OP_TYPES (one slot per enum value, more than enough to
 * hold every non-sentinel slot in pick_op_type_table[]).
 */
static enum child_op_type enabled_altops[NR_CHILD_OP_TYPES];
static unsigned int enabled_altop_count;

/*
 * Walk dormant_op_disabled[] + pick_op_type_table[] in parallel and
 * populate enabled_altops[] / enabled_altop_count.  Skips dormant slots
 * and the slot-53 sentinel hole.  Logs the resulting dispatch config so
 * the operator can see at -v what the effective altop mix actually is.
 *
 * Called once from main_loop before fork_children; the dormant gates
 * are compile-time constants so a single startup pass suffices.
 * dormant_op_set() re-invokes this so runtime flips stay accurate.
 */
void init_altop_dispatch(void)
{
	char buf[1024];
	size_t off = 0;
	unsigned int i;
	unsigned int count = 0;
	bool truncated = false;

	for (i = 0; i < ARRAY_SIZE(pick_op_type_table); i++) {
		enum child_op_type op = pick_op_type_table[i];
		int n;

		if (dormant_op_disabled[i])
			continue;
		if (op == CHILD_OP_SYSCALL)	/* slot-53 sentinel */
			continue;

		enabled_altops[count++] = op;

		if (truncated)
			continue;

		n = snprintf(buf + off, sizeof(buf) - off, "%s%s",
			off ? ", " : "", alt_op_name(op));
		if (n <= 0 || (size_t)n >= sizeof(buf) - off) {
			/* Drop the partial write and stop appending --
			 * keep walking the table so enabled_altops[]
			 * still gets every non-dormant op. */
			buf[off] = '\0';
			truncated = true;
			continue;
		}
		off += (size_t)n;
	}
	if (truncated && off + sizeof(", ...") <= sizeof(buf))
		(void) snprintf(buf + off, sizeof(buf) - off, ", ...");
	enabled_altop_count = count;

	if (count == 0) {
		output(1, "altop dispatch: nominal=5%% effective=0%% (all altops dormant, falling back to syscall)\n");
		return;
	}

	output(1, "altop dispatch: nominal=5%% effective=5%% (%u enabled altops: %s)\n",
		count, buf);
}

static enum child_op_type pick_op_type(void)
{
	unsigned int threshold = 95;
	unsigned int r;

	/* Phase 2 plateau intervention: when the classifier has the
	 * fleet in the childop_dominant regime (alt-op-driven edges
	 * out-running generic-syscall edges by PHC_CHILDOP_DOMINANT_
	 * RATIO), raise the non-dedicated-child alt-op share from 5%
	 * to 25% for the plateau duration.  Leans into the channel
	 * that's actually discovering edges instead of letting the
	 * 95% generic-syscall mass dilute its yield.
	 *
	 * Dedicated alt-op children (alt_op_children + canary slots)
	 * skip this picker entirely via the use_dedicated_op hoist in
	 * child_process(), so the canary queue's measurement window is
	 * untouched -- the burst only retargets the non-dedicated
	 * child pool.
	 *
	 * Gate is a derived predicate over shm->plateau_current_
	 * hypothesis (NOT a latched flag); deactivates automatically
	 * when the tick driver writes NONE on plateau clear or when
	 * the classifier transitions to a different hypothesis.
	 *
	 * The counter bump tracks predicate-active picker invocations
	 * (not picks that resolved to an alt-op).  We want to validate
	 * "did the burst predicate fire while childop_dominant was
	 * live?"; the realised alt-op yield can be cross-checked via
	 * the existing childop_invocations[] delta during plateau
	 * windows.
	 */
	if (__atomic_load_n(&shm->plateau_current_hypothesis,
			    __ATOMIC_RELAXED) ==
	    (int)PLATEAU_HYPOTHESIS_CHILDOP_DOMINANT) {
		threshold = 75;
		__atomic_fetch_add(
			&shm->stats.childop_burst_alt_picks_window,
			1UL, __ATOMIC_RELAXED);
	}

	r = rnd_modulo_u32(100);

	if (r < threshold || enabled_altop_count == 0)
		return CHILD_OP_SYSCALL;

	return enabled_altops[rnd_modulo_u32(enabled_altop_count)];
}

/*
 * Post-invocation feedback for the per-childop budget multiplier.
 *
 * The caller hands us the per-call edge delta surfaced by the outer
 * KCOV bracket (kcov_bracket_end's return value for this dispatch),
 * i.e. the clean count of edges attributable to THIS op's invocation
 * with no sibling-traffic noise mixed in.  If the delta clears
 * ADAPT_BUDGET_THRESHOLD we treat the invocation as productive: bump
 * the multiplier by 25% (Q8.8 *5/4) and clear the zero-streak.
 * Otherwise increment the zero-streak; once it hits
 * ADAPT_BUDGET_ZERO_STREAK the shrink ratchet fires (multiplier *4/5)
 * and the streak resets.  Both moves clamp to [ADAPT_BUDGET_MIN,
 * ADAPT_BUDGET_MAX].
 *
 * Caveats deliberately accepted:
 *
 *   - The caller only invokes adapt_budget when the outer bracket
 *     fired (mode != OFF, op_uses_outer_bracket(op), and
 *     kcov_bracket_begin succeeded).  Calls that did not bracket
 *     leave the multiplier untouched -- a quiet "no signal this
 *     iteration" rather than a ratchet driven by sibling noise.
 *     Ops permanently excluded from the bracket (CHILD_OP_SYSCALL,
 *     CHILD_OP_SCHED_CYCLER -- see op_uses_outer_bracket) therefore
 *     stay at the unity multiplier, matching the no-KCOV degradation
 *     path.  CHILD_OP_SYSCALL has its own cold-syscall heuristics
 *     inside kcov.c that this loop must not fight for control of the
 *     dominant ~95% path; the bracket exclusion already enforces that.
 *
 *   - Updates are RELAXED non-RMW stores.  Two children tail-racing on
 *     the same op_type can lose an update; the worst case is the
 *     ratchet converges a few invocations later than the strict-RMW
 *     model would.  Ratchet caps make divergence bounded in either
 *     direction.
 */
static void adapt_budget(enum child_op_type op_type,
			 unsigned long edges_this_call)
{
	uint16_t mult, new_mult;
	uint16_t streak;
	unsigned long delta;

	if (op_type == CHILD_OP_SYSCALL || op_type >= NR_CHILD_OP_TYPES)
		return;

	mult = __atomic_load_n(&shm->stats.childop_budget_mult[op_type],
			       __ATOMIC_RELAXED);
	if (mult == 0)
		mult = ADAPT_BUDGET_UNITY;

	delta = edges_this_call;

	if (delta >= ADAPT_BUDGET_THRESHOLD) {
		/* Productive: boost by 25% (Q8.8 *5/4), clamped at the cap. */
		new_mult = (uint16_t)((unsigned int)mult * 5U / 4U);
		if (new_mult > ADAPT_BUDGET_MAX)
			new_mult = ADAPT_BUDGET_MAX;
		__atomic_store_n(&shm->stats.childop_zero_streak[op_type],
				 0, __ATOMIC_RELAXED);
	} else {
		/* Hysteresis: only shrink after ADAPT_BUDGET_ZERO_STREAK
		 * consecutive sub-threshold invocations, so a single noise
		 * dip doesn't immediately cut the budget. */
		streak = (uint16_t)__atomic_add_fetch(
			&shm->stats.childop_zero_streak[op_type],
			1, __ATOMIC_RELAXED);
		if (streak < ADAPT_BUDGET_ZERO_STREAK)
			return;
		new_mult = (uint16_t)((unsigned int)mult * 4U / 5U);
		if (new_mult < ADAPT_BUDGET_MIN)
			new_mult = ADAPT_BUDGET_MIN;
		__atomic_store_n(&shm->stats.childop_zero_streak[op_type],
				 0, __ATOMIC_RELAXED);
	}

	if (new_mult != mult)
		__atomic_store_n(&shm->stats.childop_budget_mult[op_type],
				 new_mult, __ATOMIC_RELAXED);
}

/*
 * Dispatch table for the per-iteration childop call.  Indexed by
 * enum child_op_type; a NULL slot means "fall through to the
 * sequence-chain path" (CHILD_OP_SYSCALL is handled by the 95% fast
 * path in pick_op_type and reaches the dispatcher only when it ends
 * up running random_syscall via run_sequence_chain).
 *
 * A dense table replaces what was a 38-case switch in the dispatch
 * site: a single indirect call out of a cache-friendly array,
 * instead of the jump-table the compiler emits per branch site.
 */
static bool (*const op_dispatch[NR_CHILD_OP_TYPES])(struct childdata *) = {
	[CHILD_OP_SYSCALL]		= NULL,
	[CHILD_OP_MMAP_LIFECYCLE]	= mmap_lifecycle,
	[CHILD_OP_MPROTECT_SPLIT]	= mprotect_split,
	[CHILD_OP_MLOCK_PRESSURE]	= mlock_pressure,
	[CHILD_OP_INODE_SPEWER]		= inode_spewer,
	[CHILD_OP_PROCFS_WRITER]	= procfs_writer,
	[CHILD_OP_MEMORY_PRESSURE]	= memory_pressure,
	[CHILD_OP_USERNS_FUZZER]	= userns_fuzzer,
	[CHILD_OP_SCHED_CYCLER]		= sched_cycler,
	[CHILD_OP_BARRIER_RACER]	= barrier_racer,
	[CHILD_OP_GENETLINK_FUZZER]	= genetlink_fuzzer,
	[CHILD_OP_PERF_CHAINS]		= perf_event_chains,
	[CHILD_OP_TRACEFS_FUZZER]	= tracefs_fuzzer,
	[CHILD_OP_BPF_LIFECYCLE]	= bpf_lifecycle,
	[CHILD_OP_FAULT_INJECTOR]	= fault_injector,
	[CHILD_OP_RECIPE_RUNNER]	= recipe_runner,
	[CHILD_OP_IOURING_RECIPES]	= iouring_recipes,
	[CHILD_OP_FD_STRESS]		= fd_stress,
	[CHILD_OP_REFCOUNT_AUDITOR]	= refcount_auditor,
	[CHILD_OP_FS_LIFECYCLE]		= fs_lifecycle,
	[CHILD_OP_SIGNAL_STORM]		= signal_storm,
	[CHILD_OP_FUTEX_STORM]		= futex_storm,
	[CHILD_OP_PIPE_THRASH]		= pipe_thrash,
	[CHILD_OP_FORK_STORM]		= fork_storm,
	[CHILD_OP_FLOCK_THRASH]		= flock_thrash,
	[CHILD_OP_CGROUP_CHURN]		= cgroup_churn,
	[CHILD_OP_MOUNT_CHURN]		= mount_churn,
	[CHILD_OP_UFFD_CHURN]		= uffd_churn,
	[CHILD_OP_IOURING_FLOOD]	= iouring_flood,
	[CHILD_OP_CLOSE_RACER]		= close_racer,
	[CHILD_OP_SOCKET_FAMILY_CHAIN]	= socket_family_chain,
	[CHILD_OP_XATTR_THRASH]		= xattr_thrash,
	[CHILD_OP_PIDFD_STORM]		= pidfd_storm,
	[CHILD_OP_MADVISE_CYCLER]	= madvise_cycler,
	[CHILD_OP_EPOLL_VOLATILITY]	= epoll_volatility,
	[CHILD_OP_KEYRING_SPAM]		= keyring_spam,
	[CHILD_OP_VDSO_MREMAP_RACE]	= vdso_mremap_race,
	[CHILD_OP_NUMA_MIGRATION]	= numa_migration_churn,
	[CHILD_OP_CPU_HOTPLUG_RIDER]	= cpu_hotplug_rider,
	[CHILD_OP_SLAB_CACHE_THRASH]	= slab_cache_thrash,
	[CHILD_OP_TLS_ROTATE]		= tls_rotate,
	[CHILD_OP_SOCK_ULP_SOCKMAP_LAYERING]	= sock_ulp_sockmap_layering,
	[CHILD_OP_PACKET_FANOUT_THRASH]	= packet_fanout_thrash,
	[CHILD_OP_IOURING_NET_MULTISHOT] = iouring_net_multishot,
	[CHILD_OP_TCP_AO_ROTATE]	= tcp_ao_rotate,
	[CHILD_OP_VRF_FIB_CHURN]	= vrf_fib_churn,
	[CHILD_OP_NETLINK_MONITOR_RACE]	= netlink_monitor_race,
	[CHILD_OP_TIPC_LINK_CHURN]	= tipc_link_churn,
	[CHILD_OP_TLS_ULP_CHURN]	= tls_ulp_churn,
	[CHILD_OP_VXLAN_ENCAP_CHURN]	= vxlan_encap_churn,
	[CHILD_OP_BRIDGE_FDB_STP]	= bridge_fdb_stp,
	[CHILD_OP_NFTABLES_CHURN]	= nftables_churn,
	[CHILD_OP_TC_QDISC_CHURN]	= tc_qdisc_churn,
	[CHILD_OP_XFRM_CHURN]		= xfrm_churn,
	[CHILD_OP_BPF_CGROUP_ATTACH]	= bpf_cgroup_attach,
	[CHILD_OP_SCTP_ASSOC_CHURN]	= sctp_assoc_churn,
	[CHILD_OP_MPTCP_PM_CHURN]	= mptcp_pm_churn,
	[CHILD_OP_DEVLINK_PORT_CHURN]	= devlink_port_churn,
	[CHILD_OP_HANDSHAKE_REQ_ABORT]	= handshake_req_abort,
	[CHILD_OP_NF_CONNTRACK_HELPER]	= nf_conntrack_helper_churn,
	[CHILD_OP_AF_UNIX_SCM_RIGHTS_GC]	= af_unix_scm_rights_gc_churn,
	[CHILD_OP_NETNS_TEARDOWN_CHURN]	= netns_teardown_churn,
	[CHILD_OP_TCP_ULP_SWAP_CHURN]	= tcp_ulp_swap_churn,
	[CHILD_OP_MSG_ZEROCOPY_CHURN]	= msg_zerocopy_churn,
	[CHILD_OP_IOURING_SEND_ZC_CHURN]	= iouring_send_zc_churn,
	[CHILD_OP_VSOCK_TRANSPORT_CHURN]	= vsock_transport_churn,
	[CHILD_OP_BRIDGE_VLAN_CHURN]	= bridge_vlan_churn,
	[CHILD_OP_IGMP_MLD_SOURCE_CHURN]	= igmp_mld_source_churn,
	[CHILD_OP_PSP_KEY_ROTATE]	= psp_key_rotate,
	[CHILD_OP_AFXDP_CHURN]		= afxdp_churn,
	[CHILD_OP_KVM_RUN_CHURN]	= kvm_run_churn,
	[CHILD_OP_NL80211_CHURN]	= nl80211_churn,
	[CHILD_OP_NAT_T_CHURN]		= nat_t_churn,
	[CHILD_OP_SPLICE_PROTOCOLS]	= splice_protocols,
	[CHILD_OP_RXRPC_KEY_INSTALL]	= rxrpc_key_install,
	[CHILD_OP_INPLACE_CRYPTO_ORACLE]	= inplace_crypto_oracle,
	[CHILD_OP_AF_ALG_WEAK_CIPHER_PROBE]	= af_alg_weak_cipher_probe,
	[CHILD_OP_AF_ALG_TEMPLATE_PROBE]	= af_alg_template_probe,
	[CHILD_OP_AF_ALG_RECVMSG_CHURN]		= af_alg_recvmsg_churn,
	[CHILD_OP_IOURING_CMD_PASSTHROUGH]	= iouring_cmd_passthrough,
	[CHILD_OP_PAGECACHE_CANARY_CHECK]	= pagecache_canary_check,
	[CHILD_OP_MPLS_ROUTE_CHURN]	= mpls_route_churn,
	[CHILD_OP_SOCK_DIAG_WALKER]	= sock_diag_walker,
	[CHILD_OP_ALTNAME_THRASH]	= altname_thrash,
	[CHILD_OP_IPMR_CACHE_REPORT]	= ipmr_cache_report,
	[CHILD_OP_UBLK_LIFECYCLE]	= ublk_lifecycle,
	[CHILD_OP_VETH_ASYMMETRIC_XDP]	= veth_asymmetric_xdp,
	[CHILD_OP_IP6ERSPAN_NETNS_MIGRATE]	= ip6erspan_netns_migrate,
	[CHILD_OP_IPVS_SYSCTL_WRITER]	= ipvs_sysctl_writer,
	[CHILD_OP_TCP_MD5_LISTENER_RACE]	= tcp_md5_listener_race,
	[CHILD_OP_IPV6_NDISC_PROXY]	= ipv6_ndisc_proxy,
	[CHILD_OP_IPFRAG_SOURCE_CHURN]	= ipfrag_source_churn,
	[CHILD_OP_RTNL_VF_BROADCAST_GETLINK]	= rtnl_vf_broadcast_getlink,
	[CHILD_OP_OBSCURE_AF_CHURN]	= obscure_af_churn,
	[CHILD_OP_BRIDGE_CT_CHURN]	= bridge_conntrack_churn,
	[CHILD_OP_ATM_VCC_CHURN]	= atm_vcc_churn,
	[CHILD_OP_IP6GRE_BOND_LAPB_STACK]	= ip6gre_bond_lapb_stack,
	[CHILD_OP_FLOWTABLE_ENCAP_VLAN]	= flowtable_encap_vlan,
	[CHILD_OP_IPV6_PMTU_TEARDOWN_RACE]	= ipv6_pmtu_teardown_race,
	[CHILD_OP_RXRPC_SENDMSG_CMSG_CHURN]	= rxrpc_sendmsg_cmsg_churn,
	[CHILD_OP_OVS_TUNNEL_VPORT_CHURN]	= ovs_tunnel_vport_churn,
	[CHILD_OP_TTY_LDISC_CHURN]	= tty_ldisc_churn,
	[CHILD_OP_WIREGUARD_DECRYPT_FLOOD]	= wireguard_decrypt_flood,
	[CHILD_OP_BLKDEV_LIFECYCLE_RACE]	= blkdev_lifecycle_race,
	[CHILD_OP_ISCSI_TARGET_PROBE]	= iscsi_target_probe,
	[CHILD_OP_ISCSI_LOGIN_WALKER]	= iscsi_login_walker,
	[CHILD_OP_ETH_EMITTER]		= eth_emitter,
	[CHILD_OP_VMA_SPLIT_STORM]	= vma_split_storm,
	[CHILD_OP_SYSFS_STRING_RACE]	= sysfs_string_race,
	[CHILD_OP_PCI_BIND]		= pci_bind,
	[CHILD_OP_AF_UNIX_PEEK_RACE]	= af_unix_peek_race,
	[CHILD_OP_SYSV_SHM_ORPHAN_RACE]	= sysv_shm_orphan_race,
	[CHILD_OP_QRTR_BIND_RACE]	= qrtr_bind_race,
	[CHILD_OP_TC_MIRRED_BLOCKCAST]	= tc_mirred_blockcast,
	[CHILD_OP_PFKEY_SPD_WALK]	= pfkey_spd_walk,
	[CHILD_OP_L2TP_IFNAME_RACE]	= l2tp_ifname_race,
	[CHILD_OP_STATMOUNT_IDMAP_OVERFLOW] = statmount_idmap_overflow,
	[CHILD_OP_UMOUNT_RACE]		= umount_race,
};

_Static_assert(ARRAY_SIZE(op_dispatch) == NR_CHILD_OP_TYPES,
	"op_dispatch must have one slot per enum child_op_type");

/*
 * This is the child main loop, entered after init_child has completed
 * from the fork_children() loop.
 */
#define NEW_OP_COUNT 100000

/*
 * Per-child corruption-rate storm check.  Cheap modulo-gated probe of
 * the three local_* counters maintained alongside their global shm
 * stats siblings; returns true when any counter has been climbing at
 * LOCAL_STORM_RATE_THRESHOLD events/sec or more for at least
 * LOCAL_STORM_WINDOW_SEC seconds, in which case the caller should
 * exit its main loop so the parent can recycle the slot.
 *
 * The window-floor (LOCAL_STORM_WINDOW_SEC) suppresses single-spike
 * false positives -- a transient burst that cannot sustain absorbs
 * into the next snapshot roll instead of recycling the child.  When
 * the window has aged past the floor without any signal exceeding the
 * rate threshold, the snapshot is rolled forward so the next check
 * measures a fresh window rather than a smeared cumulative rate.
 *
 * Returns false (and may roll the snapshot) when no recycle is needed.
 */
static bool storm_rate_recycle(struct childdata *child)
{
	struct timespec now;
	long window_sec;
	unsigned long delta_post, delta_scribbled;

	clock_gettime(CLOCK_MONOTONIC, &now);
	window_sec = (long)(now.tv_sec - child->storm_check_last_time.tv_sec);
	if (window_sec < LOCAL_STORM_WINDOW_SEC)
		return false;

	delta_post = child->local_post_handler_corrupt_ptr -
		     child->storm_check_last_post_handler;
	delta_scribbled = child->local_scribbled_slots_caught -
			  child->storm_check_last_scribbled;

	if ((delta_post / (unsigned long)window_sec) >= LOCAL_STORM_RATE_THRESHOLD ||
	    (delta_scribbled / (unsigned long)window_sec) >= LOCAL_STORM_RATE_THRESHOLD)
		return true;

	/* Quiet window: roll the snapshot so the next check measures the
	 * next window in isolation rather than smearing a years-long
	 * cumulative count against a fresh interval. */
	child->storm_check_last_time = now;
	child->storm_check_last_post_handler = child->local_post_handler_corrupt_ptr;
	child->storm_check_last_scribbled = child->local_scribbled_slots_caught;
	return false;
}

void child_process(struct childdata *child, int childno)
{
	char childname[17];
	int ret;

	/* PR_SET_PDEATHSIG SIGKILL: when the main process dies for any
	 * reason -- a fault, or an external SIGKILL from a wrapper that
	 * gave up on a hung syscall -- the kernel kills this fuzz child
	 * instead of leaving it reparented to init.  The orderly kill_pid
	 * shutdown the supervisor would have driven on a clean exit is
	 * bypassed on a crash; without this, a child wedged in a blocking
	 * syscall (e.g. a fuse poll) outlives the supervisor and needs
	 * manual cleanup.  SIGKILL not SIGTERM because a wedged child
	 * would not respond to a polite signal.
	 *
	 * Race window: if the main process died between fork() returning
	 * here and the prctl above, PDEATHSIG was set too late to fire and
	 * getppid() != mainpid is the only signal we get.  No CLONE_NEWPID
	 * at the spawn fork (init_child enters namespaces later, after the
	 * guard has run), so the host-namespace comparison is reliable. */
	(void)prctl(PR_SET_PDEATHSIG, SIGKILL);
	if (getppid() != mainpid)
		_exit(0);

	/* Rename and lower OOM priority before init_child() runs.  init_child
	 * does a lot of mmap-heavy work (init_child_mappings, futex setup,
	 * sibling-childdata mprotect sweeps) which is exactly when memory
	 * pressure peaks.  If we wait until the end of init_child to set the
	 * comm + oom_score_adj, the kernel sees a fresh fork still named
	 * "trinity-main" with adj=0 and may pick it as the OOM victim instead
	 * of the actually-running children at adj=500. */
	memset(childname, 0, sizeof(childname));
	snprintf(childname, sizeof(childname), "trinity-c%d", childno);
	prctl(PR_SET_NAME, (unsigned long) &childname);
	oom_score_adj(500);

	init_child(child, childno);

	/* Whether this child is a dedicated alt-op slot is fixed for the
	 * child's lifetime: alt_op_children is set at startup and childno
	 * is constant per child.  Compute the predicate once instead of
	 * re-deriving it (3 loads + 2 branches) every loop iteration. */
	const bool use_dedicated_op = (alt_op_children != 0 &&
				       childno >= 0 &&
				       (unsigned int)childno < alt_op_children);

	/* kcov_shm is mapped once at startup (init_kcov_shm) and never
	 * reassigned for the child's lifetime, so the per-iteration NULL
	 * tests gating the edges_before snapshot and the post-call
	 * adapt_budget feedback are loop-invariant.  Hoist them once,
	 * mirroring the use_dedicated_op pattern above, to drop 2 loads
	 * + 2 compares per iteration on the dominant 95% syscall path. */
	const bool have_kcov = (kcov_shm != NULL);

	while (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) == STILL_RUNNING) {
		/* Catch-up sibling refreeze: a new sibling that ran init_child
		 * since our last sweep bumped shm->sibling_freeze_gen.  Re-run
		 * the mprotect sweep to pull that sibling's childdata into our
		 * PROT_READ set so a stray value-result kernel write of ours
		 * can't land there.  ACQUIRE pairs with the RELEASE bump in
		 * init_child.  No-op (single relaxed-equivalent load) on the
		 * common case where no sibling spawned. */
		unsigned int gen = __atomic_load_n(&shm->sibling_freeze_gen,
						   __ATOMIC_ACQUIRE);
		if (gen != child->last_seen_freeze_gen) {
			freeze_sibling_childdata(childno);
			child->last_seen_freeze_gen = gen;
			__atomic_add_fetch(&shm->stats.sibling_refreeze_count, 1,
					   __ATOMIC_RELAXED);
		}

		if (ctrlc_pending) {
			panic(EXIT_SIGINT);
			break;
		}

		/* SIGALRM: the blocking syscall returned EINTR.
		 * Check for stalled-on-fd, detect stalls, and
		 * count the timeout as an op. */
		if (sigalrm_pending) {
			sigalrm_pending = 0;
			alarm(0);
			if (check_stall(child))
				goto out;
			if (__atomic_load_n(&child->kill_count, __ATOMIC_RELAXED) > 0) {
				output(1, "[%d] Missed a kill signal, exiting\n", mypid());
				goto out;
			}
		}

		if (xcpu_pending) {
			child->xcpu_count++;
			xcpu_pending = 0;
			if (child->xcpu_count == 100) {
				debugf("Child %d [%d] got 100 XCPUs. Exiting child.\n",
					childno, __atomic_load_n(&pids[childno], __ATOMIC_RELAXED));
				goto out;
			}
		}

		/* If the parent reseeded, we should reflect the latest seed too. */
		if (__atomic_load_n(&shm->seed, __ATOMIC_RELAXED) != child->seed) {
			set_seed(child);
		}

		/* Two back-to-back callsites below (periodic_work and the
		 * iter-start clock_gettime refresh) share the same 16-iter
		 * cadence.  Compute the predicate once and reuse, mirroring
		 * the use_dedicated_op / have_kcov hoists at the top of
		 * child_process(); saves 1 mask + 1 compare + 1 branch on
		 * every iter, not just the 5% alt-op path. */
		const bool tick16 = ((child->op_nr & 15) == 0);

		if (tick16)
			periodic_work(child, child->op_nr);

		/* Per-child storm-containment gate: once every
		 * LOCAL_STORM_CHECK_PERIOD iterations, score the three
		 * local corruption-rate counters against the threshold.
		 * The corruption is a per-child accumulator (a poisoned
		 * OBJ_LOCAL slot or a scribbled libc arena) -- it does
		 * not survive across fork(), so a fresh child re-inherits
		 * clean state and breaks the burn-arg-gen-cycles loop the
		 * storm produces.  Symptom containment, not a root-cause
		 * fix; the upstream scribble source is still active. */
		if ((child->op_nr & (LOCAL_STORM_CHECK_PERIOD - 1)) == 0 &&
		    storm_rate_recycle(child)) {
			stats_ring_enqueue(child->stats_ring,
					   STATS_FIELD_CHILDREN_RECYCLED_ON_STORM,
					   0, 1);
			goto out;
		}

		/* Free any deferred allocations whose TTL has expired.
		 * This runs before the syscall so that freed memory can
		 * be recycled by the allocator for the next sanitise. */
		deferred_free_tick();

		/* Pick an op type for this iteration.  Dedicated alt-op
		 * children (--alt-op-children=N reserves the first N
		 * slots) keep the op_type stamped by the parent at fork
		 * time and skip the random picker entirely; any other
		 * child uses the default 95% syscall / 5% alt-op mix. */
		if (use_dedicated_op == false)
			child->op_type = pick_op_type();

		/* --dry-run only neutralizes the syscall-dispatch path (the
		 * __do_syscall gate synthesizes -1/ENOSYS without entering the
		 * kernel).  Childops issue real syscalls directly and bypass
		 * that gate, so force every iteration -- both the dedicated
		 * alt-op children and the 5% alt-op mix -- onto CHILD_OP_SYSCALL
		 * under dry_run, leaving the mode genuinely syscall-free apart
		 * from the well-formed fd-provider setup. */
		if (dry_run)
			child->op_type = CHILD_OP_SYSCALL;

		/* -c <syscall>, -r <num>, and -g <group> scope the run to a
		 * specific syscall (or a random subset, or a group) for
		 * isolation / bisection runs.  The alt-op childops bypass the
		 * syscall-table gate and issue their own unrelated syscalls;
		 * the 5% leak from pick_op_type (and any dedicated alt-op slot
		 * from --alt-op-children) would contribute coverage, crashes,
		 * and brk/VMA churn that pollute the per-target signal.  Force
		 * CHILD_OP_SYSCALL so the run is actually isolated to the
		 * targeted syscall set; mirrors the dry_run override above and
		 * catches the dedicated alt-op slot same way. */
		if (do_specific_syscall || random_selection ||
		    desired_group != GROUP_NONE)
			child->op_type = CHILD_OP_SYSCALL;

		/* Snapshot op_type once per iter.  child->op_type lives in
		 * shared memory and can be scribbled by a poisoned-arena
		 * write between the picker above and the stats writers
		 * below.  The dispatch path already bounds-checks the field
		 * before indexing op_dispatch[], but the per-op stats arrays
		 * (sized by NR_CHILD_OP_TYPES) were indexed unchecked and a
		 * corrupted index would scribble past their backing store.
		 * Use the local for both dispatch and stats; skip the
		 * per-childop stats writes entirely when the snapshot is out
		 * of range. */
		const enum child_op_type op = child->op_type;
		const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

		/* The alt-op predicate is read three times below (alarm arm,
		 * watch_taint compute, alarm disarm + op_count bump) and the
		 * op_type field cannot change inside the iter body once
		 * stamped above.  Hoist into a single bool, mirroring the
		 * tick16 / use_dedicated_op / have_kcov hoists already in
		 * this loop; saves 2 loads + 2 compares per iter.  Folded in
		 * valid_op so a corrupted op_type both stays out of dispatch
		 * and out of the alt-op-only stats paths below. */
		const bool is_alt_op = valid_op && (op != CHILD_OP_SYSCALL);

		/* Refresh the iteration-start timestamp every 16th pass.
		 * vDSO clock_gettime is fast (~20 ns) but at ~700 ops/sec
		 * across 32 children it adds up; rec->tp consumers (taint
		 * ordering, pre_crash_ring) only need second-level
		 * granularity, and the parent-side stall reaper compares
		 * tv_sec with a 30-second threshold (main.c:653).  At 700
		 * iters/sec a 16-iter sample interval is ~23 ms — well
		 * inside the second-level tolerance. */
		if (tick16)
			clock_gettime(CLOCK_MONOTONIC, &child->tp);

		/* Non-debug: hoisted to init_child().  Kept gated under
		 * shm->debug for parity with the existing debug semantics. */
		if (shm->debug == true)
			disable_coredumps();

		/*
		 * Non-syscall ops don't arm their own alarm; set one here so
		 * SIGALRM-based stall detection can fire if the op hangs.
		 * random_syscall() arms alarm internally for NEED_ALARM syscalls.
		 */
		if (is_alt_op)
			alarm(1);

		/* Snapshot the global edge counter to feed the diagnostic
		 * childop_edges_discovered[] / childop_calls_with_edges[]
		 * comparator in the post-call block below.  adapt_budget
		 * and the canary queue now consume the clean bracketed
		 * delta (childop_edges_clean[]) instead; the noisy global
		 * counter is kept tracked so operators can diff the two
		 * during the bracket-coverage soak.  Cheap (single relaxed
		 * atomic load) and only meaningful if KCOV is active. */
		unsigned long edges_before = have_kcov
			? __atomic_load_n(&kcov_shm->edges_found,
					  __ATOMIC_RELAXED)
			: 0UL;

		bool (*op_fn)(struct childdata *) =
			valid_op ? op_dispatch[op] : NULL;

		/* Soft-taint watcher: bracket non-syscall dispatches with a
		 * read of /proc/sys/kernel/tainted so a bit transition (e.g.
		 * lockdep WARN, RCU stall, reckless module load) gets pinned
		 * to the specific childop that triggered it even when the
		 * kernel doesn't escalate to an oops.  Skipped for
		 * CHILD_OP_SYSCALL — the hot 95% path can't afford an extra
		 * pair of read syscalls per iteration, and random_syscall has
		 * its own taint-tracking via the existing pre_crash_ring
		 * record on syscall return. */
		const bool watch_taint = (is_alt_op && child->tainted_fd >= 0);
		unsigned long tainted_before = 0;
		if (watch_taint)
			tainted_before = child->last_tainted;

		/* Per-childop KCOV bracket.  Wraps op_fn (and the
		 * run_sequence_chain fallthrough, which is itself ruled
		 * out by op_uses_outer_bracket for CHILD_OP_SYSCALL) so
		 * the post-call collect attributes only this dispatch's
		 * new edges to childop_edges_clean[].  The is_alt_op
		 * pre-check is implicit: op_uses_outer_bracket gates out
		 * CHILD_OP_SYSCALL, and CHILD_OP_SCHED_CYCLER opts out
		 * because it recurses into per-syscall brackets that
		 * would drain the trace buffer before the outer collect
		 * sees it.  Default --childop-kcov-attribution=off short-
		 * circuits the whole block before kcov_bracket_begin is
		 * called. */
		bool bracketed = false;
		unsigned long edges_this_call = 0;

		if (have_kcov &&
		    childop_kcov_attr_mode != CHILDOP_KCOV_ATTR_OFF &&
		    valid_op &&
		    op_uses_outer_bracket(op)) {
			/* Count one bracket attempt at the op_uses_outer_bracket
			 * gate so the begin-side reject arms in kcov_bracket_begin
			 * (skipped_cmp / skipped_nested / skipped_inactive) and
			 * the success arm (childop_kcov_bracketed) sum back to
			 * this counter -- the smoke-test invariant for this row. */
			__atomic_fetch_add(&kcov_shm->childop_kcov_attempts,
				1, __ATOMIC_RELAXED);
			bracketed = kcov_bracket_begin(&child->kcov);
		}

		/* childop_split telemetry: bracket op_fn with a monotonic
		 * sample pair so the elapsed dispatch time can be split into
		 * childop vs random-syscall buckets.  Also set child->in_childop
		 * across the dispatch so a random_syscall() called from inside
		 * an alt-op recipe (e.g. sched_cycler) bumps syscalls_in_childops
		 * at the call-complete enqueue, not syscalls_random.  The flag
		 * is the per-child source of truth for the syscall-count
		 * attribution; the wall-time accumulation below is independent
		 * of it (driven off the is_alt_op snapshot taken at the top of
		 * the iter so a corrupted op_type can't reroute the bucket
		 * after we've already paid the op_fn). */
		struct timespec split_t0, split_t1;
		clock_gettime(CLOCK_MONOTONIC, &split_t0);
		child->in_childop = is_alt_op;

		ret = op_fn ? op_fn(child) : run_sequence_chain(child);

		child->in_childop = false;
		clock_gettime(CLOCK_MONOTONIC, &split_t1);

		if (bracketed) {
			edges_this_call = kcov_bracket_end(
				&child->kcov,
				CHILDOP_KCOV_NR_BASE + op);
		}

		{
			long ns = (split_t1.tv_sec - split_t0.tv_sec) * 1000000000L
				+ (split_t1.tv_nsec - split_t0.tv_nsec);
			if (ns < 0)
				ns = 0;
			if (is_alt_op) {
				__atomic_add_fetch(&shm->stats.childop_walltime_ns,
						   (unsigned long)ns, __ATOMIC_RELAXED);
			} else if (op == CHILD_OP_SYSCALL) {
				__atomic_add_fetch(&shm->stats.syscall_walltime_ns,
						   (unsigned long)ns, __ATOMIC_RELAXED);
				/* Iteration denominator for childop_split.
				 * childop_invocations[] is gated on is_alt_op
				 * upstream, so CHILD_OP_SYSCALL is never counted
				 * there; this is its parallel counter. */
				__atomic_add_fetch(&shm->stats.random_syscall_dispatches,
						   1UL, __ATOMIC_RELAXED);
			}
		}

		if (watch_taint) {
			unsigned long tainted_after =
				read_tainted_mask(child->tainted_fd);
			unsigned long delta = tainted_after ^ tainted_before;
			if (delta) {
				pre_crash_ring_record_taint(child, delta,
							    tainted_after,
							    (unsigned int) op,
							    child->op_nr);
				__atomic_add_fetch(
					&shm->stats.taint_transitions[op],
					1, __ATOMIC_RELAXED);
			}
			child->last_tainted = tainted_after;
		}

		if (is_alt_op) {
			alarm(0);
			stats_ring_enqueue(child->stats_ring,
					   STATS_FIELD_OP_COUNT, 0, 1);
		}

		/* Feed the per-call clean edge delta into the per-op budget
		 * multiplier and the canary-queue input counter
		 * (childop_edges_clean[]).  Both consumers see only the
		 * bracketed contribution from this dispatch -- no sibling
		 * noise -- and skip the ratchet entirely on calls that did
		 * not bracket (mode OFF, op_uses_outer_bracket(op) false,
		 * or kcov_bracket_begin rejected).
		 *
		 * The global edges_found before/after delta is preserved as
		 * a diagnostic so the operator can compare the noisy
		 * discovered counter against the clean counter per op while
		 * the bracket coverage soaks; remaining consumers (plateau
		 * snapshot) still read childop_edges_discovered[].  Skipped
		 * when KCOV is unavailable -- both signals require a live
		 * kcov_shm to be meaningful. */
		if (have_kcov) {
			unsigned long edges_after = __atomic_load_n(
				&kcov_shm->edges_found, __ATOMIC_RELAXED);
			if (bracketed && valid_op)
				adapt_budget(op, edges_this_call);
			if (is_alt_op) {
				unsigned long delta = (edges_after >= edges_before)
					? (edges_after - edges_before) : 0;
				__atomic_fetch_add(
					&shm->stats.childop_edges_discovered[op],
					delta, __ATOMIC_RELAXED);
				/* Parallel call-count bump for any invocation
				 * that surfaced at least one new edge.  Mirrors
				 * the syscall-path bandit/explorer call counters
				 * so the plateau classifier's Rule 2 can compare
				 * apples-to-apples instead of edge-count vs
				 * call-count. */
				if (delta > 0)
					__atomic_fetch_add(
						&shm->stats.childop_calls_with_edges[op],
						1, __ATOMIC_RELAXED);
			}
			/* dual / on modes only: publish the bracketed per-
			 * call delta to childop_edges_clean[].  off mode
			 * never sets bracketed=true, so this slot stays at
			 * zero and the consumers above degrade to "no
			 * signal this iteration" the same way they do on a
			 * build without KCOV. */
			if (bracketed) {
				__atomic_fetch_add(
					&shm->stats.childop_edges_clean[op],
					edges_this_call, __ATOMIC_RELAXED);
			}
		}

		/* Per-op invocation tally for the canary queue's window
		 * measurement.  Bumped per alt-op iteration regardless of
		 * KCOV availability (the canary queue's window-size logic
		 * must work even on builds without kcov), at the same
		 * post-call point so a crash mid-call is not counted.
		 * Skip CHILD_OP_SYSCALL -- parent_stats.op_count already
		 * aggregates that path. */
		if (is_alt_op) {
			__atomic_fetch_add(
				&shm->stats.childop_invocations[op],
				1UL, __ATOMIC_RELAXED);

			/* Per-op "last successful dispatch" timestamp, sampled
			 * from the same fleet-clock source the syscalls_todo
			 * termination check below reads.  Only stamped when the
			 * op returned SUCCESS -- a FAIL return covers throttled
			 * / setup-failed / skipped paths and must not refresh
			 * the timestamp, otherwise the dormancy signal collapses
			 * to "this op was attempted recently" (which the
			 * invocation counter above already encodes) instead of
			 * "this op did useful work recently".  RELAXED store: a
			 * single dispatch is a single writer to its op's slot;
			 * cross-op sibling races are tolerated -- last writer
			 * wins, which is the "most recent observed success"
			 * semantics dump_stats consumes for dormancy detection.
			 * 0 stays "never succeeded" because we only store here
			 * (the create_shm() memset already zeroed the array). */
			if (ret != FAIL && shm_published != NULL) {
				__atomic_store_n(
					&shm->stats.childop_last_success_ts[op],
					__atomic_load_n(
						&shm_published->fleet_op_count,
						__ATOMIC_RELAXED),
					__ATOMIC_RELAXED);
			}
		}

		if (shm->debug == true)
			enable_coredumps();

		__atomic_add_fetch(&child->op_nr, 1, __ATOMIC_RELAXED);

		if (ret == FAIL)
			goto out;

		if (syscalls_todo) {
			/* Read the parent-published mirror page rather than the
			 * canonical aggregate (which is parent-private and not
			 * visible from a child).  Mirror lag is bounded by the
			 * parent's drain cadence (~ms), well inside the
			 * termination granularity callers expect. */
			if (shm_published != NULL &&
			    __atomic_load_n(&shm_published->fleet_op_count,
					    __ATOMIC_RELAXED) >= syscalls_todo) {
				__atomic_store_n(&shm->exit_reason,
						EXIT_REACHED_COUNT, __ATOMIC_RELAXED);
				goto out;
			}
		}
	}

	/* If we're exiting because we tainted, wait here for it to be done. */
	while (__atomic_load_n(&shm->postmortem_in_progress, __ATOMIC_ACQUIRE) == true) {
		/* Make sure the main process is still around. */
		if (pid_alive(mainpid) == false)
			goto out;

		usleep(1);
	}

out:
	deferred_free_flush();
	check_fd_leaks(child);
	/* Drain any per-child kcov stats staged below the kcov_collect()
	 * cadence threshold before tearing the kcov fd down -- otherwise a
	 * child that exits / is killed / is recycled cold loses up to
	 * KCOV_LOCAL_STATS_FLUSH_SYSCALLS worth of total_calls / remote_calls
	 * / total_pcs.  kcov_cleanup_child() takes struct kcov_child * and
	 * cannot reach child->local_stats, which is why the flush belongs
	 * here on the full childdata.  The flush is gated per-field on
	 * (delta > 0) so it is safe to call with nothing staged. */
	kcov_child_flush_stats(child);
	kcov_cleanup_child(&child->kcov);
	inode_spewer_cleanup();
	psp_key_rotate_cleanup_child();

	if (child->fail_nth_fd != -1) {
		close(child->fail_nth_fd);
		child->fail_nth_fd = -1;
	}

	if (child->tainted_fd != -1) {
		close(child->tainted_fd);
		child->tainted_fd = -1;
	}

	debugf("child %d %d exiting.\n", childno, mypid());
}
