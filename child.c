/*
 * Each process that gets forked runs this code.
 */

#include <fcntl.h>
#include <errno.h>
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

#include "arch.h"
#include "child.h"
#include "fd.h"
#include "futex.h"
#include "fd-event.h"
#include "kcov.h"
#include "list.h"
#include "maps.h"
#include "params.h"
#include "pids.h"
#include "pre_crash_ring.h"
#include "random.h"
#include "shm.h"
#include "signals.h"
#include "stats.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"	// ARRAY_SIZE
#include "uid.h"
#include "deferred-free.h"
#include "sanitise.h"
#include "sequence.h"
#include "utils.h"	// zmalloc

/*
 * Pin op_nr — the trailing field of the per-syscall hot block — to an
 * offset under 64 so a future field reorder that moves any of the hot
 * block (kcov, last_syscall_nr, last_group, op_nr, local_op_count) past
 * the leading cacheline boundary fails the build instead of silently
 * regressing the per-call cache-miss budget the layout was tuned for.
 */
_Static_assert(offsetof(struct childdata, op_nr) < 64,
	"struct childdata: op_nr (per-syscall hot field) escaped the leading cacheline");

/* Set to true once we detect that unprivileged pidns isn't available.
 * Lives in shared memory (shm->no_pidns) so the flag propagates across
 * fork() — see init_child() below. */

/*
 * Provide temporary immunity from the reaper
 * This is useful if we're going to do something that might take
 * longer than the time the reaper is prepared to wait, especially if
 * we're doing something critical, like handling a lock, or dumping a log.
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

	head = atomic_load_explicit(&ring->head, memory_order_relaxed);
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

	atomic_store_explicit(&ring->head, head + 1, memory_order_release);
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
 * Enable the kernels fault-injection code for our child process.
 * (Assumes you've set everything else up by hand).
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

	if (shm->no_fail_nth == true)
		return;

	fd = open("/proc/self/fail-nth", O_WRONLY);
	if (fd == -1) {
		shm->no_fail_nth = true;
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
static void oom_score_adj(int adj)
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
	child->kill_count = 0;
	child->dontkillme = false;
	child->xcpu_count = 0;
	child->op_nr = 0;
	child->local_op_count = 0;
	child->current_fd = -1;
	child->fd_lifetime = 0;
	child->cached_fd_generation = 0;
	child->last_group = GROUP_NONE;
	child->last_syscall_nr = EDGEPAIR_NO_PREV;
	child->dropped_privs = false;
	child->op_type = CHILD_OP_SYSCALL;
	child->stall_count = 0;
	child->stall_last = 0;
	child->fd_created = 0;
	child->fd_closed = 0;
	memset(child->fd_created_by_group, 0, sizeof(child->fd_created_by_group));
	clock_gettime(CLOCK_MONOTONIC, &child->tp);

	/* Reset live fd ring: -1 marks all slots as empty. */
	for (int i = 0; i < CHILD_FD_RING_SIZE; i++)
		child->live_fds.fds[i] = -1;
	child->live_fds.head = 0;

	/* Reset syscall ring; UNKNOWN state in zeroed slots is filtered
	 * by the post-mortem reader so a freshly-spawned child contributes
	 * nothing until it has actually completed a syscall. */
	memset(child->syscall_ring.recent, 0, sizeof(child->syscall_ring.recent));
	atomic_store_explicit(&child->syscall_ring.head, 0,
			      memory_order_relaxed);

	child->fail_nth_fd = -1;
	child->tainted_fd = -1;
	child->last_tainted = 0;
	child->current_recipe_name = NULL;

	/* Drop any sentinel reading from the previous occupant of this slot
	 * so the first periodic_work tick re-populates without comparing
	 * against state captured under a different child's environment. */
	child->sentinel_prev.valid = false;

	/* Clear any __BUG() stamp left by the prior occupant of this slot
	 * so the parent's zombie-pending warning doesn't mis-attribute the
	 * fresh child's eventual exit to the previous one's assertion. */
	child->hit_bug = false;
	child->bug_text = NULL;
	child->bug_func = NULL;
	child->bug_lineno = 0;

	if (child->fd_event_ring)
		fd_event_ring_init(child->fd_event_ring);
}

static void bind_child_to_cpu(struct childdata *child)
{
	cpu_set_t set;
	unsigned int cpudest;
	pid_t pid = __atomic_load_n(&pids[child->num], __ATOMIC_RELAXED);

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
		 rand() % 8);
	fd = open(cgpath, O_WRONLY);
	if (fd >= 0) {
		char pidbuf[16];
		int len = snprintf(pidbuf, sizeof(pidbuf), "%d", getpid());
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
		lim.rlim_cur = lim.rlim_cur / 2 + rand() % (lim.rlim_cur / 2);
		(void) setrlimit(rlim_resources[i], &lim);
	}

	/* Random umask. */
	umask((mode_t)(rand() & 0777));
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
 * Called from the fork_children loop in the main process.
 */
static void init_child(struct childdata *child, int childno)
{
	pid_t pid = getpid();
	char childname[17];
	unsigned int new_gen;
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

	/* Detach from the controlling terminal so a fuzzed
	 * open("/dev/tty", O_WRONLY) followed by write() can't reach the
	 * operator's shell.  The dup2 above only covers fds 0/1/2; this
	 * closes the wider class of paths that re-acquire the tty (open of
	 * /dev/tty itself, ioctl(TIOCSCTTY), etc.).  setsid() makes us our
	 * own session leader without a controlling terminal — subsequent
	 * /dev/tty opens fail with ENXIO. */
	(void) setsid();

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
	if (mprotect(pids, max_children * sizeof(int), PROT_READ) != 0) {
		outputerr("init_child: mprotect(pids[]) failed: %s\n", strerror(errno));
		__atomic_add_fetch(&shm->stats.sibling_mprotect_failed, 1,
				   __ATOMIC_RELAXED);
	}

	/* Wait for parent to set our childno */
	while (__atomic_load_n(&pids[childno], __ATOMIC_ACQUIRE) != pid) {
		sched_yield();
		/* Make sure parent is actually alive to wait for us. */
		if (pid_alive(mainpid) == false) {
			panic(EXIT_SHM_CORRUPTION);
			outputerr("BUG!: parent (%d) went away!\n", mainpid);
			_exit(EXIT_SHM_CORRUPTION);
		}
	}

	/* Cache our childno/pid for O(1) lookups in this_child()/find_childno().
	 * Pass the child pointer directly — don't re-derive it from
	 * children[] which sits in mprotected shared memory but accessing
	 * via the cached argument avoids the indirection on the hot path. */
	set_child_cache(childno, pid, child);
	output_set_pid(pid);

	set_seed(child);

	init_object_lists(OBJ_LOCAL, child);

	init_child_mappings();
	init_child_futexes();

	dirty_random_mapping();

	if (RAND_BOOL())
		bind_child_to_cpu(child);

	memset(childname, 0, sizeof(childname));
	snprintf(childname, sizeof(childname), "trinity-c%d", childno);
	prctl(PR_SET_NAME, (unsigned long) &childname);

	oom_score_adj(500);

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
		/* unshare(CLONE_NEWNS) gives this child its own mount namespace,
		 * but the new ns inherits propagation mode from the parent.  On
		 * most distros / is MS_SHARED, so without an explicit MS_PRIVATE
		 * remount any mount() this child later issues — including the
		 * random ones from the syscall fuzzer — propagates back into the
		 * host's mount tree.  Make the new ns recursively private so
		 * downstream mount churn stays contained.  If the remount is
		 * rejected (EPERM in some sandboxed configs) we can't undo the
		 * unshare, so log it loudly and continue: the child is still
		 * usable, just not isolated for mount fuzzing. */
		if (unshare(CLONE_NEWNS) == 0) {
			if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0)
				output(0, "child %d: MS_PRIVATE remount failed (errno=%d) "
				       "after unshare(CLONE_NEWNS); mounts in this child "
				       "may propagate to host mount table\n",
				       childno, errno);
		}
		unshare(CLONE_NEWIPC);
		unshare(CLONE_IO);
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
		child->dropped_privs = false;

	munge_process();

	kcov_init_child(&child->kcov, child->num);

	/* Uniarch: pin the active-syscalls pointer once.  Biarch leaves
	 * this NULL — the first choose_syscall_table call refreshes it. */
	if (!biarch)
		child->active_syscalls = shm->active_syscalls;
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

	pid = getpid();

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

	/* Every 128 iterations. */
	if ((op_nr & 127) == 0) {
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
	case CHILD_OP_UFFD_CHURN:		return 30;
	case CHILD_OP_IOURING_FLOOD:		return 30;
	case CHILD_OP_CLOSE_RACER:		return 30;
	case CHILD_OP_XATTR_THRASH:		return 30;
	case CHILD_OP_EPOLL_VOLATILITY:		return 30;
	default:				return 10;
	}
}

/*
 * Check if a SIGALRM timeout indicates a stuck-on-fd situation.
 * If so, evict the fd and notify the parent.
 * Only meaningful for CHILD_OP_SYSCALL — other op types don't use the
 * syscall record, so skip the fd-eviction logic for them.
 */
static void handle_alarm_timeout(struct childdata *child)
{
	struct syscallrecord *rec = &child->syscall;

	if (child->op_type != CHILD_OP_SYSCALL)
		return;

	if (rec->state != BEFORE)
		return;

	if (check_if_fd(rec) == true) {
		child->fd_lifetime = 0;

		if (child->fd_event_ring != NULL)
			fd_event_enqueue(child->fd_event_ring, FD_EVENT_CLOSE,
					 (int) rec->a1, -1, 0, 0, 0);
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
	if (child->stall_count == stall_threshold(child->op_type)) {
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
 * Pick an op type for this iteration.  Syscalls dominate (~95%),
 * with the remaining ~5% spread across the alternative ops.
 * This gives the VM-stress and inode paths occasional exercise
 * without starving the main syscall fuzzer.
 *
 * Cases 5-18 are gated here: they are structurally reachable (the r%19 bug
 * is fixed) but their throughput cost is unknown.  procfs_writer (case 4)
 * crashed iters/s 8x at default rate before its discovery path was hoisted.
 * Enable the dormant ops one at a time once each has been load-tested.
 * To enable an op: set its entry below to 0.
 */
static const int dormant_op_disabled[38] = {
	0, 0, 0, 0, 0,	/* 0-4:  active: mmap_lifecycle, mprotect_split, mlock_pressure, inode_spewer, procfs_writer */
	0, 1, 1, 1, 1,	/* 5-9:  memory_pressure active (first dormant-op enable); dormant: userns_fuzzer, sched_cycler, barrier_racer, genetlink_fuzzer */
	1, 1, 1, 0, 1,	/* 10-14: fault_injector active; dormant: perf_chains, tracefs_fuzzer, bpf_lifecycle, recipe_runner */
	1, 1, 1, 1, 1,	/* 15-19: dormant: iouring_recipes, fd_stress, refcount_auditor, fs_lifecycle, signal_storm */
	1, 1, 1, 1, 1,	/* 20-24: dormant: futex_storm, pipe_thrash, fork_storm, flock_thrash, cgroup_churn */
	1, 1, 1, 1, 1,	/* 25-29: dormant: mount_churn, uffd_churn, iouring_flood, close_racer, socket_family_chain */
	1, 1, 1, 1, 1,	/* 30-34: dormant: xattr_thrash, pidfd_storm, madvise_cycler, epoll_volatility, keyring_spam */
	1, 1, 1,	/* 35-37: dormant: vdso_mremap_race, numa_migration, cpu_hotplug_rider */
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
};
#define NR_ALT_OP_ROTATION	ARRAY_SIZE(alt_op_rotation)

static const char *alt_op_name(enum child_op_type op)
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
	case NR_CHILD_OP_TYPES:		break;
	}
	return "unknown";
}

void assign_dedicated_alt_op(struct childdata *child, int childno)
{
	if (alt_op_children == 0 || childno < 0)
		return;
	if ((unsigned int)childno >= alt_op_children)
		return;
	child->op_type = alt_op_rotation[(unsigned int)childno % NR_ALT_OP_ROTATION];
}

void log_alt_op_config(void)
{
	char buf[512];
	size_t off = 0;
	unsigned int i;
	unsigned int show;

	if (alt_op_children == 0)
		return;

	/* Dave wants the head of the rotation visible at -v so the
	 * assignment for the first few slots is eyeballable.  Cap at 5
	 * (or fewer if alt_op_children itself is smaller) and append
	 * an ellipsis when there are more rotation entries left. */
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

	output(1, "[main] alt-op children: %u reserved, rotation = %s\n",
		alt_op_children, buf);
}

static enum child_op_type pick_op_type(void)
{
	unsigned int r = rand() % 100;
	unsigned int pick;

	if (r < 95)
		return CHILD_OP_SYSCALL;

	pick = rand() % 38;
	if (dormant_op_disabled[pick])
		return CHILD_OP_SYSCALL;

	switch (pick) {
	case 0:  return CHILD_OP_MMAP_LIFECYCLE;
	case 1:  return CHILD_OP_MPROTECT_SPLIT;
	case 2:  return CHILD_OP_MLOCK_PRESSURE;
	case 3:  return CHILD_OP_INODE_SPEWER;
	case 4:  return CHILD_OP_PROCFS_WRITER;
	case 5:  return CHILD_OP_MEMORY_PRESSURE;
	case 6:  return CHILD_OP_USERNS_FUZZER;
	case 7:  return CHILD_OP_SCHED_CYCLER;
	case 8:  return CHILD_OP_BARRIER_RACER;
	case 9:  return CHILD_OP_GENETLINK_FUZZER;
	case 10: return CHILD_OP_PERF_CHAINS;
	case 11: return CHILD_OP_TRACEFS_FUZZER;
	case 12: return CHILD_OP_BPF_LIFECYCLE;
	case 13: return CHILD_OP_FAULT_INJECTOR;
	case 14: return CHILD_OP_RECIPE_RUNNER;
	case 15: return CHILD_OP_IOURING_RECIPES;
	case 16: return CHILD_OP_FD_STRESS;
	case 17: return CHILD_OP_REFCOUNT_AUDITOR;
	case 18: return CHILD_OP_FS_LIFECYCLE;
	case 19: return CHILD_OP_SIGNAL_STORM;
	case 20: return CHILD_OP_FUTEX_STORM;
	case 21: return CHILD_OP_PIPE_THRASH;
	case 22: return CHILD_OP_FORK_STORM;
	case 23: return CHILD_OP_FLOCK_THRASH;
	case 24: return CHILD_OP_CGROUP_CHURN;
	case 25: return CHILD_OP_MOUNT_CHURN;
	case 26: return CHILD_OP_UFFD_CHURN;
	case 27: return CHILD_OP_IOURING_FLOOD;
	case 28: return CHILD_OP_CLOSE_RACER;
	case 29: return CHILD_OP_SOCKET_FAMILY_CHAIN;
	case 30: return CHILD_OP_XATTR_THRASH;
	case 31: return CHILD_OP_PIDFD_STORM;
	case 32: return CHILD_OP_MADVISE_CYCLER;
	case 33: return CHILD_OP_EPOLL_VOLATILITY;
	case 34: return CHILD_OP_KEYRING_SPAM;
	case 35: return CHILD_OP_VDSO_MREMAP_RACE;
	case 36: return CHILD_OP_NUMA_MIGRATION;
	case 37: return CHILD_OP_CPU_HOTPLUG_RIDER;
	}
	return CHILD_OP_SYSCALL;
}

/*
 * Post-invocation feedback for the per-childop budget multiplier.
 *
 * Reads kcov_shm->edges_found before and after the dispatch call (the
 * caller hands us the bracketed values).  If the delta clears
 * ADAPT_BUDGET_THRESHOLD we treat the invocation as productive: bump
 * the multiplier by 25% (Q8.8 *5/4) and clear the zero-streak.
 * Otherwise increment the zero-streak; once it hits
 * ADAPT_BUDGET_ZERO_STREAK the shrink ratchet fires (multiplier *4/5)
 * and the streak resets.  Both moves clamp to [ADAPT_BUDGET_MIN,
 * ADAPT_BUDGET_MAX].
 *
 * Caveats deliberately accepted:
 *
 *   - The "edges in window" signal is the GLOBAL edge counter, so
 *     siblings running productive syscalls during our dispatch inflate
 *     our delta.  Most childops don't bracket their own kernel-side
 *     work with KCOV_ENABLE/DISABLE (they're not random_syscall
 *     callers), so a per-child counter wouldn't fire for them either —
 *     the signal we DO have is the only signal available without
 *     restructuring the KCOV plumbing.  The threshold is calibrated to
 *     filter out modest sibling noise; on very large fleets the noise
 *     floor rises and the boost ratchet stalls (safe failure mode —
 *     multipliers stay near 1.0x and behaviour matches pre-CV.13
 *     fixed budgets).
 *
 *   - Updates are RELAXED non-RMW stores.  Two children tail-racing on
 *     the same op_type can lose an update; the worst case is the
 *     ratchet converges a few invocations later than the strict-RMW
 *     model would.  Ratchet caps make divergence bounded in either
 *     direction.
 *
 *   - CHILD_OP_SYSCALL is excluded entirely.  random_syscall has its
 *     own cold-syscall heuristics inside kcov.c and we don't want this
 *     loop fighting those for control of the dominant ~95% path.
 */
static void adapt_budget(enum child_op_type op_type,
			 unsigned long edges_before,
			 unsigned long edges_after)
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

	delta = (edges_after >= edges_before) ? (edges_after - edges_before) : 0;

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
};

_Static_assert(ARRAY_SIZE(op_dispatch) == NR_CHILD_OP_TYPES,
	"op_dispatch must have one slot per enum child_op_type");

/*
 * This is the child main loop, entered after init_child has completed
 * from the fork_children() loop.
 */
#define NEW_OP_COUNT 100000

void child_process(struct childdata *child, int childno)
{
	int ret;

	init_child(child, childno);

	/* Whether this child is a dedicated alt-op slot is fixed for the
	 * child's lifetime: alt_op_children is set at startup and childno
	 * is constant per child.  Compute the predicate once instead of
	 * re-deriving it (3 loads + 2 branches) every loop iteration. */
	const bool use_dedicated_op = (alt_op_children != 0 &&
				       childno >= 0 &&
				       (unsigned int)childno < alt_op_children);

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
			freeze_sibling_childdata(child->num);
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
			handle_alarm_timeout(child);
			if (check_stall(child))
				goto out;
			if (child->kill_count > 0) {
				output(1, "[%d] Missed a kill signal, exiting\n", getpid());
				goto out;
			}
		}

		if (xcpu_pending) {
			child->xcpu_count++;
			xcpu_pending = 0;
			if (child->xcpu_count == 100) {
				debugf("Child %d [%d] got 100 XCPUs. Exiting child.\n",
					child->num, __atomic_load_n(&pids[child->num], __ATOMIC_RELAXED));
				goto out;
			}
		}

		/* If the parent reseeded, we should reflect the latest seed too. */
		if (__atomic_load_n(&shm->seed, __ATOMIC_RELAXED) != child->seed) {
			set_seed(child);
		}

		if ((child->op_nr & 15) == 0)
			periodic_work(child, child->op_nr);

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

		/* Refresh the iteration-start timestamp every 16th pass.
		 * vDSO clock_gettime is fast (~20 ns) but at ~700 ops/sec
		 * across 32 children it adds up; rec->tp consumers (taint
		 * ordering, pre_crash_ring) only need second-level
		 * granularity, and the parent-side stall reaper compares
		 * tv_sec with a 30-second threshold (main.c:653).  At 700
		 * iters/sec a 16-iter sample interval is ~23 ms — well
		 * inside the second-level tolerance. */
		if ((child->op_nr & 15) == 0)
			clock_gettime(CLOCK_MONOTONIC, &child->tp);

		disable_coredumps();

		/*
		 * Non-syscall ops don't arm their own alarm; set one here so
		 * SIGALRM-based stall detection can fire if the op hangs.
		 * random_syscall() arms alarm internally for NEED_ALARM syscalls.
		 */
		if (child->op_type != CHILD_OP_SYSCALL)
			alarm(1);

		/* Snapshot the global edge counter for adapt_budget()'s
		 * post-invocation feedback.  Cheap (single relaxed atomic
		 * load) and only meaningful if KCOV is active; otherwise the
		 * counter stays at zero and the delta is always 0, which
		 * correctly degrades to "never boost, never shrink" — the
		 * multiplier sticks at 1.0x and behaviour matches pre-CV.13. */
		unsigned long edges_before = (kcov_shm != NULL)
			? __atomic_load_n(&kcov_shm->edges_found,
					  __ATOMIC_RELAXED)
			: 0UL;

		bool (*op_fn)(struct childdata *) =
			(child->op_type < NR_CHILD_OP_TYPES)
				? op_dispatch[child->op_type]
				: NULL;

		/* Soft-taint watcher: bracket non-syscall dispatches with a
		 * read of /proc/sys/kernel/tainted so a bit transition (e.g.
		 * lockdep WARN, RCU stall, reckless module load) gets pinned
		 * to the specific childop that triggered it even when the
		 * kernel doesn't escalate to an oops.  Skipped for
		 * CHILD_OP_SYSCALL — the hot 95% path can't afford an extra
		 * pair of read syscalls per iteration, and random_syscall has
		 * its own taint-tracking via the existing pre_crash_ring
		 * record on syscall return. */
		const bool watch_taint = (child->op_type != CHILD_OP_SYSCALL &&
					  child->tainted_fd >= 0);
		unsigned long tainted_before = 0;
		if (watch_taint)
			tainted_before = read_tainted_mask(child->tainted_fd);

		ret = op_fn ? op_fn(child) : run_sequence_chain(child);

		if (watch_taint) {
			unsigned long tainted_after =
				read_tainted_mask(child->tainted_fd);
			unsigned long delta = tainted_after ^ tainted_before;
			if (delta) {
				pre_crash_ring_record_taint(child, delta,
							    tainted_after,
							    (unsigned int) child->op_type,
							    child->op_nr);
				__atomic_add_fetch(
					&shm->stats.taint_transitions[child->op_type],
					1, __ATOMIC_RELAXED);
				child->last_tainted = tainted_after;
			}
		}

		if (child->op_type != CHILD_OP_SYSCALL) {
			alarm(0);
			__atomic_add_fetch(&shm->stats.op_count, 1, __ATOMIC_RELAXED);
		}

		/* Feed the post-invocation edge delta back into the per-op
		 * budget multiplier.  Skipped when KCOV is unavailable —
		 * adapt_budget() needs a real signal to ratchet on. */
		if (kcov_shm != NULL) {
			unsigned long edges_after = __atomic_load_n(
				&kcov_shm->edges_found, __ATOMIC_RELAXED);
			adapt_budget(child->op_type, edges_before, edges_after);
		}

		enable_coredumps();

		child->op_nr++;

		if (ret == FAIL)
			goto out;

		if (syscalls_todo) {
			if (shm->stats.op_count >= syscalls_todo) {
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
	kcov_cleanup_child(&child->kcov);
	inode_spewer_cleanup();

	if (child->fail_nth_fd != -1) {
		close(child->fail_nth_fd);
		child->fail_nth_fd = -1;
	}

	if (child->tainted_fd != -1) {
		close(child->tainted_fd);
		child->tainted_fd = -1;
	}

	debugf("child %d %d exiting.\n", childno, getpid());
}
