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
#include "random.h"
#include "shm.h"
#include "signals.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"	// ARRAY_SIZE
#include "uid.h"
#include "deferred-free.h"
#include "sanitise.h"
#include "utils.h"	// zmalloc

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
 * Single-producer push: copy the just-completed syscallrecord into the
 * ring slot, then publish the new head with a release-store so the
 * post-mortem reader observes a fully-written entry when it sees the
 * matching head value.
 */
void child_syscall_ring_push(struct child_syscall_ring *ring,
			     const struct syscallrecord *rec)
{
	uint32_t head;

	head = atomic_load_explicit(&ring->head, memory_order_relaxed);
	ring->recent[head & (CHILD_SYSCALL_RING_SIZE - 1)] = *rec;
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

		sa.sa_handler = SIG_DFL;
		sa.sa_flags = 0;
		sigemptyset(&sa.sa_mask);
		(void)sigaction(SIGABRT, &sa, NULL);
		(void)sigaction(SIGSEGV, &sa, NULL);
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
	if (shm->dont_make_it_fail == true)
		return;

	fd = open("/proc/self/make-it-fail", O_WRONLY);
	if (fd == -1) {
		shm->dont_make_it_fail = true;
		return;
	}

	if (write(fd, buf, 1) == -1) {
		if (errno != EPERM)
			outputerr("writing to /proc/self/make-it-fail failed! (%s)\n", strerror(errno));
		shm->dont_make_it_fail = true;
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
	child->current_recipe_name = NULL;

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
 * Called from the fork_children loop in the main process.
 */
static void init_child(struct childdata *child, int childno)
{
	pid_t pid = getpid();
	char childname[17];
	unsigned int i;
	int devnull;

	/* Redirect stdout/stderr to /dev/null so no syscall
	 * (splice, sendfile, vmsplice, etc.) can spew to the terminal. */
	devnull = open("/dev/null", O_WRONLY);
	if (devnull >= 0) {
		dup2(devnull, STDOUT_FILENO);
		dup2(devnull, STDERR_FILENO);
		if (devnull > STDERR_FILENO)
			close(devnull);
	}

	/* Re-set num from the stack-based childno in case shared memory
	 * was corrupted by a sibling's stray write. */
	child->num = childno;

	/* Use childno (on stack) not child->num (in shared memory) to
	 * decide which struct to skip — a corrupted num would cause us
	 * to mprotect our own childdata and then SIGSEGV on write. */
	for_each_child(i) {
		if ((unsigned int)childno != i && children[i] != NULL)
			mprotect(children[i], sizeof(struct childdata), PROT_READ);
	}

	mprotect(pids, max_children * sizeof(int), PROT_READ);

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

	if (RAND_BOOL())
		use_fpu();

	mask_signals_child();

	if (RAND_BOOL()) {
		unshare(CLONE_NEWNS);
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
	if (RAND_BOOL() && !shm->no_pidns) {
		if (unshare(CLONE_NEWPID) == -1) {
			if (errno == EPERM || errno == EINVAL)
				shm->no_pidns = true;
		}
	}
#endif

	if (orig_uid == 0)
		child->dropped_privs = false;

	munge_process();

	kcov_init_child(&child->kcov, child->num);

	deferred_free_init();
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
 */
static void periodic_work(void)
{
	static unsigned int periodic_counter = 0;

	periodic_counter++;

	/* Every 16 iterations. */
	if (!(periodic_counter & 15))
		check_parent_pid();

	/* Every 128 iterations. */
	if (!(periodic_counter & 127)) {
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
					 (int) rec->a1, -1, 0);
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
 */
static enum child_op_type pick_op_type(void)
{
	unsigned int r = rand() % 100;

	if (r < 95)
		return CHILD_OP_SYSCALL;

	switch (r % 19) {
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
	}
	return CHILD_OP_SYSCALL;
}

/*
 * This is the child main loop, entered after init_child has completed
 * from the fork_children() loop.
 */
#define NEW_OP_COUNT 100000

void child_process(struct childdata *child, int childno)
{
	int ret;

	init_child(child, childno);

	while (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) == STILL_RUNNING) {
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
		if (shm->seed != child->seed) {
			set_seed(child);
		}

		periodic_work();

		/* Free any deferred allocations whose TTL has expired.
		 * This runs before the syscall so that freed memory can
		 * be recycled by the allocator for the next sanitise. */
		deferred_free_tick();

		/* Pick an op type for this iteration. */
		child->op_type = pick_op_type();

		/* timestamp, and dispatch the op */
		clock_gettime(CLOCK_MONOTONIC, &child->tp);

		disable_coredumps();

		/*
		 * Non-syscall ops don't arm their own alarm; set one here so
		 * SIGALRM-based stall detection can fire if the op hangs.
		 * random_syscall() arms alarm internally for NEED_ALARM syscalls.
		 */
		if (child->op_type != CHILD_OP_SYSCALL)
			alarm(1);

		switch (child->op_type) {
		case CHILD_OP_MMAP_LIFECYCLE:	ret = mmap_lifecycle(child); break;
		case CHILD_OP_MPROTECT_SPLIT:	ret = mprotect_split(child); break;
		case CHILD_OP_MLOCK_PRESSURE:	ret = mlock_pressure(child); break;
		case CHILD_OP_INODE_SPEWER:		ret = inode_spewer(child); break;
		case CHILD_OP_PROCFS_WRITER:		ret = procfs_writer(child); break;
		case CHILD_OP_MEMORY_PRESSURE:		ret = memory_pressure(child); break;
		case CHILD_OP_USERNS_FUZZER:		ret = userns_fuzzer(child); break;
		case CHILD_OP_SCHED_CYCLER:		ret = sched_cycler(child); break;
		case CHILD_OP_BARRIER_RACER:		ret = barrier_racer(child); break;
		case CHILD_OP_GENETLINK_FUZZER:		ret = genetlink_fuzzer(child); break;
		case CHILD_OP_PERF_CHAINS:		ret = perf_event_chains(child); break;
		case CHILD_OP_TRACEFS_FUZZER:		ret = tracefs_fuzzer(child); break;
		case CHILD_OP_BPF_LIFECYCLE:		ret = bpf_lifecycle(child); break;
		case CHILD_OP_FAULT_INJECTOR:		ret = fault_injector(child); break;
		case CHILD_OP_RECIPE_RUNNER:		ret = recipe_runner(child); break;
		case CHILD_OP_IOURING_RECIPES:		ret = iouring_recipes(child); break;
		case CHILD_OP_FD_STRESS:		ret = fd_stress(child); break;
		case CHILD_OP_REFCOUNT_AUDITOR:		ret = refcount_auditor(child); break;
		case CHILD_OP_FS_LIFECYCLE:		ret = fs_lifecycle(child); break;
		default:				ret = random_syscall(child); break;
		}

		if (child->op_type != CHILD_OP_SYSCALL) {
			alarm(0);
			__atomic_add_fetch(&shm->stats.op_count, 1, __ATOMIC_RELAXED);
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

	debugf("child %d %d exiting.\n", childno, getpid());
}
