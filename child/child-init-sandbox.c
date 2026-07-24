/*
 * Per-child sandbox bring-up: block on shm->ready, arm the fault
 * injectors (via child-init-clean.c helpers), optionally dirty FPU
 * and mask signals, per-child unshare()s (with the mnt/net gates on
 * shm->isolation.*_ready), root-only drop_privs(), unconditional
 * capset()-to-empty + cap-drop oracle anchor capture, and the
 * random rlimit / cgroup / umask sweep in munge_process.
 *
 * Split out of child-init.c so make -j can compile the sandbox
 * phase concurrently with the clean / freeze / isolate / runtime
 * setup helpers.
 *
 * munge_process stays static -- only init_child_setup_sandbox calls
 * it and both live here.  init_child_setup_sandbox sheds its static
 * linkage so init_child (still in child-init.c during the carve)
 * can call it; declaration added to include/child-internal.h.
 * set_make_it_fail / open_fail_nth / open_tainted_fd / use_fpu
 * remain declared in include/child-internal.h from the clean.c carve.
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
void init_child_setup_sandbox(struct childdata *child, int childno)
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
