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
 * linkage so init_child (in child-init-core.c) can call it;
 * declaration added to include/child-internal.h.
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
#include <sys/socket.h>

#include "arch.h"
#include "child.h"
#include "child-internal.h"
#include "tables.h"
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
 * Check whether any active syscall entry requests the userns-admin lane.
 * Returns the first matching entry, or NULL if none does.  Used at child
 * setup time to decide whether to unshare into a private user+net namespace
 * before the capset(empty) drop.
 *
 * Only the shm-level active_syscalls array is consulted because
 * child->active_syscalls is not yet assigned when init_child_setup_sandbox
 * runs (that assignment happens in init_child_setup_runtime, which is called
 * after the sandbox phase).
 */
static struct syscallentry *find_userns_lane_entry(void)
{
	unsigned int i;

	for (i = 0; i < shm->nr_active_syscalls; i++) {
		struct syscallentry *e =
			get_syscall_entry((unsigned int)shm->active_syscalls[i],
					  false);
		if (e != NULL && e->userns_admin_lane)
			return e;
	}
	return NULL;
}

/*
 * Write a short line to a proc file.  Returns 0 on success, -errno on
 * failure.  Used by maybe_enter_userns_admin_lane() to install the identity
 * uid/gid maps after unshare(CLONE_NEWUSER).
 */
static int userns_lane_write_proc(const char *path, const char *line)
{
	ssize_t wlen;
	size_t len = strlen(line);
	int fd, saved;

	fd = open(path, O_WRONLY);
	if (fd < 0)
		return -errno;
	wlen = write(fd, line, len);
	saved = errno;
	(void)close(fd);
	if (wlen == (ssize_t)len)
		return 0;
	if (wlen < 0)
		return -(saved ? saved : EIO);
	return -EIO;
}

/*
 * Set to true after maybe_enter_userns_admin_lane() completes all
 * three idmap writes successfully.  Consulted by the cap-drop oracle
 * to invert the SO_RCVBUFFORCE probe expectation: with the lane active
 * the socket lives in the lane's netns where the child holds
 * CAP_NET_ADMIN, so SO_RCVBUFFORCE must SUCCEED rather than fail.
 * Process-local: each forked child gets its own copy.
 */
static bool child_userns_lane_active;

/*
 * Enter the userns-admin lane for the current persistent child.
 *
 * Preconditions (verified by caller):
 *   - shm->no_userns_lane is false.
 *   - At least one active syscallentry has userns_admin_lane set.
 *
 * Sequence:
 *   1. Read /proc/sys/user/max_user_namespaces; if the value is <= 0 or
 *      unreadable, latch shm->no_userns_lane and return.
 *   2. Capture euid/egid before the unshare (kernel checks the pre-unshare
 *      euid when validating the single-line identity idmap write).
 *   3. unshare(CLONE_NEWUSER | CLONE_NEWNET).
 *      On EPERM: latch shm->no_userns_lane and return (policy denial).
 *      On other failure: return without latching (transient, may not recur).
 *   4. Write uid_map, setgroups=deny, gid_map.
 *      Failure here is logged but does not latch; the cap-drop that follows
 *      still fires and the child fuzz loop runs without userns-lane caps.
 *
 * After a successful return the child holds a full capability set inside its
 * own user namespace.  capset(empty) has already run in the caller; that
 * dropped all capabilities in init_user_ns.  Issuing unshare(CLONE_NEWUSER)
 * AFTER capset means create_user_ns() sets cap_effective = CAP_FULL_SET in
 * the new userns unconditionally -- the kernel grants full caps in a newly
 * created userns regardless of the caller's effective caps.  capset does not
 * alter euid/egid, so the identity idmap write still runs with the process's
 * current effective uid/gid.  The child then holds caps only in its
 * private user namespace, never in init_user_ns, so:
 *   - capable(CAP_*)   -> ns_capable(&init_user_ns, cap) -> false
 *   - ns_capable(child_userns, cap)                      -> true
 * The cap-drop oracle probes (bpf/mount/net_admin/capget) all gate on
 * init_user_ns-scoped paths and remain correct.
 */
static void maybe_enter_userns_admin_lane(int childno)
{
	char buf[64];
	uid_t uid;
	gid_t gid;
	int fd, ret;
	long max_ns;

	if (__atomic_load_n(&shm->no_userns_lane, __ATOMIC_RELAXED))
		return;

	/*
	 * Check /proc/sys/user/max_user_namespaces before attempting the
	 * unshare.  A zero or negative value means the kernel will reject
	 * CLONE_NEWUSER unconditionally; read-failure (ENOENT on CONFIG_
	 * USER_NS=n) is treated the same way.  Latch and return in either
	 * case so we don't spam EPERM probes.
	 */
	fd = open("/proc/sys/user/max_user_namespaces", O_RDONLY);
	if (fd < 0) {
		__atomic_store_n(&shm->no_userns_lane, true, __ATOMIC_RELAXED);
		return;
	}
	{
		ssize_t n = read(fd, buf, sizeof(buf) - 1);
		(void)close(fd);
		if (n <= 0) {
			__atomic_store_n(&shm->no_userns_lane, true,
					 __ATOMIC_RELAXED);
			return;
		}
		buf[n] = '\0';
		max_ns = strtol(buf, NULL, 10);
	}
	if (max_ns <= 0) {
		__atomic_store_n(&shm->no_userns_lane, true, __ATOMIC_RELAXED);
		return;
	}

	/*
	 * Capture euid/egid before the unshare.  After unshare(CLONE_NEWUSER)
	 * but before the id maps are written, geteuid()/getegid() return the
	 * overflow id (65534).  The kernel validates that the mapped-outside
	 * id in the single-line idmap equals the opener's pre-unshare euid,
	 * so we must read it now.
	 */
	uid = geteuid();
	gid = getegid();

	if (unshare(CLONE_NEWUSER | CLONE_NEWNET) != 0) {
		if (errno == EPERM) {
			if (!__atomic_exchange_n(&shm->no_userns_lane, true,
						 __ATOMIC_RELAXED))
				outputerr("child %d: userns-admin lane: "
					  "unshare(CLONE_NEWUSER|CLONE_NEWNET) "
					  "EPERM (policy); latching off\n",
					  childno);
		} else {
			outputerr("child %d: userns-admin lane: "
				  "unshare(CLONE_NEWUSER|CLONE_NEWNET) "
				  "failed (errno=%d); skipping\n",
				  childno, errno);
		}
		return;
	}

	/*
	 * Write identity uid/gid maps.  uid_map first, then setgroups=deny
	 * (required before an unprivileged writer can set gid_map), then
	 * gid_map.  Failure here is soft: the child continues to the
	 * capset(empty) drop and fuzz loop without userns-lane caps.
	 */
	snprintf(buf, sizeof(buf), "0 %u 1\n", (unsigned int)uid);
	ret = userns_lane_write_proc("/proc/self/uid_map", buf);
	if (ret != 0) {
		outputerr("child %d: userns-admin lane: uid_map write "
			  "failed (errno=%d); lane inactive\n",
			  childno, -ret);
		return;
	}

	ret = userns_lane_write_proc("/proc/self/setgroups", "deny\n");
	if (ret != 0) {
		outputerr("child %d: userns-admin lane: setgroups write "
			  "failed (errno=%d); lane inactive\n",
			  childno, -ret);
		return;
	}

	snprintf(buf, sizeof(buf), "0 %u 1\n", (unsigned int)gid);
	ret = userns_lane_write_proc("/proc/self/gid_map", buf);
	if (ret != 0) {
		outputerr("child %d: userns-admin lane: gid_map write "
			  "failed (errno=%d); lane inactive\n",
			  childno, -ret);
		return;
	}
	child_userns_lane_active = true;
}

/*
 * Returns true iff this child successfully entered the userns-admin
 * lane (unshare + all three idmap writes completed).  Consumed by the
 * cap-drop oracle to select the correct SO_RCVBUFFORCE probe direction.
 */
bool child_userns_lane_is_active(void)
{
	return child_userns_lane_active;
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

/*
 * Index of the /sys/fs/cgroup/trinity{0..7} cgroup this child was
 * placed in by munge_process().  -1 means the placement did not
 * happen (cgroup pool not pre-created, or the open/write failed).
 *
 * Per-child file-static: each forked child gets its own copy.
 * Exported via child_cgroup_slot() so BPF childops can attach to
 * the same cgroup the child is actually a member of.
 */
static int child_cgroup_idx = -1;

/*
 * Return the cgroup index this child joined in munge_process(), or
 * -1 if the join was skipped (pool not pre-created).  BPF childops
 * use this to attach to the cgroup the running task is actually in
 * so the hook fires correctly.
 */
int child_cgroup_slot(void)
{
	return child_cgroup_idx;
}

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
	 * if they don't exist we skip silently but note it once so the
	 * operator can see that BPF cgroup hooks will not fire.
	 *
	 * NOTE: nothing in-tree creates /sys/fs/cgroup/trinity0..7.
	 * cgroup-churn.c uses trinity-<pid>-<seq> and the supervisor
	 * uses trinity-kill-<pid>.  The numbered pool is a setup-time
	 * requirement: create them before running Trinity if you want
	 * BPF cgroup childops to fire.
	 */
	{
		static bool cgroup_pool_warned;
		unsigned int cg_idx = rnd_modulo_u32(8);

		snprintf(cgpath, sizeof(cgpath),
			 "/sys/fs/cgroup/trinity%u/cgroup.procs", cg_idx);
		fd = open(cgpath, O_WRONLY);
		if (fd >= 0) {
			char pidbuf[16];
			int len = snprintf(pidbuf, sizeof(pidbuf), "%d", mypid());
			ssize_t ret = write(fd, pidbuf, (size_t) len);

			if (ret > 0)
				child_cgroup_idx = (int) cg_idx;
			(void) close(fd);
		} else {
			/*
			 * Latch a one-shot warning so "cgroup pool absent"
			 * is visible in logs rather than silently inferred
			 * from zero BPF hook traffic.
			 */
			if (!__atomic_exchange_n(&cgroup_pool_warned, true,
						 __ATOMIC_RELAXED))
				outputerr("munge_process: /sys/fs/cgroup/trinity%u "
					  "not accessible (errno=%d); "
					  "/sys/fs/cgroup/trinity0..7 must be "
					  "pre-created for BPF cgroup childops "
					  "to fire\n", cg_idx, errno);
		}
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
	 * Userns-admin lane: runs here, AFTER capset(empty), so that
	 * unshare(CLONE_NEWUSER) creates a new userns in which create_user_ns()
	 * sets cap_effective = CAP_FULL_SET unconditionally.  The pre-move
	 * placement (before capset) caused the new userns to mirror the empty
	 * effective set, making every ns_capable() check return -EPERM.
	 * capset does not alter euid/egid; the identity idmap write is valid
	 * here.  Must run after the random namespace unshare block above and
	 * before the oracle anchor capture below.
	 *
	 * Only engaged when at least one active syscallentry has
	 * userns_admin_lane set and the kernel permits unprivileged user
	 * namespaces.  No entry currently sets the flag; this is a no-op
	 * for all baseline runs.
	 */
	if (find_userns_lane_entry() != NULL) {
		maybe_enter_userns_admin_lane(childno);
		/*
		 * Self-test: if the lane entered successfully SO_RCVBUFFORCE
		 * must now SUCCEED -- the socket lives in the lane's netns
		 * whose user_ns is the child's own userns where it holds
		 * CAP_FULL_SET.  A failure here turns a silent broken lane
		 * into an observable outputerr.
		 */
		if (!__atomic_load_n(&shm->no_userns_lane, __ATOMIC_RELAXED)) {
			int lane_probe_fd = socket(AF_INET, SOCK_DGRAM, 0);
			if (lane_probe_fd >= 0) {
				int lane_probe_sz = 4096;
				if (setsockopt(lane_probe_fd, SOL_SOCKET,
					       SO_RCVBUFFORCE,
					       &lane_probe_sz,
					       sizeof(lane_probe_sz)) != 0)
					outputerr("child %d: userns-admin lane "
						  "self-test: SO_RCVBUFFORCE "
						  "failed (errno=%d) -- lane "
						  "entered but ns_capable "
						  "still denied\n",
						  childno, errno);
				(void)close(lane_probe_fd);
			}
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
