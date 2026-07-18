/*
 * sysv_shm_orphan_race - drive the SysV shm orphan-destroy TOCTOU: a creator
 * task exits with SHM_DEST set (post-IPC_RMID) while concurrent attachers
 * tight-loop shmat() against the same shmid.  Targets the window in
 * ipc/shm.c between shmat's RCU lookup on ns->ids[IPC_SHM_IDS] and the
 * ipc_lock that bumps nattch: a concurrent destroy that wins the lock drops
 * the IDR slot under the attacher's feet, and exit_shm() on the creator
 * walks shm_clist and calls shm_close on the just-RMID'd segment.
 *
 * The orphan-reap path only fires for the CREATOR task's exit_shm, so this
 * op spawns a transient "originator" sub-task (never the long-lived trinity
 * dispatch child) that shmget's, publishes the shmid, briefly attaches,
 * IPC_RMIDs, and exits.  An "attacher" sibling tight-loops shmat/shmdt via
 * raw __NR_* syscalls (no libc, no dispatch, no shm pool); parent runs its
 * own attach loop for a third source of nattch pressure.  Cross-task state
 * lives in a MAP_SHARED page with atomic-release + FUTEX_WAKE go/stop.
 *
 * Brick-safety: SysV IPC segments leak kernel-wide if not RMID'd, so step
 * 8 unconditionally shmctl(IPC_RMID) as a backstop (EIDRM/EINVAL from an
 * already-destroyed segment is expected and ignored).  4096-byte segment,
 * race burst capped at 32, all loops bounded.  No modprobe / namespace /
 * sysfs writes.
 *
 * Sibling defences: PR_SET_PDEATHSIG SIGKILL immediately after clone, plus
 * a getppid()==1 re-check to cover the pre-arming window.  Independent
 * alarm(2) watchdog (no CLONE_SIGHAND, so it doesn't collide with parent's
 * SIGALRM(1)).  Raw __NR_* syscalls only.
 *
 * Cap-gate latch: first invocation probes shmget(IPC_PRIVATE,4096,...) and
 * immediately IPC_RMIDs it.  EPERM / ENOSYS / ENOSPC latches for the
 * process's life; transient EAGAIN/ENOMEM fall through to the per-iter
 * retry.  clone3 ENOSYS latches once and the op falls back to an in-process
 * single-task race so the iter isn't wasted.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "child.h"
#include "syscall-gate.h"
#include "shm.h"
#include "trinity.h"

#if __has_include(<sys/shm.h>)

#include <linux/futex.h>
#include <linux/sched.h>	/* struct clone_args */
#include <sched.h>		/* sched_yield */
#include <signal.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/shm.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include "childops-util.h"	/* waitpid_eintr */
#include "jitter.h"
#include "random.h"

/* Per-process latched gate: SysV SHM unsupported on this kernel.  Once
 * set, every subsequent invocation just bumps setup_failed and returns. */
static bool ns_unsupported_sysv_shm_orphan_race;

/* Per-process probe-once latch: false until the first invocation has
 * confirmed (or rejected) SysV SHM availability. */
static bool sysv_shm_orphan_race_probed;

/* Per-process latch: clone3() returned ENOSYS once, so don't try again.
 * Pre-5.3-ish kernels lack clone3; further attempts would burn syscall
 * entries.  Single-task race burst is the fallback. */
static bool sysv_shm_orphan_race_clone3_unavailable;

#define SYSV_SHM_LOOP_BUDGET		8U
#define SYSV_SHM_LOOP_ITERS_BASE	2U
#define SYSV_SHM_RACE_BUDGET		32U
#define SYSV_SHM_RACE_ITERS_BASE	8U
#define SYSV_SHM_SEG_BYTES		4096U
#define SYSV_SHM_PUBLISH_WAIT_NS	(100UL * 1000UL * 1000UL)	/* 100ms cap */

/* Sentinel for rs->shmid: -1 = not yet published, -2 = originator's
 * shmget failed (publish-failure marker, parent abandons iter). */
#define SYSV_SHM_ID_UNPUBLISHED		(-1)
#define SYSV_SHM_ID_PUBLISH_FAILED	(-2)

/*
 * Cross-task shared state.  Lives in a MAP_SHARED MAP_ANONYMOUS page so
 * writes from any side are immediately visible to the others -- the
 * siblings are cloned without CLONE_VM, so without MAP_SHARED their
 * COW'd pages would diverge on first write.
 *
 * `shmid` is the lookup key for the segment created by the originator.
 *   -1: not yet published (parent must wait)
 *   -2: originator's shmget failed (parent abandons iter)
 *   >=0: valid IPC id, attacher/parent may shmat
 *
 * `go` is a futex word: parent flips to 1 and FUTEX_WAKEs after both
 * siblings are spawned and the shmid is in hand.  Siblings FUTEX_WAIT
 * on it before entering their loops.
 *
 * `stop` is atomic-ACQUIRE checked by attacher each iteration so the
 * parent can ask it to exit early.  Originator does its fixed workload
 * and exits regardless.
 */
struct sysv_shm_race_shared {
	int		shmid;
	uint32_t	race_budget;
	uint32_t	go;
	uint32_t	stop;
	uint32_t	originator_published;	/* futex slot for shmid publish */
};

static long raw_futex_wait(uint32_t *uaddr, uint32_t val)
{
	return trinity_raw_syscall(__NR_futex, uaddr, FUTEX_WAIT, val, NULL, NULL, 0);
}

static long raw_futex_wake(uint32_t *uaddr, int n)
{
	return trinity_raw_syscall(__NR_futex, uaddr, FUTEX_WAKE, n, NULL, NULL, 0);
}

/*
 * Raw SysV SHM syscall wrappers for the sibling tasks.  Using
 * syscall(__NR_*) avoids libc's shm* wrappers, which on some libcs
 * touch internal state (e.g. errno is thread-local but the wrapper
 * still does a function call into libc; raw syscall keeps the sibling
 * entirely in the kernel-entry path).
 */
static long raw_shmget(key_t key, size_t size, int flag)
{
	return trinity_raw_syscall(__NR_shmget, (long)key, (long)size, (long)flag);
}

static long raw_shmat(int shmid, const void *addr, int flag)
{
	return trinity_raw_syscall(__NR_shmat, (long)shmid, (long)addr, (long)flag);
}

static long raw_shmdt(const void *addr)
{
	return trinity_raw_syscall(__NR_shmdt, (long)addr);
}

static long raw_shmctl(int shmid, int cmd, void *buf)
{
	return trinity_raw_syscall(__NR_shmctl, (long)shmid, (long)cmd, (long)buf);
}

/*
 * Originator sibling body.  Runs inside a clone3(SIGCHLD) child:
 *   - separate VM, separate sighand, separate TGID/pid
 *   - is the segment CREATOR (shm_clist entry lives on this task)
 *
 * That isolation is the whole point of this sibling: only the creator
 * task's exit_shm() walks shm_clist and runs shm_close on segments it
 * created, which is the orphan-destroy path under test.  The trinity
 * dispatch child must not be the creator -- it is long-lived and would
 * never drive exit_shm during the burst.
 *
 * By design the sibling NEVER enters trinity dispatch, never calls
 * trinity helpers, never includes shm.h, never bumps stats.  All work
 * is raw syscall(__NR_*).  Defences:
 *
 *   - PR_SET_PDEATHSIG SIGKILL: if the parent crashes, the kernel
 *     kills the orphaned sibling so it cannot leak the segment.
 *   - alarm(2): self-bound watchdog.  Independent of the parent's
 *     per-syscall alarm(1) (no CLONE_SIGHAND, so the parent's SIGALRM
 *     never reaches us).
 *   - getppid()==1 re-check post-PDEATHSIG: covers the race where the
 *     parent died between clone return and prctl arming.
 *
 * Workload: shmget -> publish -> wait for go -> shmat (puts an
 * attachment count) -> shmctl(IPC_RMID) (sets SHM_DEST) -> exit.
 * exit_shm() then runs the orphan-reap path against the just-RMID'd
 * segment, racing the parent's and attacher's concurrent shmat storm.
 */
__attribute__((noreturn))
static void sysv_shm_originator_main(struct sysv_shm_race_shared *rs)
{
	long shmid;

	(void)trinity_raw_syscall(__NR_prctl, PR_SET_PDEATHSIG, SIGKILL, 0UL, 0UL, 0UL);
	(void)alarm(2);

	if (trinity_raw_syscall(__NR_getppid) == 1)
		(void)syscall(__NR_exit, 0);

	shmid = raw_shmget(IPC_PRIVATE, SYSV_SHM_SEG_BYTES, IPC_CREAT | 0600);
	if (shmid < 0) {
		__atomic_store_n(&rs->shmid, SYSV_SHM_ID_PUBLISH_FAILED,
				 __ATOMIC_RELEASE);
		__atomic_store_n(&rs->originator_published, 1U, __ATOMIC_RELEASE);
		(void)raw_futex_wake(&rs->originator_published, 1);
		syscall(__NR_exit, 0);
		__builtin_unreachable();
	}

	__atomic_store_n(&rs->shmid, (int)shmid, __ATOMIC_RELEASE);
	__atomic_store_n(&rs->originator_published, 1U, __ATOMIC_RELEASE);
	(void)raw_futex_wake(&rs->originator_published, 1);

	while (__atomic_load_n(&rs->go, __ATOMIC_ACQUIRE) == 0U)
		(void)raw_futex_wait(&rs->go, 0U);

	/*
	 * Stay attached through IPC_RMID so the kernel sees nattch > 0
	 * and marks the segment SHM_DEST instead of destroying it
	 * immediately.  Process exit (no explicit shmdt) then drops the
	 * mapping, and exit_shm() runs the orphan-reap path against the
	 * SHM_DEST-marked segment, racing the concurrent attach storm.
	 */
	(void)raw_shmat((int)shmid, NULL, 0);

	(void)raw_shmctl((int)shmid, IPC_RMID, NULL);

	syscall(__NR_exit, 0);
	__builtin_unreachable();
}

/*
 * Attacher sibling body.  Runs inside a clone3(SIGCHLD) child with the
 * same isolation as the originator (separate VM/sighand/TGID).  Drives
 * concurrent shmat against the shmid published by the originator.
 *
 * Same defence set: PR_SET_PDEATHSIG SIGKILL, alarm(2), getppid()==1
 * re-check, raw syscall(__NR_*) only, no trinity dispatch, no shm
 * pool access.
 */
__attribute__((noreturn))
static void sysv_shm_attacher_main(struct sysv_shm_race_shared *rs)
{
	uint32_t budget;
	uint32_t i;
	int shmid;

	(void)trinity_raw_syscall(__NR_prctl, PR_SET_PDEATHSIG, SIGKILL, 0UL, 0UL, 0UL);
	(void)alarm(2);

	if (trinity_raw_syscall(__NR_getppid) == 1)
		(void)syscall(__NR_exit, 0);

	while (__atomic_load_n(&rs->go, __ATOMIC_ACQUIRE) == 0U)
		(void)raw_futex_wait(&rs->go, 0U);

	shmid = __atomic_load_n(&rs->shmid, __ATOMIC_ACQUIRE);
	if (shmid < 0)
		(void)syscall(__NR_exit, 0);

	budget = rs->race_budget;
	for (i = 0; i < budget; i++) {
		long addr;

		if (__atomic_load_n(&rs->stop, __ATOMIC_ACQUIRE) != 0U)
			break;

		addr = raw_shmat(shmid, NULL, 0);
		if (addr != -1L)
			(void)raw_shmdt((const void *)addr);
	}

	syscall(__NR_exit, 0);
	__builtin_unreachable();
}

/*
 * Allocate the shared-state page.  MAP_SHARED MAP_ANONYMOUS is the
 * cheapest cross-task primitive that survives a clone-without-CLONE_VM.
 * The page is freed by the caller via munmap().
 */
static struct sysv_shm_race_shared *race_shared_alloc(void)
{
	struct sysv_shm_race_shared *rs;

	rs = mmap(NULL, sizeof(*rs), PROT_READ | PROT_WRITE,
		  MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (rs == MAP_FAILED)
		return NULL;

	rs->shmid                = SYSV_SHM_ID_UNPUBLISHED;
	rs->race_budget          = 0;
	rs->go                   = 0;
	rs->stop                 = 0;
	rs->originator_published = 0;
	return rs;
}

/*
 * Spawn a sibling via clone3(SIGCHLD) and dispatch it to `entry`.
 * Returns the sibling pid on success, -1 on failure (caller falls back
 * to the single-task race burst).  Uses clone3 exclusively for ABI
 * portability across architectures; pre-5.3 kernels without clone3
 * latch ENOSYS once and never retry.
 *
 * No CLONE_FILES / CLONE_VM / CLONE_SIGHAND: the sibling shares only
 * the MAP_SHARED state page (mapped before fork) with the parent.
 */
typedef void (*sysv_shm_sibling_entry)(struct sysv_shm_race_shared *);

static pid_t spawn_sysv_shm_sibling(struct sysv_shm_race_shared *rs,
				    sysv_shm_sibling_entry entry)
{
	struct clone_args args;
	long ret;

	if (sysv_shm_orphan_race_clone3_unavailable)
		return -1;

	memset(&args, 0, sizeof(args));
	args.exit_signal = SIGCHLD;

	ret = trinity_raw_syscall(__NR_clone3, &args, sizeof(args));
	if (ret < 0) {
		if (errno == ENOSYS)
			sysv_shm_orphan_race_clone3_unavailable = true;
		return -1;
	}
	if (ret == 0) {
		entry(rs);
		_exit(0);	/* unreachable; entry is noreturn */
	}
	return (pid_t)ret;
}

/*
 * Reap a sibling.  Try non-blocking first so a sibling that completed
 * its budget early is reaped cheaply; if still alive, ask it to stop
 * via the shared flag, then SIGKILL + blocking waitpid.  SIGKILL is
 * unblockable and we hold no shared sighand, so the sibling cannot
 * defer or mask it.
 */
static void reap_sysv_shm_sibling(pid_t sibling, struct sysv_shm_race_shared *rs)
{
	int status = 0;
	pid_t rc;

	__atomic_store_n(&rs->stop, 1U, __ATOMIC_RELEASE);

	rc = waitpid_eintr(sibling, &status, WNOHANG);
	if (rc == 0) {
		(void)kill(sibling, SIGKILL);
		rc = waitpid_eintr(sibling, &status, 0);
	}
	if (rc <= 0)
		return;

	if (WIFEXITED(status)) {
		__atomic_add_fetch(&shm->stats.sysv_shm_orphan_race_sibling_reaped_ok,
				   1, __ATOMIC_RELAXED);
	} else if (WIFSIGNALED(status)) {
		__atomic_add_fetch(&shm->stats.sysv_shm_orphan_race_sibling_crashed,
				   1, __ATOMIC_RELAXED);
	}
}

/*
 * Wait for the originator to publish its shmid (or its publish-failed
 * sentinel).  Bounded by SYSV_SHM_PUBLISH_WAIT_NS so a sibling that
 * was SIGKILLed between clone return and shmget cannot pin the parent
 * forever.  Returns the published shmid on success, -1 on timeout or
 * publish-failure.
 */
static int wait_for_shmid_publish(struct sysv_shm_race_shared *rs)
{
	struct timespec ts;
	int shmid;

	while (__atomic_load_n(&rs->originator_published,
			       __ATOMIC_ACQUIRE) == 0U) {
		ts.tv_sec  = 0;
		ts.tv_nsec = SYSV_SHM_PUBLISH_WAIT_NS;
		(void)trinity_raw_syscall(__NR_futex, &rs->originator_published, FUTEX_WAIT,
			      0U, &ts, NULL, 0);
		if (__atomic_load_n(&rs->originator_published,
				    __ATOMIC_ACQUIRE) != 0U)
			break;
		/* Spurious wake or timeout -- give up rather than spin. */
		return -1;
	}

	shmid = __atomic_load_n(&rs->shmid, __ATOMIC_ACQUIRE);
	if (shmid < 0)
		return -1;
	return shmid;
}

/*
 * Single-task race burst: drive shmget / shmat / shmdt / IPC_RMID
 * in-process when sibling spawn fails (clone3 unavailable, EAGAIN
 * under cgroup-MAX, etc.).  No cross-task race window, but exercises
 * the shm syscall surface so a failed sibling spawn does not turn into
 * a wasted iter.  Always IPC_RMIDs every segment it creates.
 */
static void run_burst_solo(unsigned int races)
{
	unsigned int r;
	int shmid;
	void *addr;

	shmid = shmget(IPC_PRIVATE, SYSV_SHM_SEG_BYTES, IPC_CREAT | 0600);
	if (shmid < 0) {
		__atomic_add_fetch(&shm->stats.sysv_shm_orphan_race_shmget_failed,
				   1, __ATOMIC_RELAXED);
		return;
	}
	__atomic_add_fetch(&shm->stats.sysv_shm_orphan_race_shmget_ok,
			   1, __ATOMIC_RELAXED);

	for (r = 0; r < races; r++) {
		addr = shmat(shmid, NULL, 0);
		if (addr == (void *)-1) {
			__atomic_add_fetch(&shm->stats.sysv_shm_orphan_race_attach_failed,
					   1, __ATOMIC_RELAXED);
			break;
		}
		__atomic_add_fetch(&shm->stats.sysv_shm_orphan_race_attach_ok,
				   1, __ATOMIC_RELAXED);
		(void)shmdt(addr);

		if (ONE_IN(8))
			break;
	}

	if (shmctl(shmid, IPC_RMID, NULL) == 0) {
		__atomic_add_fetch(&shm->stats.sysv_shm_orphan_race_rmid_ok,
				   1, __ATOMIC_RELAXED);
	} else {
		__atomic_add_fetch(&shm->stats.sysv_shm_orphan_race_rmid_failed,
				   1, __ATOMIC_RELAXED);
	}
}

/*
 * Parent's half of the cross-task race: tight-loop shmat(shmid) +
 * shmdt(addr) for race_budget iterations.  Bumps attach_ok /
 * attach_failed.  Bails on the first attach failure (almost always
 * EIDRM from the originator's RMID + exit_shm winning the destroy
 * race) so we don't burn iters against a destroyed segment.
 */
static void run_burst_parent_half(int shmid, unsigned int races)
{
	unsigned int r;

	for (r = 0; r < races; r++) {
		void *addr;

		addr = shmat(shmid, NULL, 0);
		if (addr == (void *)-1) {
			__atomic_add_fetch(&shm->stats.sysv_shm_orphan_race_attach_failed,
					   1, __ATOMIC_RELAXED);
			break;
		}
		__atomic_add_fetch(&shm->stats.sysv_shm_orphan_race_attach_ok,
				   1, __ATOMIC_RELAXED);
		(void)shmdt(addr);
	}
}

/*
 * One outer iteration: allocate cross-task state, spawn originator,
 * wait for shmid publish, spawn attacher, flip go, drive the parent's
 * attach burst, reap siblings, then backstop-RMID the segment.
 *
 * The teardown path always attempts shmctl(IPC_RMID).  If the
 * originator's RMID + exit_shm race already destroyed the segment,
 * shmctl returns EIDRM/EINVAL; that is the expected case and is
 * counted in rmid_failed (not setup_failed -- failure here is
 * coverage, not a bug).  If RMID succeeds here, the originator died
 * before its own RMID landed (e.g. SIGKILL during the wait) and we
 * cleaned up the leak.
 */
static void iter_one(struct childdata *child)
{
	struct sysv_shm_race_shared *rs = NULL;
	pid_t originator = -1;
	pid_t attacher = -1;
	int shmid = -1;
	unsigned int races;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	races = BUDGETED(CHILD_OP_SYSV_SHM_ORPHAN_RACE,
			 SYSV_SHM_RACE_ITERS_BASE);
	if (races > SYSV_SHM_RACE_BUDGET)
		races = SYSV_SHM_RACE_BUDGET;
	if (races == 0U)
		races = 1U;

	rs = race_shared_alloc();
	if (rs == NULL) {
		__atomic_add_fetch(&shm->stats.sysv_shm_orphan_race_setup_failed,
				   1, __ATOMIC_RELAXED);
		run_burst_solo(races);
		return;
	}
	rs->race_budget = races;

	originator = spawn_sysv_shm_sibling(rs, sysv_shm_originator_main);
	if (originator < 0) {
		__atomic_add_fetch(&shm->stats.sysv_shm_orphan_race_sibling_spawn_failed,
				   1, __ATOMIC_RELAXED);
		run_burst_solo(races);
		goto out;
	}
	__atomic_add_fetch(&shm->stats.sysv_shm_orphan_race_sibling_spawn_ok,
			   1, __ATOMIC_RELAXED);

	shmid = wait_for_shmid_publish(rs);
	if (shmid < 0) {
		__atomic_add_fetch(&shm->stats.sysv_shm_orphan_race_shmget_failed,
				   1, __ATOMIC_RELAXED);
		/* Reap originator (it either exited or will exit shortly
		 * once its PDEATHSIG/alarm fires); no segment to RMID. */
		reap_sysv_shm_sibling(originator, rs);
		originator = -1;
		goto out;
	}
	__atomic_add_fetch(&shm->stats.sysv_shm_orphan_race_shmget_ok,
			   1, __ATOMIC_RELAXED);
	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	attacher = spawn_sysv_shm_sibling(rs, sysv_shm_attacher_main);
	if (attacher < 0) {
		__atomic_add_fetch(&shm->stats.sysv_shm_orphan_race_sibling_spawn_failed,
				   1, __ATOMIC_RELAXED);
	} else {
		__atomic_add_fetch(&shm->stats.sysv_shm_orphan_race_sibling_spawn_ok,
				   1, __ATOMIC_RELAXED);
	}

	__atomic_store_n(&rs->go, 1U, __ATOMIC_RELEASE);
	(void)raw_futex_wake(&rs->go, 2);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	run_burst_parent_half(shmid, races);

out:
	if (attacher > 0)
		reap_sysv_shm_sibling(attacher, rs);
	if (originator > 0)
		reap_sysv_shm_sibling(originator, rs);

	/* Backstop RMID: must NEVER leak a SysV segment.  EIDRM/EINVAL
	 * is the expected case when the originator's RMID + exit_shm
	 * already won the destroy race. */
	if (shmid >= 0) {
		if (shmctl(shmid, IPC_RMID, NULL) == 0) {
			__atomic_add_fetch(&shm->stats.sysv_shm_orphan_race_rmid_ok,
					   1, __ATOMIC_RELAXED);
		} else {
			__atomic_add_fetch(&shm->stats.sysv_shm_orphan_race_rmid_failed,
					   1, __ATOMIC_RELAXED);
		}
	}

	if (rs != NULL)
		(void)munmap(rs, sizeof(*rs));
}

/*
 * One-time SysV SHM probe.  shmget(IPC_PRIVATE, ...) + shmctl(IPC_RMID)
 * verifies both IPC namespace presence and shmget permission without
 * leaving any state behind.  Latches ns_unsupported on EPERM / ENOSYS
 * / ENOSPC; transient errors (EAGAIN, ENOMEM) do not latch.
 */
static void probe_sysv_shm(void)
{
	int shmid;

	sysv_shm_orphan_race_probed = true;

	shmid = shmget(IPC_PRIVATE, SYSV_SHM_SEG_BYTES, IPC_CREAT | 0600);
	if (shmid < 0) {
		if (errno == EPERM || errno == ENOSYS || errno == ENOSPC)
			ns_unsupported_sysv_shm_orphan_race = true;
		return;
	}
	(void)shmctl(shmid, IPC_RMID, NULL);
}

bool sysv_shm_orphan_race(struct childdata *child)
{
	unsigned int outer_iters, i;

	__atomic_add_fetch(&shm->stats.sysv_shm_orphan_race_runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_sysv_shm_orphan_race) {
		__atomic_add_fetch(&shm->stats.sysv_shm_orphan_race_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (!sysv_shm_orphan_race_probed) {
		probe_sysv_shm();
		if (ns_unsupported_sysv_shm_orphan_race) {
			/* child->op_type lives in shared memory and can be
			 * scribbled by a poisoned-arena write from a sibling;
			 * bounds-check the snapshot before indexing the
			 * NR_CHILD_OP_TYPES-sized stats array, same pattern
			 * the child.c dispatch loop uses for the unguarded
			 * write that motivated this guard. */
			{
				const enum child_op_type op = child->op_type;
				if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
					__atomic_store_n(&shm->stats.childop.latch_reason[op],
							 CHILDOP_LATCH_NS_UNSUPPORTED,
							 __ATOMIC_RELAXED);
			}
			__atomic_add_fetch(&shm->stats.sysv_shm_orphan_race_setup_failed,
					   1, __ATOMIC_RELAXED);
			return true;
		}
	}

	outer_iters = BUDGETED(CHILD_OP_SYSV_SHM_ORPHAN_RACE,
			       JITTER_RANGE(SYSV_SHM_LOOP_ITERS_BASE));
	if (outer_iters > SYSV_SHM_LOOP_BUDGET)
		outer_iters = SYSV_SHM_LOOP_BUDGET;
	if (outer_iters == 0U)
		outer_iters = 1U;

	for (i = 0; i < outer_iters; i++)
		iter_one(child);

	return true;
}

#else  /* !__has_include(<sys/shm.h>) */

bool sysv_shm_orphan_race(struct childdata *child)
{
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * write entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.sysv_shm_orphan_race_runs,
			   1, __ATOMIC_RELAXED);
	if (valid_op)
		__atomic_store_n(&shm->stats.childop.latch_reason[op],
				 CHILDOP_LATCH_UNSUPPORTED, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.sysv_shm_orphan_race_setup_failed,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif /* __has_include(<sys/shm.h>) */
