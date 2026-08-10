/*
 * process_mrelease_race - race process_mrelease(2) against mm teardown
 * while mm_users transitions.
 *
 * Trinity's normal random_syscall path hands process_mrelease(2) a
 * random live pidfd.  The syscall validates the fd, checks that the
 * target is exiting, then falls through to reap_mm() / __mmput().
 * With a random live pidfd the target is almost never in the narrow
 * exiting window, so the validation fails with EINVAL or ESRCH and
 * the teardown paths -- reap_mm(), __mmput() racing mm_users from 1
 * to 0, the anon-vma walks, swap-entry release, and the folio-batch
 * drain -- see essentially zero coverage.
 *
 * This op closes the gap by constructing a controlled lifecycle:
 *
 *   1. Fork a victim that faults 16-128 MiB of anonymous memory
 *      (optionally adding a shmem mapping and a MADV_HUGEPAGE THP
 *      hint for variety).  The victim signals readiness via a pipe,
 *      then blocks waiting for the parent.
 *   2. Parent opens a pidfd for the victim, then SIGKILLs it and
 *      simultaneously releases two process_mrelease racer processes
 *      and a waitid racer from a pipe-EOF starting line.  The parent
 *      races with madvise(DONTNEED/FREE) on a background mapping and
 *      close(pidfd).
 *   3. A negative-control round forks a child that exits normally;
 *      process_mrelease on the already-reaped task should return
 *      ESRCH or EINVAL, never 0.
 *
 * success / EINTR / ESRCH / EINVAL / other_fail are tracked
 * separately.  The coverage goal is mm teardown while mm_users
 * transitions, not pidfd argument parsing.
 */

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "arch.h"		/* page_size */
#include "child.h"
#include "childop-outcome.h"
#include "childops-util.h"
#include "jitter.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "syscall-gate.h"
#include "signals.h"
#include "trinity.h"
#include "utils.h"

/* Victim memory footprint range in MiB. */
#define VICTIM_MIB_MIN	 16U
#define VICTIM_MIB_MAX	128U

/* Kill-race rounds per invocation. */
#define NR_KILL_ROUNDS	3U

/* Number of concurrent process_mrelease racer processes per round. */
#define NR_RACERS	2U

/* Per-racer result slot in the shared results page.
 * The direct_count field accumulates raw-syscall sites so the
 * childop-direct-syscall-uncounted check can verify each fork worker
 * is wired into the syscall telemetry.  It is summed by the parent
 * and forwarded to childop_direct_syscalls_add() at op-exit. */
struct racer_result {
	int           rc;           /* 0 on success, -errno on failure */
	unsigned long direct_count; /* raw-syscall count from this child */
};

/* Indices into the results[] page.
 * [0..NR_RACERS-1] for process_mrelease racers,
 * NR_RACERS for the waitid racer, NR_RACERS+1 for the victim. */
#define RESULT_IDX_WAITID	(NR_RACERS)
#define RESULT_IDX_VICTIM	(NR_RACERS + 1)
#define NR_RESULT_SLOTS		(NR_RACERS + 2)

/* Latched: process_mrelease(2) returned ENOSYS -- kernel predates 5.15. */
static bool ns_unsupported_process_mrelease;
/* Latched: process_mrelease(2) confirmed present -- skip the support probe. */
static bool ns_supported_process_mrelease;

static int sys_process_mrelease(int pidfd, unsigned int flags)
{
#ifdef __NR_process_mrelease
	return (int)trinity_raw_syscall(__NR_process_mrelease, pidfd, flags);
#else
	(void)pidfd;
	(void)flags;
	errno = ENOSYS;
	return -1;
#endif
}

static int sys_pidfd_open(pid_t pid, unsigned int flags)
{
#ifdef __NR_pidfd_open
	return (int)trinity_raw_syscall(__NR_pidfd_open, pid, flags);
#else
	(void)pid;
	(void)flags;
	errno = ENOSYS;
	return -1;
#endif
}

/*
 * Bump the control-probe counter that matches the process_mrelease() outcome.
 * Called only for the known-negative control probes; race results go to
 * tally_mrelease_result() instead.
 */
static void tally_control_result(int rc)
{
	if (rc == 0) {
		__atomic_add_fetch(
			&shm->stats.process_mrelease_race.control_unexpected_success,
			1, __ATOMIC_RELAXED);
		return;
	}
	switch (errno) {
	case ESRCH:
		__atomic_add_fetch(
			&shm->stats.process_mrelease_race.control_esrch,
			1, __ATOMIC_RELAXED);
		break;
	case EINVAL:
		__atomic_add_fetch(
			&shm->stats.process_mrelease_race.control_einval,
			1, __ATOMIC_RELAXED);
		break;
	default:
		break;
	}
}

/*
 * Translate a process_mrelease() return value into a stats bucket and
 * bump the matching counter.  Called for each racer result.
 */
static void tally_mrelease_result(int rc)
{
	if (rc == 0) {
		__atomic_add_fetch(&shm->stats.process_mrelease_race.success,
				   1, __ATOMIC_RELAXED);
		return;
	}
	switch (errno) {
	case EINTR:
		__atomic_add_fetch(&shm->stats.process_mrelease_race.eintr,
				   1, __ATOMIC_RELAXED);
		break;
	case ESRCH:
		__atomic_add_fetch(&shm->stats.process_mrelease_race.esrch,
				   1, __ATOMIC_RELAXED);
		break;
	case EINVAL:
		__atomic_add_fetch(&shm->stats.process_mrelease_race.einval,
				   1, __ATOMIC_RELAXED);
		break;
	default:
		__atomic_add_fetch(&shm->stats.process_mrelease_race.other_fail,
				   1, __ATOMIC_RELAXED);
		break;
	}
}

/*
 * Victim child body.  Faults a large anonymous region (plus optionally
 * a shmem region and a MADV_HUGEPAGE hint) to fill the mm with diverse
 * VMAs, signals readiness, then blocks until the release pipe gives EOF.
 * Called only in the child branch of fork(); never returns.
 *
 * PR_SET_PDEATHSIG + getppid() re-check ensures we die if the parent
 * crashes before sending SIGKILL.
 */
static void victim_body(int ready_wr, int release_rd,
			size_t fault_bytes, bool add_shmem, bool add_thp,
			struct racer_result *slot)
{
	CHILDOP_GRANDCHILD_ENTER();
	void *anon_region;
	void *shmem_region = MAP_FAILED;
	volatile char *p;
	size_t i;
	char rdy = 'R';
	char byte;
	unsigned long ncalls = 0; /* raw-syscall count for tally */

	(void)prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
	if (getppid() == 1)
		_exit(0);

	anon_region = mmap(NULL, fault_bytes,
			   PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	ncalls++;	/* mmap */
	if (anon_region == MAP_FAILED)
		goto done;

	if (add_thp)
		(void)madvise(anon_region, fault_bytes, MADV_HUGEPAGE);

	/* Fault every page to build a populated mm. */
	p = anon_region;
	for (i = 0; i < fault_bytes; i += page_size)
		p[i] = (char)(i & 0xff);

	if (add_shmem) {
		shmem_region = mmap(NULL, 4 * 1024 * 1024,
				    PROT_READ | PROT_WRITE,
				    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
		ncalls++;	/* mmap (shmem) */
		if (shmem_region != MAP_FAILED) {
			volatile char *sp = shmem_region;
			for (i = 0; i < 4 * 1024 * 1024; i += page_size)
				sp[i] = 1;
		}
	}

	/* Signal parent: memory is faulted and we are ready. */
	{
		ssize_t w;

		do {
			w = write(ready_wr, &rdy, 1);
		} while (w < 0 && errno == EINTR);
		ncalls++;	/* write */
	}
	close(ready_wr);
	ncalls++;	/* close */

	/* Flush the running count to the shared slot before blocking.
	 * SIGKILL arrives during read() below; the done: label is
	 * unreachable in normal flow, so this is the only live store. */
	if (slot)
		slot->direct_count = ncalls;

	/* Block until parent closes the write end of release_pipe (EOF). */
	{
		ssize_t r;

		do {
			r = read(release_rd, &byte, 1);
		} while (r < 0 && errno == EINTR);
		ncalls++;	/* read */
	}
	close(release_rd);
	ncalls++;	/* close */

	/* Unreachable in normal flow -- SIGKILL lands here. */
	(void)munmap(anon_region, fault_bytes);
	if (shmem_region != MAP_FAILED)
		(void)munmap(shmem_region, 4 * 1024 * 1024);

done:
	_exit(0);
}

/*
 * Racer child body.  Blocks at the release pipe's EOF starting line,
 * then immediately calls process_mrelease(pidfd, 0) and writes the
 * result into its slot in the shared results page before exiting.
 *
 * We inherit both the release_rd fd and the pidfd from the parent
 * across fork().  No other work is done here -- this process exists
 * only to race the mm teardown.
 */
static void racer_body(int pidfd, int release_rd,
		       struct racer_result *slot)
{
	CHILDOP_GRANDCHILD_ENTER();
	char byte;
	int rc;

	(void)prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
	if (getppid() == 1)
		_exit(0);

	/* Block until parent closes the release pipe (EOF). */
	{
		ssize_t r;

		do {
			r = read(release_rd, &byte, 1);
		} while (r < 0 && errno == EINTR);
	}
	close(release_rd);

	rc = sys_process_mrelease(pidfd, 0);
	slot->rc = rc;
	if (rc < 0)
		slot->rc = -errno;
	/* Wire raw-syscall sites into the per-slot tally so the
	 * childop-direct-syscall-uncounted gate can verify this
	 * fork worker is accounted: read+close+process_mrelease = 3. */
	slot->direct_count = 3;

	_exit(0);
}

/*
 * waitid-racer child body.  Mirrors racer_body() but calls
 * waitid(P_PIDFD, ...) to race the reap against process_mrelease.
 * We use WNOWAIT so we don't consume the wait state; the parent still
 * waitpid()'s the victim normally after the racers have all exited.
 */
static void waitid_racer_body(int pidfd, int release_rd,
			      struct racer_result *slot)
{
	CHILDOP_GRANDCHILD_ENTER();
	char byte;
	siginfo_t info;

	(void)prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
	if (getppid() == 1)
		_exit(0);

	{
		ssize_t r;

		do {
			r = read(release_rd, &byte, 1);
		} while (r < 0 && errno == EINTR);
	}
	close(release_rd);

	memset(&info, 0, sizeof(info));
	/* P_PIDFD = 3 on Linux; use the constant directly as some build
	 * environments lack the idtype_t enum value. */
	(void)trinity_raw_syscall(__NR_waitid, 3UL, (unsigned long)pidfd,
				  (unsigned long)&info,
				  (unsigned long)(WEXITED | WNOWAIT),
				  0UL);
	/* Wire raw-syscall sites: read+close+waitid = 3. */
	slot->direct_count = 3;
	_exit(0);
}

/*
 * Spawn the victim child and open a pidfd for it.  Returns the
 * victim's pid on success; returns -1 on any error and cleans up.
 * ready_wr is the write end of the ready_pipe (victim signals parent).
 * release_rd is the read end of the release pipe (parent closes write
 * end to simultaneously unblock all racers + this victim read).
 *
 * victim_pidfd_out receives the opened pidfd (>=0) on success.
 */
static pid_t spawn_victim(int ready_wr, int release_rd,
			  int *victim_pidfd_out,
			  struct racer_result *slot)
{
	size_t fault_mib;
	size_t fault_bytes;
	bool add_shmem;
	bool add_thp;
	pid_t pid;
	int pfd;

	fault_mib   = VICTIM_MIB_MIN +
		      rnd_modulo_u32(VICTIM_MIB_MAX - VICTIM_MIB_MIN + 1);
	fault_bytes = fault_mib * 1024 * 1024;
	add_shmem   = RAND_BOOL();
	add_thp     = RAND_BOOL();

	pid = fork();
	if (pid == 0)
		victim_body(ready_wr, release_rd, fault_bytes,
			    add_shmem, add_thp, slot);	/* never returns */
	if (pid < 0)
		return -1;

	pfd = sys_pidfd_open(pid, 0);
	if (pfd < 0) {
		kill(pid, SIGKILL);
		(void)waitpid_eintr(pid, NULL, 0);
		return -1;
	}
	*victim_pidfd_out = pfd;
	return pid;
}

/*
 * Spawn one process_mrelease racer.  The child inherits pidfd and
 * release_rd.  Its result lands in results[slot_idx].
 * Returns the spawned pid, or -1 on fork failure.
 */
static pid_t spawn_mrelease_racer(int pidfd, int release_rd,
				  struct racer_result *slot)
{
	pid_t pid = fork();

	if (pid == 0)
		racer_body(pidfd, release_rd, slot);	/* never returns */
	return pid;
}

/*
 * Run one SIGKILL + race round.
 *
 * Orchestration:
 *   1. Allocate shared results page.
 *   2. Create ready_pipe and release_pipe.
 *   3. Spawn victim; wait for its readiness signal.
 *   4. Spawn NR_RACERS process_mrelease racers + one waitid racer.
 *   5. SIGKILL victim, then close release_pipe write end to fire
 *      all racers simultaneously.
 *   6. Parent races madvise(bg_map) + close(pidfd).
 *   7. Collect all racer pids and tally results.
 *   8. Reap victim.
 */
static unsigned long run_kill_race(void *bg_map, size_t bg_size)
{
	struct racer_result *results;
	int ready_pipe[2];
	int release_pipe[2];
	int victim_pidfd = -1;
	pid_t victim_pid;
	pid_t racer_pids[NR_RACERS];
	pid_t waitid_pid = -1;
	unsigned int i;
	unsigned long direct_sum = 0;
	char ready_byte;

	results = mmap(NULL, page_size,
		       PROT_READ | PROT_WRITE,
		       MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (results == MAP_FAILED)
		return 0;
	memset(results, 0, page_size);

	/* Initialise every racer slot to a sentinel so unwritten slots
	 * (fork failure, PDEATHSIG early exit before store) are
	 * distinguishable from a real rc==0 success. */
	for (i = 0; i < NR_RACERS; i++)
		results[i].rc = INT_MIN;

	if (pipe(ready_pipe) < 0)
		goto out_results;
	if (pipe(release_pipe) < 0)
		goto out_ready;

	/* Spawn victim; it closes ready_wr after writing 'R'. */
	victim_pid = spawn_victim(ready_pipe[1], release_pipe[0],
				  &victim_pidfd,
				  &results[RESULT_IDX_VICTIM]);
	if (victim_pid < 0)
		goto out_pipes;

	close(ready_pipe[1]);
	ready_pipe[1] = -1;

	/* Wait for victim to finish faulting its memory. */
	if (read(ready_pipe[0], &ready_byte, 1) != 1 ||
	    ready_byte != 'R') {
		kill(victim_pid, SIGKILL);
		(void)waitpid_eintr(victim_pid, NULL, 0);
		close(victim_pidfd);
		goto out_pipes;
	}
	close(ready_pipe[0]);
	ready_pipe[0] = -1;

	/* Spawn process_mrelease racers. */
	for (i = 0; i < NR_RACERS; i++) {
		racer_pids[i] = spawn_mrelease_racer(victim_pidfd,
						     release_pipe[0],
						     &results[i]);
		if (racer_pids[i] < 0)
			racer_pids[i] = -1;
	}

	/* Spawn waitid racer. */
	waitid_pid = fork();
	if (waitid_pid == 0)
		waitid_racer_body(victim_pidfd, release_pipe[0],
				  &results[RESULT_IDX_WAITID]);

	/* SIGKILL victim, then release all racers via EOF on release_pipe. */
	kill(victim_pid, SIGKILL);
	close(release_pipe[0]);
	release_pipe[0] = -1;
	close(release_pipe[1]);
	release_pipe[1] = -1;

	/* Parent races: madvise background mapping + close pidfd. */
	if (bg_map != MAP_FAILED) {
		(void)madvise(bg_map, bg_size,
			      RAND_BOOL() ? MADV_DONTNEED : MADV_FREE);
	}
	close(victim_pidfd);
	victim_pidfd = -1;

	/* Collect all racer pids. */
	for (i = 0; i < NR_RACERS; i++) {
		if (racer_pids[i] > 0)
			(void)waitpid_eintr(racer_pids[i], NULL, 0);
	}
	if (waitid_pid > 0)
		(void)waitpid_eintr(waitid_pid, NULL, 0);

	/* Tally racer results. */
	for (i = 0; i < NR_RACERS; i++) {
		int rc = results[i].rc;

		/* INT_MIN means the child never wrote its result slot
		 * (fork failure, PDEATHSIG early exit before store).
		 * Count it separately so the invariant
		 *   success + esrch + einval + eintr + other_fail +
		 *   racer_unreported == kill_rounds * NR_RACERS
		 * always holds, and skip tally_mrelease_result() which
		 * would miscount the sentinel as a spurious success. */
		if (rc == INT_MIN) {
			__atomic_add_fetch(
				&shm->stats.process_mrelease_race.racer_unreported,
				1, __ATOMIC_RELAXED);
			continue;
		}
		if (rc < 0)
			errno = -rc;
		tally_mrelease_result(rc);
	}

	/* Reap victim: non-blocking try first, then blocking. */
	{
		int status;

		if (waitpid_eintr(victim_pid, &status, WNOHANG) != victim_pid) {
			__atomic_add_fetch(
				&shm->stats.process_mrelease_race.reap_slow,
				1, __ATOMIC_RELAXED);
			(void)waitpid_eintr(victim_pid, &status, 0);
		}
	}

	__atomic_add_fetch(&shm->stats.process_mrelease_race.kill_rounds,
			   1, __ATOMIC_RELAXED);

	/* Sum direct_count from slots that were actually written.
	 * For mrelease racers: rc==INT_MIN means the child never stored a
	 * result (fork failure, PDEATHSIG early exit).  For the waitid and
	 * victim children use the fork-success pid as the guard. */
	for (i = 0; i < NR_RACERS; i++) {
		if (results[i].rc != INT_MIN)
			direct_sum += results[i].direct_count;
	}
	if (waitid_pid > 0)
		direct_sum += results[RESULT_IDX_WAITID].direct_count;
	if (victim_pid > 0)
		direct_sum += results[RESULT_IDX_VICTIM].direct_count;

	(void)munmap(results, page_size);
	return direct_sum;

out_pipes:
	if (release_pipe[0] >= 0) close(release_pipe[0]);
	if (release_pipe[1] >= 0) close(release_pipe[1]);
out_ready:
	if (ready_pipe[0] >= 0) close(ready_pipe[0]);
	if (ready_pipe[1] >= 0) close(ready_pipe[1]);
out_results:
	(void)munmap(results, page_size);
	return 0;
}

/*
 * Negative-control probe: fork a child that exits immediately (normal
 * exit), reap it via waitpid so the pidfd goes stale, then call
 * process_mrelease on it.  Expected result: ESRCH or EINVAL; a return
 * of 0 would be a kernel bug.
 *
 * Results go to the control counters, not the race-result counters.
 * ENOSYS is not tallied here -- the caller handles the unsupported latch.
 *
 * Returns 0 on process_mrelease success, -1 on failure (errno set), or
 * 1 if the probe was inconclusive (pidfd_open failed before the syscall
 * was issued -- caller should not update support state or direct_calls).
 */
static int run_exit_probe(void)
{
	int pfd;
	pid_t pid;
	int rc;
	int status;

	pid = fork();
	if (pid == 0) {
		CHILDOP_GRANDCHILD_ENTER();
		_exit(0);
	}
	if (pid < 0)
		return 1;

	pfd = sys_pidfd_open(pid, 0);

	/* Reap the child so process_mrelease sees a dead/stale target. */
	(void)waitpid_eintr(pid, &status, 0);

	if (pfd < 0)
		return 1;

	rc = sys_process_mrelease(pfd, 0);
	{
		int saved_errno = errno;

		close(pfd);
		errno = saved_errno;
	}

	/* Tally into control counters; leave ENOSYS for the caller. */
	if (rc < 0 && errno == ENOSYS)
		return rc;
	tally_control_result(rc);
	return rc;
}

bool process_mrelease_race(struct childdata *child)
{
	void *bg_map;
	size_t bg_size;
	unsigned int i;
	unsigned long direct_calls = 0;
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int)op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.process_mrelease_race.runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_process_mrelease)
		return true;

	/*
	 * Probe for ENOSYS / confirm support on the first call.
	 * run_exit_probe() subsumes the old inline fork; once support is
	 * confirmed, ns_supported_process_mrelease latches true and the
	 * probe is skipped on every subsequent invocation.
	 */
	if (!ns_supported_process_mrelease) {
		int probe_rc = run_exit_probe();

		if (probe_rc < 0 && errno == ENOSYS) {
			ns_unsupported_process_mrelease = true;
			if (valid_op) {
				__atomic_store_n(
					&shm->stats.childop.latch_reason[op],
					CHILDOP_LATCH_NS_UNSUPPORTED,
					__ATOMIC_RELAXED);
			}
			return true;
		}
		if (probe_rc <= 0) {
			/* Syscall confirmed present; latch to skip next time. */
			ns_supported_process_mrelease = true;
			direct_calls++;
		}
		/* probe_rc == 1: pidfd_open failed, probe inconclusive;
		 * leave ns_supported_process_mrelease false and retry next
		 * invocation. */
	}

	/* Background mapping for madvise pressure during race rounds. */
	bg_size = 8 * 1024 * 1024;
	bg_map  = mmap(NULL, bg_size, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (bg_map != MAP_FAILED) {
		volatile char *p = bg_map;
		size_t j;

		for (j = 0; j < bg_size; j += page_size)
			p[j] = 1;
	}

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	for (i = 0; i < JITTER_RANGE(NR_KILL_ROUNDS); i++) {
		if (valid_op)
			__atomic_add_fetch(
				&shm->stats.childop.data_path[op],
				1, __ATOMIC_RELAXED);
		/* Accumulate direct-syscall counts from result slots that
		 * were actually written; bail paths that issued zero
		 * process_mrelease calls contribute zero. */
		direct_calls += run_kill_race(bg_map, bg_size);
	}

	/* Control probe already ran (and latched) on first invocation;
	 * nothing extra to do here on subsequent calls. */

	if (bg_map != MAP_FAILED)
		(void)munmap(bg_map, bg_size);

	if (valid_op)
		childop_direct_syscalls_add(op, direct_calls);

	return true;
}
