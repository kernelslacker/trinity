/*
 * pidfd_storm - rapid pidfd_open/pidfd_send_signal/pidfd_getfd churn
 * against a small pool of self-forked children.
 *
 * Trinity's random_syscall path can issue pidfd_open, pidfd_send_signal,
 * and pidfd_getfd individually, but only sporadically and against
 * arbitrary (mostly invalid) pids, so the kernel's pidfd code path —
 * pidfd_get_pid, pidfd_get_task, pidfd_send_signal's group_send_sig_info
 * fast path, and pidfd_getfd's PTRACE_MODE_ATTACH_REALCREDS check
 * followed by __fget+receive_fd() — only sees one stray operation at a
 * time.  pidfd_storm closes that gap by holding a small pool of pidfds
 * onto live children of its own and hammering them in a tight bounded
 * loop, so the pidfd refcount/install/lookup paths see sustained
 * concurrent pressure within a single task and (across multiple
 * pidfd_storm children running in parallel under --alt-op-children)
 * across tasks too.
 *
 * Each invocation:
 *
 *   1. Forks NR_CHILDREN short-lived children that immediately call
 *      pause(); these are alive (so pidfd_open succeeds and the
 *      pidfd_send_signal target lookup hits a real task) but do nothing
 *      else (we don't want sibling fuzz behaviour from them).
 *   2. pidfd_open(child_pid, 0) on each, holding the pidfds in an array.
 *   3. Storm loop, capped at MAX_ITERATIONS or BUDGET_NS:
 *      - Pick a random pidfd from the pool.
 *      - Either pidfd_send_signal with a curated signal from a benign
 *        set (SIGUSR1, SIGUSR2, SIGCONT, SIGSTOP, SIGCHLD — explicitly
 *        no SIGKILL/SIGTERM here, those are reserved for teardown), or
 *      - pidfd_getfd with a small target_fd value (0/1/2 plus a few
 *        small ints).  These succeed against just-forked children that
 *        inherited the parent's fd table; any returned fd is closed
 *        immediately so the storm doesn't accumulate fd debt.
 *   4. Teardown (outside the timed budget):
 *        SIGKILL every pidfd via pidfd_send_signal, waitpid() each child
 *        to reap, close every pidfd.  All accounted for so no zombie or
 *        leaked pidfd escapes the op.
 *
 * Self-bounding:
 *   - MAX_ITERATIONS caps inner-loop iterations.
 *   - BUDGET_NS (200 ms) sits in the same band pipe_thrash / flock_thrash
 *     use; setup/teardown is OUTSIDE the timed budget so the storm
 *     itself fits in the window.
 *   - alarm(1) is armed by child.c around every non-syscall op, so a
 *     wedged pidfd path here still trips the SIGALRM stall detector.
 *   - All forked children are reaped before return.
 */

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "childops-util.h"
#include "jitter.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/* Wall-clock ceiling for the inner storm loop.  Same band as
 * pipe_thrash / flock_thrash so dump_stats keeps ticking and SIGALRM
 * stall detection still has headroom.  Setup (fork+pidfd_open) and
 * teardown (SIGKILL+waitpid+close) run OUTSIDE this budget. */
#define BUDGET_NS	200000000L	/* 200 ms */

/* Hard cap on inner storm iterations.  Each iteration is one
 * pidfd_send_signal or one pidfd_getfd+close; both are cheap, so 64 is
 * plenty of cache-hot pressure within the budget without risking the
 * SIGALRM stall detector. */
#define MAX_ITERATIONS	64

/* Number of children we fork per invocation.  Small on purpose: enough
 * to spread pidfd_send_signal across multiple targets so each storm
 * iteration can pick a different one, but well under any sane
 * RLIMIT_NPROC margin. */
#define NR_CHILDREN	6

/* Curated signal set for the storm body.  Explicitly avoids
 * SIGKILL/SIGTERM — those are for teardown.  SIGSTOP/SIGCONT exercise
 * the job-control path inside pidfd_send_signal; SIGCHLD targets the
 * SIGCHLD-as-arbitrary-signal path; SIGUSR1/SIGUSR2 are the standard
 * "harmless but delivered" choices. */
static const int storm_signals[] = {
	SIGUSR1,
	SIGUSR2,
	SIGCONT,
	SIGSTOP,
	SIGCHLD,
};

/* Small target_fd values for pidfd_getfd.  0/1/2 are stdin/stdout/stderr
 * and basically always present in a forked child; the few small ints
 * cover other early-allocated fds that may be inherited. */
static const int getfd_targets[] = {
	0, 1, 2, 3, 4, 5,
};

/*
 * Sanitize the pause-child's signal environment before it enters
 * pause().  The forked child inherited every handler trinity installed
 * (child_fault_handler for SIGSEGV/SIGBUS/SIGFPE, SIGCHLD reaper,
 * SIGALRM stall detector); when the storm delivers SIGUSR1 / SIGUSR2 /
 * SIGCHLD here those handlers run in the wrong process context,
 * touching shared shm state and writing per-pid logs under the wrong
 * pid.  Worst case, child_fault_handler dumps a crash log for the
 * wrong pid on a stray SIGSEGV.  Reset every catchable handler to
 * SIG_DFL so any unexpected fault here just kills the pause-child
 * cleanly.
 *
 * Then re-arm every signal in storm_signals[] to SIG_IGN.  The default
 * action for SIGUSR1/SIGUSR2 is terminate, so leaving them as SIG_DFL
 * would evict the target on the very first storm hit — the pause-child
 * would die, the pidfd pool would shrink, and the storm would lose the
 * repeat-pressure it is meant to apply.  SIG_IGN keeps the helper
 * looping in pause() across arbitrarily many deliveries.  SIGCHLD's
 * default is already ignore (no-op).  SIGSTOP/SIGCONT drive job
 * control regardless of disposition, so SIG_IGN does not disturb that
 * path.  Teardown still works because trinity reaps these helpers
 * with SIGKILL, which is uncatchable.
 */
static void sanitize_pause_child_signals(void)
{
	unsigned int i;
	int s;

	for (s = 1; s < NSIG; s++)
		(void)signal(s, SIG_DFL); /* SIGKILL/SIGSTOP return SIG_ERR; harmless. */

	for (i = 0; i < ARRAY_SIZE(storm_signals); i++)
		(void)signal(storm_signals[i], SIG_IGN);
}

static int sys_pidfd_open(pid_t pid, unsigned int flags)
{
#ifdef __NR_pidfd_open
	return (int) syscall(__NR_pidfd_open, pid, flags);
#else
	(void) pid;
	(void) flags;
	errno = ENOSYS;
	return -1;
#endif
}

static int sys_pidfd_send_signal(int pidfd, int sig, siginfo_t *info,
				 unsigned int flags)
{
#ifdef __NR_pidfd_send_signal
	return (int) syscall(__NR_pidfd_send_signal, pidfd, sig, info, flags);
#else
	(void) pidfd;
	(void) sig;
	(void) info;
	(void) flags;
	errno = ENOSYS;
	return -1;
#endif
}

static int sys_pidfd_getfd(int pidfd, int targetfd, unsigned int flags)
{
#ifdef __NR_pidfd_getfd
	return (int) syscall(__NR_pidfd_getfd, pidfd, targetfd, flags);
#else
	(void) pidfd;
	(void) targetfd;
	(void) flags;
	errno = ENOSYS;
	return -1;
#endif
}

struct pidfd_slot {
	pid_t pid;
	int pidfd;
};

/*
 * Setup phase: fork up to nr pause-children and open a pidfd for each,
 * filling the caller-owned slots[] and returning the count of live
 * slots.  Runs outside the timed storm budget — the storm itself only
 * counts iterations of the inner loop.
 *
 * The child branch of fork() lives inside this helper on purpose: the
 * inherited-handler reset (sanitize_pause_child_signals) must run in
 * the forked child before pause(), so it stays welded to the fork
 * site.  A slot whose pidfd_open failed keeps pidfd=-1 so teardown can
 * still reap the pid via kill(2).
 */
static unsigned int pidfd_storm_iter_spawn(struct pidfd_slot *slots,
					   unsigned int nr)
{
	unsigned int active = 0;
	unsigned int i;

	for (i = 0; i < nr; i++) {
		pid_t pid = fork();

		if (pid == 0) {
			/* Child: just sit here until the parent SIGKILLs us
			 * at teardown.  Don't do anything else — we don't
			 * want sibling fuzz behaviour leaking out of this
			 * helper.  Reset the inherited trinity signal
			 * handlers first so the storm's signal traffic
			 * doesn't fire them in the wrong process context.
			 * pause() returns on any signal handler delivery,
			 * so loop to absorb SIGUSR1/2/CHLD/CONT (which have
			 * default actions of ignore/term/ignore; relying on
			 * default to stay alive on USR1/USR2/CHLD is
			 * fragile, so re-enter pause unconditionally).
			 *
			 * PR_SET_PDEATHSIG SIGKILL: if the parent crashes
			 * before sending the teardown SIGKILL, the kernel
			 * reaps us instead of orphaning us to PID 1 where
			 * we'd pause() forever.  Re-check getppid() after
			 * arming the death signal — the parent may already
			 * be gone by the time the inner gets scheduled, in
			 * which case PDEATHSIG was set too late to fire. */
			sanitize_pause_child_signals();
			(void)syscall(__NR_prctl, PR_SET_PDEATHSIG, SIGKILL,
				      0UL, 0UL, 0UL);
			if (getppid() == 1)
				_exit(0);
			for (;;)
				pause();
			_exit(0);	/* unreachable */
		}

		if (pid < 0)
			break;

		slots[active].pid = pid;
		slots[active].pidfd = sys_pidfd_open(pid, 0);
		if (slots[active].pidfd < 0) {
			__atomic_add_fetch(&shm->stats.pidfd_storm_failed,
					   1, __ATOMIC_RELAXED);
			/* pidfd_open failed (ENOSYS on ancient kernels, or
			 * the child raced and exited).  We still need to
			 * reap this pid in teardown, so keep the slot but
			 * mark pidfd as -1 — teardown handles that. */
		}
		active++;
	}

	return active;
}

/*
 * Storm phase: tight bounded loop over the live slots, picking a
 * random pidfd each iteration and either signalling it (curated
 * benign signal with an occasional negative-edge substitution) or
 * pulling an fd out of it via pidfd_getfd (closed immediately so the
 * storm doesn't accumulate fd debt).  Caller guarantees active > 0.
 * Loop is double-bounded by the iters cap and the BUDGET_NS
 * wall-clock gate; the timer is started inside the helper so the
 * caller doesn't have to thread a timespec through.
 */
static void pidfd_storm_iter_drive(struct pidfd_slot *slots,
				   unsigned int active, unsigned int iters)
{
	struct timespec start;
	unsigned int iter;

	clock_gettime(CLOCK_MONOTONIC, &start);

	for (iter = 0; iter < iters; iter++) {
		struct pidfd_slot *s = &slots[rnd_modulo_u32(active)];
		int rc;

		if (s->pidfd < 0)
			continue;

		if (rnd_modulo_u32(2) == 0) {
			int sig = storm_signals[rnd_modulo_u32(ARRAY_SIZE(storm_signals))];

			/* 1-in-RAND_NEGATIVE_RATIO sub the curated benign signal
			 * for a curated edge value (-1, 0, INT_MAX, ...) — the
			 * curated set above is all valid signals, so this is the
			 * only path that exercises pidfd_send_signal's signo
			 * range check (valid_signal()). */
			rc = sys_pidfd_send_signal(s->pidfd,
						   (int)RAND_NEGATIVE_OR(sig),
						   NULL, 0);
			if (rc == 0) {
				__atomic_add_fetch(&shm->stats.pidfd_storm_signals,
						   1, __ATOMIC_RELAXED);
			} else {
				__atomic_add_fetch(&shm->stats.pidfd_storm_failed,
						   1, __ATOMIC_RELAXED);
			}
		} else {
			int target = getfd_targets[rnd_modulo_u32(ARRAY_SIZE(getfd_targets))];

			rc = sys_pidfd_getfd(s->pidfd, target, 0);
			if (rc >= 0) {
				__atomic_add_fetch(&shm->stats.pidfd_storm_getfds,
						   1, __ATOMIC_RELAXED);
				/* Drop the duplicated fd immediately so
				 * the storm doesn't accumulate fd debt. */
				close(rc);
			} else {
				__atomic_add_fetch(&shm->stats.pidfd_storm_failed,
						   1, __ATOMIC_RELAXED);
				/* EPERM (Yama / ptrace policy), EBADF
				 * (target_fd not present in target),
				 * ENOSYS (old kernel) all expected; fall
				 * through to next iteration. */
			}
		}

		if (budget_elapsed_ns(&start, BUDGET_NS))
			break;
	}
}

/*
 * Teardown phase: SIGKILL every spawned child via its pidfd, falling
 * back to kill(2) by pid where pidfd_open failed at spawn.  A second
 * pass waitpid()s each pid to reap and closes each pidfd, so no
 * zombie or leaked pidfd escapes the op.  Runs outside the timed
 * budget — correctness, not speed, matters here.
 */
static void pidfd_storm_iter_reap(struct pidfd_slot *slots,
				  unsigned int active)
{
	unsigned int i;

	for (i = 0; i < active; i++) {
		if (slots[i].pidfd >= 0)
			(void) sys_pidfd_send_signal(slots[i].pidfd, SIGKILL, NULL, 0);
		else
			(void) kill(slots[i].pid, SIGKILL);
	}

	for (i = 0; i < active; i++) {
		int status;

		(void) waitpid_eintr(slots[i].pid, &status, 0);
		if (slots[i].pidfd >= 0)
			close(slots[i].pidfd);
	}
}

bool pidfd_storm(struct childdata *child)
{
	struct pidfd_slot slots[NR_CHILDREN];
	unsigned int active;

	(void) child;

	__atomic_add_fetch(&shm->stats.pidfd_storm_runs, 1, __ATOMIC_RELAXED);

	active = pidfd_storm_iter_spawn(slots, NR_CHILDREN);
	if (active == 0)
		return true;

	pidfd_storm_iter_drive(slots, active, JITTER_RANGE(MAX_ITERATIONS));
	pidfd_storm_iter_reap(slots, active);

	return true;
}
