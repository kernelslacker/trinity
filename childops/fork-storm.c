/*
 * fork_storm - rapid fork()/exit() bursts to stress the fork/exit hot
 * path and the signal-delivery races on parent reap.
 *
 * Trinity's normal random_syscall path can emit fork(), clone(), and
 * waitpid() in isolation, but the rate is low and the children rarely
 * exit before the next iteration — the kernel sees one stray fork at
 * a time, not the burst pattern that hammers the cache-hot allocators
 * (task_struct slab, mm_struct slab, pid bitmap), the SIGCHLD
 * generation path, and the sigqueue-on-exit -> wait_consider_task ->
 * release_task pipeline.
 *
 * fork_storm closes that gap.  Each invocation runs a small bounded
 * number of rounds; in each round it forks a burst of grandchildren
 * that immediately exit, then drains them all via waitpid(2).  A
 * subset of grandchildren go one level deeper (fork-and-reap a great-
 * grandchild before exiting themselves), so the kernel sees a two-
 * level tree being torn down concurrently.  Recursion is hard-capped
 * at depth 1 to avoid runaway pid/task consumption — the goal is hot-
 * path pressure, not pid exhaustion.
 *
 * Exit-mode mix exercises both reap paths:
 *
 *   - _exit(0):           WIFEXITED branch in wait_consider_task.
 *   - _exit(N), N != 0:   same path, non-zero exit code.
 *   - raise(SIGUSR1) with handler reset to SIG_DFL: WIFSIGNALED branch,
 *     so the parent reaps a signal-killed child and the kernel walks
 *     the death-by-signal accounting (do_notify_parent siginfo build,
 *     SIGCHLD with si_code=CLD_KILLED, signal_struct cputime rollup).
 *
 * Bounding discipline:
 *
 *   - MAX_ROUNDS caps burst rounds per invocation.
 *   - MAX_FORKS  caps grandchildren per round, well under any sane
 *                RLIMIT_NPROC margin so the storm cannot starve the
 *                outer trinity child pool.
 *   - All grandchildren _exit() within microseconds of fork(), so the
 *     reap drain is bounded by exit-handler walk time, not workload.
 *   - Every spawned pid is blocking-waitpid()ed before return; a
 *     partial fork-failure mid-burst still drains what was created.
 *   - alarm(1) is armed by child.c around every non-syscall op, so a
 *     wedged exit path here still trips the SIGALRM stall detector.
 */

#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "child.h"
#include "childops-util.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * Per-round bounds.  Conservative on purpose: the goal is hot-path
 * pressure, not pid exhaustion.  Worst case per invocation is
 * MAX_ROUNDS * MAX_FORKS direct grandchildren plus the depth-1 nested
 * great-grandchildren, well under RLIMIT_NPROC headroom.
 */
#define MAX_ROUNDS	3
#define MAX_FORKS	32

/*
 * 1-in-N probability that a given grandchild forks one great-
 * grandchild before exiting.  Kept low so the bulk of the storm is
 * single-level fork/exit (the cache-hot path); the nested subset
 * provides occasional two-level concurrent teardown coverage.
 */
#define NEST_ONE_IN	4

enum exit_mode {
	EXIT_CLEAN,	/* _exit(0) */
	EXIT_NONZERO,	/* _exit(N), N != 0 */
	EXIT_SIGNAL,	/* raise(SIGUSR1) with SIG_DFL handler */
};

static enum exit_mode pick_exit_mode(void)
{
	unsigned int r = rand() % 8;

	/* ~12.5% signal-kill, ~25% non-zero exit code, rest clean exits.
	 * Keeps WIFEXITED dominant (the common kernel path) while still
	 * routinely reaching the WIFSIGNALED accounting branch. */
	if (r == 0)
		return EXIT_SIGNAL;
	if (r < 3)
		return EXIT_NONZERO;
	return EXIT_CLEAN;
}

static void __attribute__((noreturn)) do_exit_as(enum exit_mode mode)
{
	switch (mode) {
	case EXIT_SIGNAL: {
		struct sigaction sa;

		/* Make sure SIGUSR1 isn't inherited as ignored: we want
		 * raise() to actually kill us so the reaper sees CLD_KILLED. */
		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = SIG_DFL;
		(void)sigaction(SIGUSR1, &sa, NULL);
		raise(SIGUSR1);
		_exit(0);	/* unreachable */
	}
	case EXIT_NONZERO:
		_exit(1 + (rand() % 254));
	case EXIT_CLEAN:
	default:
		_exit(0);
	}
}

/*
 * Great-grandchild: depth-1 nested fork.  Trivially exit so the
 * grandchild's waitpid() returns promptly and the storm keeps moving.
 */
static void __attribute__((noreturn)) great_grandchild(void)
{
	do_exit_as(pick_exit_mode());
}

/*
 * Grandchild path.  Either exits straight away (the common case,
 * exercising the cache-hot single-level fork/exit path) or forks one
 * great-grandchild and reaps it before exiting itself (depth-1 nested
 * teardown, exercises concurrent two-level release_task ordering).
 */
static void __attribute__((noreturn)) grandchild(void)
{
	if (ONE_IN(NEST_ONE_IN)) {
		pid_t pid = fork();
		int status;

		if (pid == 0)
			great_grandchild();

		if (pid > 0) {
			(void)waitpid_eintr(pid, &status, 0);
			__atomic_add_fetch(&shm->stats.fork_storm_nested,
					   1, __ATOMIC_RELAXED);
		}
		/* fork() failure: just exit; nothing to drain. */
	}

	do_exit_as(pick_exit_mode());
}

/*
 * One round: spawn up to MAX_FORKS grandchildren, then drain them all.
 * Returns the number of grandchildren actually reaped so the outer
 * loop can early-out if the kernel is rejecting forks (RLIMIT_NPROC).
 */
static unsigned int run_round(void)
{
	pid_t pids[MAX_FORKS];
	unsigned int nforks;
	unsigned int spawned = 0;
	unsigned int reaped = 0;
	unsigned int i;

	nforks = 1 + (rand() % MAX_FORKS);

	for (i = 0; i < nforks; i++) {
		pid_t pid = fork();

		if (pid == 0)
			grandchild();

		if (pid < 0) {
			/* fork() failed (likely EAGAIN from RLIMIT_NPROC).
			 * Stop spawning; drain what we already have. */
			__atomic_add_fetch(&shm->stats.fork_storm_failed,
					   1, __ATOMIC_RELAXED);
			break;
		}

		pids[spawned++] = pid;
	}

	__atomic_add_fetch(&shm->stats.fork_storm_forks, spawned,
			   __ATOMIC_RELAXED);

	/*
	 * Drain.  Mix WNOHANG sweeps with blocking waitpid() so the
	 * kernel's wait queue gets exercised both ways.  Always finish
	 * with a blocking waitpid() so no zombie escapes this round.
	 */
	for (i = 0; i < spawned; i++) {
		int status;
		pid_t r;

		if (RAND_BOOL()) {
			r = waitpid_eintr(pids[i], &status, WNOHANG);
			if (r == 0)
				r = waitpid_eintr(pids[i], &status, 0);
		} else {
			r = waitpid_eintr(pids[i], &status, 0);
		}

		if (r != pids[i])
			continue;

		reaped++;
		if (WIFSIGNALED(status))
			__atomic_add_fetch(&shm->stats.fork_storm_reaped_signal,
					   1, __ATOMIC_RELAXED);
	}

	return reaped;
}

bool fork_storm(struct childdata *child)
{
	unsigned int rounds;
	unsigned int i;

	(void)child;

	__atomic_add_fetch(&shm->stats.fork_storm_runs, 1, __ATOMIC_RELAXED);

	rounds = 1 + (rand() % MAX_ROUNDS);
	for (i = 0; i < rounds; i++) {
		if (run_round() == 0) {
			/* Whole round produced zero reaped grandchildren —
			 * fork is failing.  Bail rather than spin. */
			break;
		}
	}

	return true;
}
