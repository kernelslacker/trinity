/*
 * signal_storm - mass kill() / sigqueue() to siblings.
 *
 * Trinity's normal random_syscall path will occasionally emit a kill(),
 * tgkill(), or rt_sigqueueinfo() with a random pid arg, but the rate is
 * low and the targeted pid is rarely a live trinity sibling.  As a
 * result, the kernel's signal-delivery and sigqueue-management paths
 * (signal_pending wakeups, shared_pending list maintenance, sigqueue
 * slab refills, RLIMIT_SIGPENDING accounting) get only thin coverage.
 *
 * signal_storm closes that gap.  Each invocation snapshots a small set
 * of currently-live sibling pids out of pids[], then fires a tight
 * burst of kill(2) and sigqueue(2) calls aimed at them.  Signals are
 * picked uniformly from a curated catalog: harmless ones the targets
 * can ignore (SIGUSR1, SIGUSR2, SIGCONT, SIGCHLD), one rarely-issued
 * fatal (SIGTERM, weighted to ~1/16 to avoid mass sibling kills), and
 * a sweep of real-time signals so the kernel's RT queue path actually
 * gets exercised.  sigqueue() pairs each RT delivery with a random
 * sigval payload so the kernel's siginfo plumbing sees varying data.
 *
 * Hard exclusions: SIGKILL, SIGSTOP, SIGABRT.  Killing siblings
 * defeats the fuzzer (the parent will respawn but we burn cycles), and
 * SIGSTOP leaves a target frozen indefinitely with no path back here
 * to deliver SIGCONT in time.  SIGABRT triggers the trinity panic
 * handler.
 *
 * Iteration cap mirrors barrier_racer's bounded-loop discipline: a
 * fixed small upper bound keeps any single op invocation short so the
 * SIGALRM-based stall detector in child.c can still fire if the kernel
 * wedges on a delivery path.
 */

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "child.h"
#include "pids.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * Non-RT catalog: signals safe to mass-deliver.  SIGTERM is included
 * but gated behind a 1-in-N draw so we do not routinely murder the
 * sibling pool.  SIGCHLD is harmless to most processes (default
 * action is ignore) but exercises the dequeue/handler-lookup path.
 */
static const int safe_signals[] = {
	SIGUSR1,
	SIGUSR2,
	SIGCONT,
	SIGCHLD,
};

#define SIGTERM_ONE_IN		16

/* Cap iterations to bound time-in-op; SIGALRM stall detection still
 * needs to be able to fire on hung delivery paths. */
#define MAX_TARGETS		4
#define MAX_ITERATIONS		32

static int pick_signal(void)
{
	/* ~25%: real-time signal.  rt_sigqueueinfo / dequeue paths are
	 * meaningfully different from the legacy signal queue, so bias
	 * toward them here. */
	if (rand() % 4 == 0) {
		int span = SIGRTMAX - SIGRTMIN + 1;

		if (span <= 0)
			return SIGUSR1;
		return SIGRTMIN + (rand() % span);
	}

	if (ONE_IN(SIGTERM_ONE_IN))
		return SIGTERM;

	return safe_signals[rand() % ARRAY_SIZE(safe_signals)];
}

bool signal_storm(struct childdata *child)
{
	pid_t targets[MAX_TARGETS];
	pid_t self = getpid();
	pid_t ppid = getppid();
	unsigned int ntargets = 0;
	unsigned int i, iters;

	(void)child;

	__atomic_add_fetch(&shm->stats.signal_storm_runs, 1, __ATOMIC_RELAXED);

	/*
	 * Snapshot up to MAX_TARGETS live sibling pids.  Random walk
	 * from a random starting offset so the same children do not get
	 * preferentially hammered every invocation.
	 */
	if (max_children > 0) {
		unsigned int start = rand() % max_children;

		for (i = 0; i < max_children && ntargets < MAX_TARGETS; i++) {
			unsigned int slot = (start + i) % max_children;
			pid_t pid = __atomic_load_n(&pids[slot], __ATOMIC_RELAXED);

			if (pid == EMPTY_PIDSLOT)
				continue;
			if (pid == self || pid == ppid)
				continue;
			if (!pid_is_valid(pid))
				continue;
			targets[ntargets++] = pid;
		}
	}

	if (ntargets == 0) {
		__atomic_add_fetch(&shm->stats.signal_storm_no_targets,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	iters = 1 + (rand() % MAX_ITERATIONS);
	for (i = 0; i < iters; i++) {
		pid_t pid = targets[rand() % ntargets];
		int sig = pick_signal();

		if (RAND_BOOL()) {
			(void)kill(pid, sig);
			__atomic_add_fetch(&shm->stats.signal_storm_kill,
					   1, __ATOMIC_RELAXED);
		} else {
			union sigval sv;

			sv.sival_int = (int)rand32();
			(void)sigqueue(pid, sig, sv);
			__atomic_add_fetch(&shm->stats.signal_storm_sigqueue,
					   1, __ATOMIC_RELAXED);
		}
	}

	return true;
}
