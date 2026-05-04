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

/*
 * Per-invocation burst ordering.  Baseline MIXED draws (target, mode,
 * sig) independently each iteration; the other orderings cluster
 * deliveries to push specific per-task pending-queue shapes the
 * high-entropy uniform draw can't reach.
 *
 *   SAME_TARGET_BURST: K (2-8) signals at one target, then move on
 *     -> grows __sigqueue / shared_pending depth on a single task.
 *   MODE_GROUPED: all-kill burst then all-sigqueue burst per target
 *     -> exercises kill -> sigqueue transition on the pending queue.
 *   CATALOG_RESTRICTED: whole burst is RT-only or standard-only
 *     -> RT-only hits the queued-RT siginfo path; standard-only hits
 *        the bitmap-collapse path where back-to-back identical
 *        deliveries coalesce instead of queueing one entry each.
 */
enum storm_order {
	ORDER_MIXED,
	ORDER_SAME_TARGET_BURST,
	ORDER_MODE_GROUPED,
	ORDER_CATALOG_RESTRICTED,
	NR_STORM_ORDERS,
};

enum catalog_mode {
	CATALOG_ANY,
	CATALOG_RT_ONLY,
	CATALOG_STD_ONLY,
};

static int pick_signal_in(enum catalog_mode mode)
{
	/* CATALOG_ANY: ~25% RT bias, matching the original mix.
	 * rt_sigqueueinfo / dequeue paths are meaningfully different
	 * from the legacy signal queue. */
	if (mode == CATALOG_RT_ONLY ||
	    (mode == CATALOG_ANY && rand() % 4 == 0)) {
		int span = SIGRTMAX - SIGRTMIN + 1;

		if (span <= 0)
			return SIGUSR1;
		return SIGRTMIN + (rand() % span);
	}
	if (ONE_IN(SIGTERM_ONE_IN))
		return SIGTERM;
	return safe_signals[rand() % ARRAY_SIZE(safe_signals)];
}

static void emit_signal(pid_t pid, int sig, bool use_kill)
{
	if (use_kill) {
		(void)kill(pid, (int)RAND_NEGATIVE_OR(sig));
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

/*
 * Reorder snapshotted targets: forward (no-op), reverse, or shuffle.
 * The natural sequential walk follows pids[] slot order which roughly
 * tracks fork order; reversing or shuffling exposes per-CPU run-queue
 * locality bugs that order-dependent wakeup paths can mask when the
 * burst orderings (SAME_TARGET_BURST, MODE_GROUPED) actually walk the
 * target array in sequence rather than picking uniformly.
 */
static void reorder_targets(pid_t *t, unsigned int n)
{
	unsigned int pick = rand() % 3;
	unsigned int i;

	if (pick == 1) {
		for (i = 0; i < n / 2; i++) {
			pid_t tmp = t[i];

			t[i] = t[n - 1 - i];
			t[n - 1 - i] = tmp;
		}
	} else if (pick == 2) {
		for (i = n; i > 1; i--) {
			unsigned int j = (unsigned int)rand() % i;
			pid_t tmp = t[i - 1];

			t[i - 1] = t[j];
			t[j] = tmp;
		}
	}
}

bool signal_storm(struct childdata *child)
{
	pid_t targets[MAX_TARGETS];
	pid_t self = getpid();
	pid_t ppid = getppid();
	unsigned int ntargets = 0;
	unsigned int i, iters;
	enum storm_order order;
	enum catalog_mode catalog;

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
	order = (enum storm_order)((unsigned int)rand() % NR_STORM_ORDERS);
	reorder_targets(targets, ntargets);

	if (order == ORDER_CATALOG_RESTRICTED)
		catalog = RAND_BOOL() ? CATALOG_RT_ONLY : CATALOG_STD_ONLY;
	else
		catalog = CATALOG_ANY;

	switch (order) {
	case ORDER_SAME_TARGET_BURST: {
		unsigned int t = 0;

		i = 0;
		while (i < iters) {
			pid_t pid = targets[t % ntargets];
			unsigned int burst = 2 + (rand() % 7); /* 2..8 */
			unsigned int k;

			for (k = 0; k < burst && i < iters; k++, i++) {
				int sig = pick_signal_in(catalog);

				emit_signal(pid, sig, RAND_BOOL());
			}
			t++;
		}
		break;
	}
	case ORDER_MODE_GROUPED: {
		unsigned int t = 0;

		i = 0;
		while (i < iters) {
			pid_t pid = targets[t % ntargets];
			unsigned int kburst = 1 + (rand() % 4); /* 1..4 */
			unsigned int qburst = 1 + (rand() % 4);
			unsigned int k;

			for (k = 0; k < kburst && i < iters; k++, i++)
				emit_signal(pid, pick_signal_in(catalog),
					    true);
			for (k = 0; k < qburst && i < iters; k++, i++)
				emit_signal(pid, pick_signal_in(catalog),
					    false);
			t++;
		}
		break;
	}
	case ORDER_MIXED:
	case ORDER_CATALOG_RESTRICTED:
	default:
		for (i = 0; i < iters; i++) {
			pid_t pid = targets[rand() % ntargets];
			int sig = pick_signal_in(catalog);

			emit_signal(pid, sig, RAND_BOOL());
		}
		break;
	}

	return true;
}
