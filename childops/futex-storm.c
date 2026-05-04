/*
 * futex-storm: mass futex contention childop
 *
 * Forks a small herd of inner workers that all race a curated mix of
 * FUTEX_WAIT, FUTEX_WAKE, FUTEX_REQUEUE, and FUTEX_CMP_REQUEUE against
 * a shared page of futex words.  All workers release simultaneously
 * from a process-shared pthread barrier so the kernel sees a thundering-
 * herd fan-in on a small set of hashed futex buckets.
 *
 * The point is to exercise the futex waitqueue / hashbucket locking:
 *   - requeue races against concurrent wakers,
 *   - missed wakeups when the value flips between cmp-and-enqueue,
 *   - bucket lock contention when many addresses collide,
 *   - waitqueue ordering bugs under simultaneous wake_q drains.
 *
 * Patterned after barrier-racer.c — same mmap-anonymous-shared barrier
 * trick to fan workers out across processes — but the workers loop for
 * a bounded wall-clock window instead of issuing one op, so the kernel
 * sees sustained per-bucket pressure rather than a single coordinated
 * burst.
 *
 * Self-bounding: every FUTEX_WAIT carries a sub-millisecond timespec,
 * every loop iteration checks the shared "done" flag, and the parent
 * issues a broadcast wake on all words at shutdown to dislodge any
 * worker that re-entered FUTEX_WAIT just before the flag flip.  Any
 * survivor past the grace window is SIGKILLed.
 */

#include <errno.h>
#include <limits.h>
#include <linux/futex.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "childops-util.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

#define NR_FUTEX_WORDS	8	/* small enough that workers collide hard */
#define MAX_WORKERS	6
#define STORM_BUDGET_NS	200000000L	/* 200 ms wall-clock per round */

struct futex_storm_shared {
	pthread_barrier_t barrier;

	/*
	 * Pool of futex words workers race against.  Kept small so that
	 * with MAX_WORKERS in-flight the same word is hammered by multiple
	 * actors per iteration, maximizing hashbucket contention.
	 */
	int futexes[NR_FUTEX_WORDS];

	/* Set by the parent when the storm budget elapses; workers poll
	 * this between ops and exit on the next iteration. */
	int done;

	/* Cumulative iteration counter, updated by every worker after
	 * each futex syscall.  Drained into shm->stats.futex_storm_iters
	 * by the parent before teardown. */
	unsigned long iters;
};

/* ------------------------------------------------------------------ */
/* Worker                                                              */
/* ------------------------------------------------------------------ */

static void do_wait(struct futex_storm_shared *s, int idx)
{
	struct timespec ts;
	int val;

	/*
	 * Sub-millisecond timeout: if no waker shows up the worker rejoins
	 * the loop quickly and the storm keeps churning.  100us-1ms range
	 * keeps the per-iteration latency below the storm budget so a
	 * stuck waiter can't gate worker shutdown.
	 */
	ts.tv_sec  = 0;
	ts.tv_nsec = 100000 + (rand() % 900000);

	val = __atomic_load_n(&s->futexes[idx], __ATOMIC_RELAXED);
	syscall(__NR_futex, &s->futexes[idx], FUTEX_WAIT, val, &ts, NULL, 0);
}

static void do_wake(struct futex_storm_shared *s, int idx)
{
	int nwake = 1 + (rand() % 4);

	/*
	 * Bump the value first so any racing FUTEX_WAIT loaded a stale
	 * comparand and either bails with -EWOULDBLOCK or, if it already
	 * enqueued, gets popped by the WAKE below.  Either outcome
	 * exercises the value-vs-enqueue ordering.
	 */
	__atomic_add_fetch(&s->futexes[idx], 1, __ATOMIC_RELAXED);
	syscall(__NR_futex, &s->futexes[idx], (int)RAND_NEGATIVE_OR(FUTEX_WAKE), nwake, NULL, NULL, 0);
}

static void do_requeue(struct futex_storm_shared *s, int idx1, int idx2)
{
	/*
	 * FUTEX_REQUEUE: wake one waiter on uaddr1, requeue the rest to
	 * uaddr2.  No value check — pairs with the WAKE path's value
	 * bump to create cmp-vs-requeue races.
	 */
	syscall(__NR_futex, &s->futexes[idx1], FUTEX_REQUEUE,
		1, INT_MAX, &s->futexes[idx2], 0);
}

static void do_cmp_requeue(struct futex_storm_shared *s, int idx1, int idx2)
{
	int val = __atomic_load_n(&s->futexes[idx1], __ATOMIC_RELAXED);

	/*
	 * FUTEX_CMP_REQUEUE: same as REQUEUE but bails with -EAGAIN if
	 * *uaddr1 != val.  The val we sample here is racy by design —
	 * concurrent wakers may flip it between sample and syscall, and
	 * that's exactly the path we want to exercise.
	 */
	syscall(__NR_futex, &s->futexes[idx1], FUTEX_CMP_REQUEUE,
		1, INT_MAX, &s->futexes[idx2], val);
}

static void inner_worker(struct futex_storm_shared *s)
{
	/*
	 * Each fork() inherits the parent's libc PRNG state, so without a
	 * reseed every worker would walk the same op/idx sequence and the
	 * "race" would degenerate into N copies of the same syscall.
	 *
	 * Seed BEFORE pthread_barrier_wait so the cost of seeding is not
	 * folded into the post-release thundering herd, and mix three
	 * sources because no single one is sufficient on its own:
	 *   - getpid() aliases across rapidly-forked siblings (PIDs
	 *     differ by 1..N in this loop),
	 *   - CLOCK_MONOTONIC tv_nsec collides when workers are forked
	 *     within the same scheduler tick,
	 *   - one byte from getrandom() is guaranteed to differ per
	 *     worker.  A stack address (&now) would NOT help here:
	 *     fork() preserves the child VM layout, so &now is the same
	 *     virtual address in every worker.  getrandom() is the
	 *     cheapest source we have that actually diverges per fork.
	 *
	 * If getrandom() fails, extra stays 0 and we fall back to the
	 * (pid ^ tv_nsec) seed — degraded, but no worse than before.
	 */
	struct timespec now;
	unsigned char extra = 0;

	clock_gettime(CLOCK_MONOTONIC, &now);
	(void)syscall(__NR_getrandom, &extra, sizeof(extra), 0);
	srand((unsigned int)(getpid() ^ now.tv_nsec ^
			     ((unsigned int)extra << 16)));

	pthread_barrier_wait(&s->barrier);

	while (!__atomic_load_n(&s->done, __ATOMIC_RELAXED)) {
		unsigned int op = rand() % 4;
		int idx1 = rand() % NR_FUTEX_WORDS;
		int idx2 = rand() % NR_FUTEX_WORDS;

		switch (op) {
		case 0: do_wait(s, idx1);              break;
		case 1: do_wake(s, idx1);              break;
		case 2: do_requeue(s, idx1, idx2);     break;
		case 3: do_cmp_requeue(s, idx1, idx2); break;
		}

		__atomic_add_fetch(&s->iters, 1, __ATOMIC_RELAXED);
	}

	_exit(0);
}

/* ------------------------------------------------------------------ */
/* Parent: fork workers, time-box the storm, broadcast-wake, reap     */
/* ------------------------------------------------------------------ */

static void broadcast_wake(struct futex_storm_shared *s)
{
	int i;

	/* One last value bump + wake on every word so any worker that
	 * entered FUTEX_WAIT after the done flip still gets dislodged
	 * before its timeout would have expired. */
	for (i = 0; i < NR_FUTEX_WORDS; i++) {
		__atomic_add_fetch(&s->futexes[i], 1, __ATOMIC_RELAXED);
		syscall(__NR_futex, &s->futexes[i], FUTEX_WAKE,
			INT_MAX, NULL, NULL, 0);
	}
}

bool futex_storm(struct childdata *child)
{
	struct futex_storm_shared *s;
	pthread_barrierattr_t attr;
	struct timespec budget;
	unsigned int nworkers;
	pid_t pids[MAX_WORKERS];
	int i, alive, status;

	(void)child;

	__atomic_add_fetch(&shm->stats.futex_storm_runs, 1, __ATOMIC_RELAXED);

	nworkers = 3 + (rand() % (MAX_WORKERS - 2));	/* 3..MAX_WORKERS */

	s = mmap(NULL, sizeof(*s), PROT_READ | PROT_WRITE,
		 MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (s == MAP_FAILED)
		return true;

	memset(s->futexes, 0, sizeof(s->futexes));
	s->done  = 0;
	s->iters = 0;

	if (pthread_barrierattr_init(&attr) != 0)
		goto out_unmap;

	if (pthread_barrierattr_setpshared(&attr, PTHREAD_PROCESS_SHARED) != 0) {
		pthread_barrierattr_destroy(&attr);
		goto out_unmap;
	}

	if (pthread_barrier_init(&s->barrier, &attr, nworkers) != 0) {
		pthread_barrierattr_destroy(&attr);
		goto out_unmap;
	}
	pthread_barrierattr_destroy(&attr);

	alive = 0;
	for (i = 0; i < (int)nworkers; i++) {
		pid_t pid = fork();

		if (pid < 0)
			break;
		if (pid == 0) {
			inner_worker(s);
			_exit(0);	/* unreachable */
		}
		pids[alive++] = pid;
	}

	/*
	 * Same fork-shortfall handling as barrier_racer: if we couldn't
	 * fill the barrier slots, surviving workers will park forever on
	 * pthread_barrier_wait().  SIGKILL them and skip the storm.
	 */
	if (alive < (int)nworkers) {
		for (i = 0; i < alive; i++)
			kill(pids[i], SIGKILL);
		for (i = 0; i < alive; i++)
			waitpid_eintr(pids[i], &status, 0);
		goto out_barrier;
	}

	budget.tv_sec  = 0;
	budget.tv_nsec = STORM_BUDGET_NS;
	nanosleep(&budget, NULL);

	__atomic_store_n(&s->done, 1, __ATOMIC_RELAXED);
	broadcast_wake(s);

	/*
	 * Workers should exit promptly now: the done flag is set and any
	 * in-flight FUTEX_WAIT either timed out (sub-ms) or just got woken
	 * by the broadcast.  Give a brief grace window, then SIGKILL the
	 * stragglers so a hung worker doesn't gate the whole storm.
	 */
	for (i = 0; i < alive; i++) {
		pid_t r = 0;
		int spin;

		for (spin = 0; spin < 50; spin++) {
			r = waitpid_eintr(pids[i], &status, WNOHANG);
			if (r == pids[i] || r < 0)
				break;
			budget.tv_sec  = 0;
			budget.tv_nsec = 1000000;	/* 1 ms */
			nanosleep(&budget, NULL);
		}
		if (r == 0) {
			kill(pids[i], SIGKILL);
			waitpid_eintr(pids[i], &status, 0);
			continue;
		}
		if (r == pids[i] && WIFSIGNALED(status))
			__atomic_add_fetch(&shm->stats.futex_storm_inner_crashed,
					   1, __ATOMIC_RELAXED);
	}

	__atomic_add_fetch(&shm->stats.futex_storm_iters,
			   __atomic_load_n(&s->iters, __ATOMIC_RELAXED),
			   __ATOMIC_RELAXED);

out_barrier:
	pthread_barrier_destroy(&s->barrier);
out_unmap:
	munmap(s, sizeof(*s));
	return true;
}
