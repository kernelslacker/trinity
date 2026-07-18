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
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "syscall-gate.h"
#include "pids.h"
#include "childops-util.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"

#define NR_FUTEX_WORDS	8	/* small enough that workers collide hard */
#define MAX_WORKERS	6
#define STORM_BUDGET_NS	200000000L	/* 200 ms wall-clock per round */
#define STORM_SLICE_NS	5000000L	/* 5 ms per shutdown-poll slice */

/*
 * Per-invocation op-selection mode.  All workers in a single futex_storm()
 * call share the mode picked by the parent before fork(), so the storm as
 * a whole presents one coherent waiter/wake population to the kernel
 * rather than every worker independently sampling a uniform distribution.
 */
enum storm_mode {
	STORM_WAVE_NORMAL,	/* original: uniform 4-way op pick, free idx */
	STORM_SAME_FUTEX_BURST,	/* all actors stack on one word, mostly WAIT */
	STORM_WAKE_BEFORE_WAIT,	/* WAKE-biased; hit no-waiter / drain paths */
	STORM_REQUEUE_HEAVY,	/* concentrate REQUEUE/CMP_REQUEUE on one pair */
	STORM_MODE_MAX,
};

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
	 * each futex syscall.  Drained into shm->stats.futex_storm.iters
	 * by the parent before teardown. */
	unsigned long iters;

	/* Op-selection mode and the two pinned indices used by the
	 * SAME_FUTEX_BURST and REQUEUE_HEAVY modes.  Set once by the
	 * parent before fork() and read-only in the workers. */
	unsigned int mode;
	int pinned1;
	int pinned2;
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
	ts.tv_nsec = 100000 + rnd_modulo_u32(900000);

	val = __atomic_load_n(&s->futexes[idx], __ATOMIC_RELAXED);
	trinity_raw_syscall(__NR_futex, &s->futexes[idx], FUTEX_WAIT, val, &ts, NULL, 0);
}

static void do_wake(struct futex_storm_shared *s, int idx)
{
	int nwake = 1 + (int)rnd_modulo_u32(4);

	/*
	 * Bump the value first so any racing FUTEX_WAIT loaded a stale
	 * comparand and either bails with -EWOULDBLOCK or, if it already
	 * enqueued, gets popped by the WAKE below.  Either outcome
	 * exercises the value-vs-enqueue ordering.
	 */
	__atomic_add_fetch(&s->futexes[idx], 1, __ATOMIC_RELAXED);
	trinity_raw_syscall(__NR_futex, &s->futexes[idx], (int)RAND_NEGATIVE_OR(FUTEX_WAKE), nwake, NULL, NULL, 0);
}

static void do_requeue(struct futex_storm_shared *s, int idx1, int idx2)
{
	/*
	 * FUTEX_REQUEUE: wake one waiter on uaddr1, requeue the rest to
	 * uaddr2.  No value check — pairs with the WAKE path's value
	 * bump to create cmp-vs-requeue races.
	 */
	trinity_raw_syscall(__NR_futex, &s->futexes[idx1], FUTEX_REQUEUE,
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
	trinity_raw_syscall(__NR_futex, &s->futexes[idx1], FUTEX_CMP_REQUEUE,
		1, INT_MAX, &s->futexes[idx2], val);
}

static void inner_worker(struct futex_storm_shared *s)
{
	/*
	 * Belt to the shm->exit_reason brace below: PDEATHSIG covers the
	 * orchestrator-died-for-a-non-shutdown-reason path (watchdog SIGKILL,
	 * a fault) where exit_reason stays STILL_RUNNING and the worker would
	 * otherwise burn the host on futex ops orphaned under PID 1.  The
	 * exit_reason check in the loop below still handles Ctrl-C and any
	 * other shm-propagated shutdown where the parent stays alive long
	 * enough to drive a clean drain.  Armed BEFORE pthread_barrier_wait
	 * so a parent that dies while workers are still parked on the barrier
	 * does not leave them blocked indefinitely.
	 *
	 * getppid()==1 re-check covers the race where the orchestrator died
	 * between fork() returning here and the prctl arming -- PDEATHSIG
	 * would not fire and the reparent-to-init has already happened.
	 */
	(void)prctl(PR_SET_PDEATHSIG, SIGKILL);
	if (getppid() == 1)
		_exit(0);

	pthread_barrier_wait(&s->barrier);

	/*
	 * Second predicate handles orphaned-worker shutdown: if the parent
	 * orchestrator is killed mid-budget before it sets s->done, the
	 * worker would otherwise loop forever (s->done stuck at 0).  Match
	 * the main child dispatch loop's exit gate (child.c: while
	 * exit_reason == STILL_RUNNING) so a SIGINT propagated via
	 * shm->exit_reason drains the herd within one iteration.
	 */
	while (!__atomic_load_n(&s->done, __ATOMIC_RELAXED) &&
	       __atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) == STILL_RUNNING) {
		unsigned int r = rnd_u32();
		unsigned int op;
		int idx1, idx2;

		switch (s->mode) {
		case STORM_SAME_FUTEX_BURST:
			/*
			 * Every worker pins to one shared word and mostly
			 * sleeps on it, so the hashed bucket grows to a
			 * deep waiter chain before the occasional WAKE
			 * drains it — exercises the bulk wake_q walk and
			 * the per-bucket plist ordering, which the uniform
			 * 4-way mix never builds up enough waiters to hit.
			 */
			idx1 = idx2 = s->pinned1;
			op = ((r % 10) < 7) ? 0 : 1;
			break;
		case STORM_WAKE_BEFORE_WAIT:
			/*
			 * WAKE-heavy with free indices, so most wakes land
			 * on a bucket with zero waiters (no-op fast path)
			 * or on a waiter that hasn't finished enqueuing yet
			 * (the value-bump in do_wake forces -EWOULDBLOCK).
			 * Both paths are skipped by the alternation-style
			 * wait-then-wake distribution.
			 */
			idx1 = (int)((r >> 4) % NR_FUTEX_WORDS);
			idx2 = (int)((r >> 8) % NR_FUTEX_WORDS);
			op = ((r % 10) < 7) ? 1 : 0;
			break;
		case STORM_REQUEUE_HEAVY:
			/*
			 * Concentrate REQUEUE / CMP_REQUEUE traffic on a
			 * single source/destination pair so the requeue
			 * path runs back-to-back against the same two
			 * buckets.  A handful of WAITs keep the source
			 * populated; one WAKE in ten clears the head so
			 * the next requeue isn't a no-op.
			 */
			idx1 = s->pinned1;
			idx2 = s->pinned2;
			if ((r % 10) < 6)
				op = 2 + (r & 1);
			else if ((r % 10) < 9)
				op = 0;
			else
				op = 1;
			break;
		case STORM_WAVE_NORMAL:
		default:
			op   = r % 4;
			idx1 = (int)((r >> 4) % NR_FUTEX_WORDS);
			idx2 = (int)((r >> 8) % NR_FUTEX_WORDS);
			break;
		}

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

/*
 * Per-invocation state shared across the futex_storm_iter_* helpers.
 * Lives on the orchestrator's stack and is fresh per invocation.  Lifted
 * only the fields read across helper boundaries; per-phase scratch
 * (barrier attr, timespec budgets, fork-loop status) stays local to its
 * phase.
 *
 * Worker fork inheritance: s is the parent-side pointer to the
 * MAP_SHARED region.  The spawn phase passes it into inner_worker() so
 * each forked child sees the same mapping the setup phase created --
 * do not relocate the mmap inside the fork loop.
 */
struct futex_storm_iter_ctx {
	struct futex_storm_shared	*s;		/* mapped region, NULL until setup */
	pid_t				worker_pids[MAX_WORKERS];
	unsigned int			nworkers;	/* target worker count */
	int				alive;		/* # successfully forked */
	bool				barrier_up;	/* pthread_barrier was initialised */
};

static void broadcast_wake(struct futex_storm_shared *s)
{
	int i;

	/* One last value bump + wake on every word so any worker that
	 * entered FUTEX_WAIT after the done flip still gets dislodged
	 * before its timeout would have expired. */
	for (i = 0; i < NR_FUTEX_WORDS; i++) {
		__atomic_add_fetch(&s->futexes[i], 1, __ATOMIC_RELAXED);
		trinity_raw_syscall(__NR_futex, &s->futexes[i], FUTEX_WAKE,
			INT_MAX, NULL, NULL, 0);
	}
}

/*
 * Phase 1: stand up the MAP_SHARED region every worker reads/writes
 * against and the process-shared barrier the parent uses to release
 * them simultaneously.  The region is mmap'd here so the resulting
 * pointer can be inherited by the fork burst that follows -- moving
 * the mmap after the fork would give each worker a private mapping
 * and break every shared-state access.  nworkers is rolled before
 * the barrier_init so the barrier waits on exactly the right count.
 *
 * Any internal setup failure unmaps the region (if it had been
 * mapped) and destroys the barrier attr before return, so the caller
 * can just bail without further teardown.  barrier_up is flipped
 * only after a successful pthread_barrier_init so the orchestrator's
 * teardown path can tell whether the barrier needs destroying.
 * Returns 0 on success or -1 if the iteration should bail.
 */
static int futex_storm_iter_setup_region(struct futex_storm_iter_ctx *ctx)
{
	pthread_barrierattr_t attr;

	ctx->nworkers = 3 + rnd_modulo_u32(MAX_WORKERS - 2);	/* 3..MAX_WORKERS */

	ctx->s = mmap(NULL, sizeof(*ctx->s), PROT_READ | PROT_WRITE,
		      MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (ctx->s == MAP_FAILED) {
		ctx->s = NULL;
		return -1;
	}

	memset(ctx->s->futexes, 0, sizeof(ctx->s->futexes));
	ctx->s->done  = 0;
	ctx->s->iters = 0;

	/*
	 * Pick the per-invocation op-selection mode and the two pinned
	 * indices the bucket-burst / requeue-heavy modes use.  The two
	 * indices must differ so REQUEUE_HEAVY actually drives traffic
	 * across two buckets rather than degenerating into a self-requeue.
	 */
	ctx->s->mode    = rnd_modulo_u32(STORM_MODE_MAX);
	ctx->s->pinned1 = (int)rnd_modulo_u32(NR_FUTEX_WORDS);
	ctx->s->pinned2 = (int)rnd_modulo_u32(NR_FUTEX_WORDS);
	if (ctx->s->pinned2 == ctx->s->pinned1)
		ctx->s->pinned2 = (ctx->s->pinned1 + 1) % NR_FUTEX_WORDS;

	if (pthread_barrierattr_init(&attr) != 0)
		goto fail_unmap;

	if (pthread_barrierattr_setpshared(&attr, PTHREAD_PROCESS_SHARED) != 0) {
		pthread_barrierattr_destroy(&attr);
		goto fail_unmap;
	}

	if (pthread_barrier_init(&ctx->s->barrier, &attr, ctx->nworkers) != 0) {
		pthread_barrierattr_destroy(&attr);
		goto fail_unmap;
	}
	pthread_barrierattr_destroy(&attr);
	ctx->barrier_up = true;
	return 0;

fail_unmap:
	munmap(ctx->s, sizeof(*ctx->s));
	ctx->s = NULL;
	return -1;
}

/*
 * Phase 2: fan out the worker fleet.  Each forked child enters
 * inner_worker against the parent's ctx->s mapping -- the
 * MAP_SHARED region must already be standing (setup_region runs
 * first) so the inheritance is the post-fork shared mapping rather
 * than per-child private copies.  Successful child pids are pushed
 * into ctx->worker_pids and ctx->alive tracks the count.
 *
 * Shortfall handling: if fewer than nworkers forks landed, every
 * surviving worker would park forever on pthread_barrier_wait
 * (the barrier was sized for the full count).  SIGKILL the partial
 * herd and waitpid each one synchronously -- no grace window since
 * a worker stuck on the barrier won't notice the done flag.
 * ctx->alive is zeroed so the orchestrator's teardown skips the
 * reap loop entirely.  Returns 0 if every fork landed or -1 on
 * shortfall (after the partial herd has been cleaned up).
 */
static int futex_storm_iter_spawn_workers(struct futex_storm_iter_ctx *ctx)
{
	int i, status;

	for (i = 0; i < (int)ctx->nworkers; i++) {
		pid_t pid = fork();

		if (pid < 0)
			break;
		if (pid == 0) {
			inner_worker(ctx->s);
			_exit(0);	/* unreachable */
		}
		ctx->worker_pids[ctx->alive++] = pid;
	}

	if (ctx->alive < (int)ctx->nworkers) {
		for (i = 0; i < ctx->alive; i++)
			kill(ctx->worker_pids[i], SIGKILL);
		for (i = 0; i < ctx->alive; i++)
			waitpid_eintr(ctx->worker_pids[i], &status, 0);
		ctx->alive = 0;
		return -1;
	}
	return 0;
}

/*
 * Phase 3: drive the storm.  Sleep for the wall-clock budget while
 * workers churn, then flip the done flag and broadcast a wake on
 * every futex word so any worker that re-entered FUTEX_WAIT just
 * before the flag flip gets dislodged before its sub-ms timeout
 * would have expired.  This is the only phase that can take
 * STORM_BUDGET_NS of wall-clock; setup and teardown stay outside
 * the timed window.
 */
static void futex_storm_iter_drive_burst(struct futex_storm_iter_ctx *ctx)
{
	struct timespec slice;
	long elapsed_ns;

	/*
	 * Slice the budget so a shutdown signal (Ctrl-C -> exit_reason flip)
	 * is honoured within ~one slice instead of dragging on for the full
	 * STORM_BUDGET_NS.  Each slice nanosleeps for STORM_SLICE_NS then
	 * polls shm->exit_reason; on shutdown we flip done + broadcast a wake
	 * and return early so the orchestrator proceeds straight to reap.
	 * The no-shutdown path still consumes the full budget, preserving
	 * the storm's intended wall-clock pressure.
	 */
	slice.tv_sec = 0;
	for (elapsed_ns = 0; elapsed_ns < STORM_BUDGET_NS; elapsed_ns += STORM_SLICE_NS) {
		long remaining = STORM_BUDGET_NS - elapsed_ns;

		slice.tv_nsec = (remaining < STORM_SLICE_NS) ? remaining : STORM_SLICE_NS;
		nanosleep(&slice, NULL);

		if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) != STILL_RUNNING)
			break;
	}

	__atomic_store_n(&ctx->s->done, 1, __ATOMIC_RELAXED);
	broadcast_wake(ctx->s);
}

/*
 * Phase 4: reap the worker burst.  Workers should exit promptly now:
 * the done flag is set and any in-flight FUTEX_WAIT either timed out
 * (sub-ms) or just got woken by the broadcast.  Give each a brief
 * grace window, then SIGKILL the stragglers so a hung worker doesn't
 * gate the whole storm.  Drain the per-invocation iters counter into
 * shm->stats so the storm's actual progress is visible in dump_stats.
 *
 * Workers that exited via signal (WIFSIGNALED) bump futex_storm_inner_crashed
 * -- the inner_worker path has no legitimate fatal-signal exit, so any
 * crash here is a real kernel-vs-worker fault worth surfacing.
 */
static void futex_storm_iter_reap(struct futex_storm_iter_ctx *ctx)
{
	struct timespec grace;
	int i, status;

	for (i = 0; i < ctx->alive; i++) {
		pid_t r = 0;
		int spin;

		for (spin = 0; spin < 50; spin++) {
			r = waitpid_eintr(ctx->worker_pids[i], &status, WNOHANG);
			if (r == ctx->worker_pids[i] || r < 0)
				break;
			grace.tv_sec  = 0;
			grace.tv_nsec = 1000000;	/* 1 ms */
			nanosleep(&grace, NULL);
		}
		if (r == 0) {
			kill(ctx->worker_pids[i], SIGKILL);
			waitpid_eintr(ctx->worker_pids[i], &status, 0);
			continue;
		}
		if (r == ctx->worker_pids[i] && WIFSIGNALED(status))
			__atomic_add_fetch(&shm->stats.futex_storm.inner_crashed,
					   1, __ATOMIC_RELAXED);
	}
	ctx->alive = 0;

	__atomic_add_fetch(&shm->stats.futex_storm.iters,
			   __atomic_load_n(&ctx->s->iters, __ATOMIC_RELAXED),
			   __ATOMIC_RELAXED);
}

/*
 * Phase 5: release everything the prior phases stood up.  Gated on the
 * per-resource _up / non-NULL flags so a partial setup (mmap ok but
 * barrier_init failed, etc.) tears down only what actually came up.
 * Called unconditionally on the success path and on the spawn-shortfall
 * path; setup_region rolls back its own mmap on failure so the early
 * return there does not need to route through here.
 */
static void futex_storm_iter_teardown(struct futex_storm_iter_ctx *ctx)
{
	if (ctx->barrier_up)
		pthread_barrier_destroy(&ctx->s->barrier);
	if (ctx->s)
		munmap(ctx->s, sizeof(*ctx->s));
}

bool futex_storm(struct childdata *child)
{
	struct futex_storm_iter_ctx ctx = { .s = NULL };

	__atomic_add_fetch(&shm->stats.futex_storm.runs, 1, __ATOMIC_RELAXED);

	if (futex_storm_iter_setup_region(&ctx) != 0)
		return true;

	if (futex_storm_iter_spawn_workers(&ctx) != 0)
		goto out;

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}
	futex_storm_iter_drive_burst(&ctx);
	futex_storm_iter_reap(&ctx);

out:
	futex_storm_iter_teardown(&ctx);
	return true;
}
