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
#include <sys/types.h>
#include <unistd.h>

#include "child.h"
#include "pids.h"
#include "random.h"
#include "rnd.h"
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
	    (mode == CATALOG_ANY && rnd_modulo_u32(4) == 0)) {
		int span = SIGRTMAX - SIGRTMIN + 1;

		if (span <= 0)
			return SIGUSR1;
		return SIGRTMIN + rnd_modulo_u32(span);
	}
	if (ONE_IN(SIGTERM_ONE_IN))
		return SIGTERM;
	return safe_signals[rnd_modulo_u32(ARRAY_SIZE(safe_signals))];
}

static void emit_signal(pid_t pid, int sig, bool use_kill)
{
	if (use_kill) {
		int sig_used = (int)RAND_NEGATIVE_OR(sig);

		(void)kill(pid, sig_used);
		/*
		 * kill(pid, 0) is a process-existence probe and delivers
		 * no signal; bill it separately so the delivery counter
		 * reflects actual signal delivery rate.
		 */
		if (sig_used == 0)
			__atomic_add_fetch(&shm->stats.signal_storm.probe,
					   1, __ATOMIC_RELAXED);
		else
			__atomic_add_fetch(&shm->stats.signal_storm.kill,
					   1, __ATOMIC_RELAXED);
	} else {
		union sigval sv;

		sv.sival_int = (int)rand32();
		(void)sigqueue(pid, sig, sv);
		__atomic_add_fetch(&shm->stats.signal_storm.sigqueue,
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
	unsigned int pick = rnd_modulo_u32(3);
	unsigned int i;

	if (pick == 1) {
		for (i = 0; i < n / 2; i++) {
			pid_t tmp = t[i];

			t[i] = t[n - 1 - i];
			t[n - 1 - i] = tmp;
		}
	} else if (pick == 2) {
		for (i = n; i > 1; i--) {
			unsigned int j = rnd_modulo_u32(i);
			pid_t tmp = t[i - 1];

			t[i - 1] = t[j];
			t[j] = tmp;
		}
	}
}

/*
 * Per-invocation context shared across the signal_storm phase helpers.
 * `targets[]` is filled by signal_storm_iter_collect_targets and read by
 * every burst arm; `iters`, `order`, and `catalog` are rolled by
 * signal_storm_iter_pick_mode and consumed by the burst arms.
 */
struct signal_storm_iter_ctx {
	pid_t			targets[MAX_TARGETS];
	unsigned int		ntargets;
	unsigned int		iters;
	enum storm_order	order;
	enum catalog_mode	catalog;
};

/*
 * Phase: snapshot up to MAX_TARGETS live sibling pids into ictx->targets.
 * Random walk from a random starting offset so the same children do not
 * get preferentially hammered every invocation.  The self/ppid skip and
 * the pid_is_valid() guard are load-bearing: both must filter a candidate
 * out before it lands in the array, otherwise a stale or self-referential
 * pid can leak into the burst arms.
 */
static void signal_storm_iter_collect_targets(struct signal_storm_iter_ctx *ictx)
{
	pid_t self = mypid();
	pid_t ppid = getppid();
	unsigned int i;

	if (max_children == 0)
		return;

	unsigned int start = rnd_modulo_u32(max_children);

	for (i = 0; i < max_children && ictx->ntargets < MAX_TARGETS; i++) {
		unsigned int slot = (start + i) % max_children;
		pid_t pid = __atomic_load_n(&pids[slot], __ATOMIC_RELAXED);

		if (pid == EMPTY_PIDSLOT)
			continue;
		if (pid == self || pid == ppid)
			continue;
		if (!pid_is_valid(pid))
			continue;
		ictx->targets[ictx->ntargets++] = pid;
	}
}

/*
 * Phase: roll iteration count, burst ordering, and signal catalog, then
 * reorder the snapshotted targets.  CATALOG_RESTRICTED locks the burst
 * onto a single sub-catalog (RT-only or std-only) so the catalog
 * selection has to happen here rather than per-emit -- the whole point
 * of that ordering is per-burst homogeneity.
 */
static void signal_storm_iter_pick_mode(struct signal_storm_iter_ctx *ictx)
{
	ictx->iters = 1 + rnd_modulo_u32(MAX_ITERATIONS);
	ictx->order = (enum storm_order)rnd_modulo_u32(NR_STORM_ORDERS);
	reorder_targets(ictx->targets, ictx->ntargets);

	if (ictx->order == ORDER_CATALOG_RESTRICTED)
		ictx->catalog = RAND_BOOL() ? CATALOG_RT_ONLY : CATALOG_STD_ONLY;
	else
		ictx->catalog = CATALOG_ANY;
}

/*
 * Phase: SAME_TARGET_BURST -- K (2..8) signals at one target, then move
 * to the next.  Grows __sigqueue / shared_pending depth on a single task
 * before rotating, which the uniform-draw default never sustains long
 * enough to exercise.
 */
static void signal_storm_iter_burst_same_target(struct signal_storm_iter_ctx *ictx)
{
	unsigned int t = 0;
	unsigned int i = 0;

	while (i < ictx->iters) {
		pid_t pid = ictx->targets[t % ictx->ntargets];
		unsigned int burst = 2 + rnd_modulo_u32(7); /* 2..8 */
		unsigned int k;

		for (k = 0; k < burst && i < ictx->iters; k++, i++) {
			int sig = pick_signal_in(ictx->catalog);

			emit_signal(pid, sig, RAND_BOOL());
		}
		t++;
	}
}

/*
 * Phase: MODE_GROUPED -- per target, K (1..4) kill()s back-to-back then
 * Q (1..4) sigqueue()s.  Exercises the kill -> sigqueue transition on a
 * single task's pending queue, which the per-iter mode flip of
 * burst_mixed cannot string together.
 */
static void signal_storm_iter_burst_mode_grouped(struct signal_storm_iter_ctx *ictx)
{
	unsigned int t = 0;
	unsigned int i = 0;

	while (i < ictx->iters) {
		pid_t pid = ictx->targets[t % ictx->ntargets];
		unsigned int kburst = 1 + rnd_modulo_u32(4); /* 1..4 */
		unsigned int qburst = 1 + rnd_modulo_u32(4);
		unsigned int k;

		for (k = 0; k < kburst && i < ictx->iters; k++, i++)
			emit_signal(pid, pick_signal_in(ictx->catalog), true);
		for (k = 0; k < qburst && i < ictx->iters; k++, i++)
			emit_signal(pid, pick_signal_in(ictx->catalog), false);
		t++;
	}
}

/*
 * Phase: MIXED -- baseline uniform draw of (target, mode, sig) each
 * iteration.  Also the catalog-restricted shape: when pick_mode latched
 * a CATALOG_RT_ONLY / CATALOG_STD_ONLY catalog, the homogeneous burst
 * lands here because the per-iter mode flip is what surfaces the
 * single-family queue behaviour we want.  Default arm: any future
 * storm_order with no dedicated burst helper falls through to this
 * shape.
 */
static void signal_storm_iter_burst_mixed(struct signal_storm_iter_ctx *ictx)
{
	unsigned int i;

	for (i = 0; i < ictx->iters; i++) {
		pid_t pid = ictx->targets[rnd_modulo_u32(ictx->ntargets)];
		int sig = pick_signal_in(ictx->catalog);

		emit_signal(pid, sig, RAND_BOOL());
	}
}

bool signal_storm(struct childdata *child)
{
	struct signal_storm_iter_ctx ictx = { 0 };

	__atomic_add_fetch(&shm->stats.signal_storm.runs, 1, __ATOMIC_RELAXED);

	signal_storm_iter_collect_targets(&ictx);

	if (ictx.ntargets == 0) {
		__atomic_add_fetch(&shm->stats.signal_storm.no_targets,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	signal_storm_iter_pick_mode(&ictx);

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

	switch (ictx.order) {
	case ORDER_SAME_TARGET_BURST:
		signal_storm_iter_burst_same_target(&ictx);
		break;
	case ORDER_MODE_GROUPED:
		signal_storm_iter_burst_mode_grouped(&ictx);
		break;
	case ORDER_MIXED:
	case ORDER_CATALOG_RESTRICTED:
	default:
		signal_storm_iter_burst_mixed(&ictx);
		break;
	}

	return true;
}
