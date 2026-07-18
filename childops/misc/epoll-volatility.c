/*
 * epoll_volatility - rapid EPOLL_CTL_ADD/MOD/DEL churn against a small
 * pool of overlapping epfds and target fds.
 *
 * Trinity's random_syscall path issues epoll_create / epoll_ctl /
 * epoll_wait independently and against arbitrary (mostly invalid) fds,
 * so the kernel's epoll code path — ep_insert (RB-tree insert + per-fd
 * epitem list link + waitqueue add), ep_modify (events update + idr
 * lookup), ep_remove (RB-tree erase + per-fd epitem list unlink +
 * waitqueue removal) — only sees one stray operation at a time.  None
 * of the existing childops put sustained concurrent pressure on the
 * per-target-fd epitem list or on cross-epfd cleanup.
 *
 * epoll_volatility closes that gap.  Each invocation:
 *
 *   1. Creates NR_EPFDS epoll instances via epoll_create1(EPOLL_CLOEXEC).
 *   2. Creates NR_TARGET_FDS eventfds (cheap, always pollable, no fd-pair
 *      bookkeeping) — these are the targets that get added/modified/
 *      deleted across every epfd.  Eventfds work as monitor targets in
 *      every container/namespace trinity might run in.
 *   3. Tight bounded loop, capped at MAX_ITERATIONS or BUDGET_NS:
 *      - Pick a random op from {ADD, MOD, DEL, WAIT}.
 *      - For ADD/MOD/DEL: pick a random epfd and a target_fd; bias
 *        toward an unregistered slot (ADD) or a registered slot
 *        (MOD/DEL) by sampling a few random indices, so most ops are
 *        valid.  Some -EEXIST / -ENOENT churn slips through and
 *        exercises the error-return paths.  Random event masks chosen
 *        from EPOLLIN / EPOLLOUT / EPOLLET / EPOLLONESHOT /
 *        EPOLLEXCLUSIVE in random combos so the events_update path
 *        sees realistic mask transitions.
 *      - WAIT: epoll_wait with timeout 1ms and a small evs[] buffer.
 *   4. Teardown (outside the timed budget): close every epfd, then
 *      every target fd.  The per-epfd epitem cleanup runs in the
 *      ep_eventpoll release path when each epfd closes — that's a
 *      core part of the test surface.
 *
 * The overlap is the test surface: 4 epfds × 8 target_fds means a single
 * eventfd can sit on the per-fd epitem list of every epfd at once, so
 * rapid ADD/MOD/DEL across epfds exercises the per-target-fd epitem
 * list cleanup (file_remove_eventpoll style chains) and the
 * cross-epfd waitqueue racing that ep_poll_callback contends with.
 * Multiple epoll_volatility children running in parallel under
 * --alt-op-children give those paths cross-task pressure on top of the
 * per-task burst pressure.
 *
 * Self-bounding:
 *   - MAX_ITERATIONS caps inner-loop iterations.
 *   - BUDGET_NS (200 ms) sits in the same band the other recent thrash
 *     ops use; setup/teardown is OUTSIDE the timed budget so the
 *     storm itself fits in the window.
 *   - alarm(1) is armed by child.c around every non-syscall op, so a
 *     wedged epoll path here still trips the SIGALRM stall detector.
 *   - All epfds and target fds are closed before return.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <string.h>
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

#include "kernel/eventfd.h"
/* Number of epoll instances per invocation.  Small on purpose: enough
 * that a single target_fd ends up on multiple per-fd epitem lists, so
 * cross-epfd waitqueue racing is exercised, but well under any sane
 * RLIMIT_NOFILE margin (we hold 4 epfds + 8 eventfds = 12 fds at peak). */
#define NR_EPFDS	4

/* Number of eventfd targets registered across the epfd pool.  8 targets
 * give the per-fd epitem list a non-trivial walk on cleanup without
 * inflating fd consumption. */
#define NR_TARGET_FDS	8

/* Hard cap on inner loop iterations.  Sized like xattr_thrash and
 * pidfd_storm: cheap enough that 64 iterations finishes well under the
 * 1-second SIGALRM the parent arms before dispatch. */
#define MAX_ITERATIONS	64

/* Wall-clock ceiling for the inner loop.  Sits in the 200ms band the
 * other recent thrash childops use so dump_stats still ticks regularly
 * and SIGALRM stall detection has plenty of headroom. */
#define BUDGET_NS	200000000L	/* 200 ms */

/* Curated event-mask components.  Combined randomly per ADD/MOD so the
 * events_update path inside ep_modify sees realistic mask transitions
 * (level vs edge, oneshot, exclusive) instead of a single static mask. */
static const uint32_t event_bits[] = {
	EPOLLIN,
	EPOLLOUT,
	EPOLLET,
	EPOLLONESHOT,
	EPOLLEXCLUSIVE,
};

/* Build a randomised events mask.  Always include at least one of
 * EPOLLIN/EPOLLOUT so ep_insert has something concrete to hash on; the
 * other bits are toggled independently.  EPOLLEXCLUSIVE is mutually
 * exclusive with EPOLLONESHOT in the kernel — if both happen to land
 * the kernel will return -EINVAL, which we count as benign failure. */
static uint32_t random_events(void)
{
	uint32_t ev = 0;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(event_bits); i++) {
		if (rnd_modulo_u32(2) == 0)
			ev |= event_bits[i];
	}
	if ((ev & (EPOLLIN | EPOLLOUT)) == 0)
		ev |= EPOLLIN;
	return ev;
}

/* Find a target_fd slot in the chosen epfd that matches the desired
 * registration state (true = registered, false = unregistered).  Probe
 * up to NR_TARGET_FDS random indices; if none match, fall back to a
 * random index (the resulting op will return -EEXIST or -ENOENT, which
 * is benign and exercises the error-return paths). */
static unsigned int pick_fd_idx(const bool registered[NR_EPFDS][NR_TARGET_FDS],
				unsigned int epfd_idx, unsigned int n_target_fds,
				bool want_registered)
{
	unsigned int tries;

	if (n_target_fds == 0)
		return 0;

	for (tries = 0; tries < n_target_fds; tries++) {
		unsigned int idx = rnd_modulo_u32(n_target_fds);

		if (registered[epfd_idx][idx] == want_registered)
			return idx;
	}
	return rnd_modulo_u32(n_target_fds);
}

/*
 * Per-invocation state shared across the epoll_volatility phase
 * helpers.  Only fields read or written across helper boundaries are
 * lifted here -- per-iter scratch (op selector, event mask, evs[]
 * buffer, the start/budget timespec) stays local to the drive phase.
 *
 * n_epfds / n_target_fds double as both the high-water mark for the
 * setup phase and the bound the teardown phase walks when closing,
 * so a setup that fails partway through still leaves the teardown
 * helper able to close exactly the fds that were successfully
 * created.  Counts start at 0 via the orchestrator's initializer.
 */
struct epoll_volatility_iter_ctx {
	int		epfds[NR_EPFDS];
	int		target_fds[NR_TARGET_FDS];
	bool		registered[NR_EPFDS][NR_TARGET_FDS];
	unsigned int	n_epfds;
	unsigned int	n_target_fds;
};

/*
 * Setup phase: create up to NR_EPFDS epoll instances and
 * NR_TARGET_FDS eventfds, recording how many of each were
 * successfully created in ctx->n_epfds / ctx->n_target_fds.
 * Returns 0 if the drive phase has something to work with (at
 * least one epfd AND at least one target fd) and -1 otherwise.
 * On -1 the teardown helper is still safe to call: it closes
 * exactly ctx->n_epfds + ctx->n_target_fds descriptors.
 */
static int epoll_volatility_iter_setup(struct epoll_volatility_iter_ctx *ctx)
{
	unsigned int i;

	for (i = 0; i < NR_EPFDS; i++) {
		int fd = epoll_create1(EPOLL_CLOEXEC);

		if (fd < 0)
			break;
		ctx->epfds[ctx->n_epfds++] = fd;
	}

	for (i = 0; i < NR_TARGET_FDS; i++) {
		int fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);

		if (fd < 0)
			break;
		ctx->target_fds[ctx->n_target_fds++] = fd;
	}

	if (ctx->n_epfds == 0 || ctx->n_target_fds == 0)
		return -1;

	memset(ctx->registered, 0, sizeof(ctx->registered));
	return 0;
}

/*
 * Drive phase: the timed ADD/MOD/DEL/WAIT churn loop.  Picks a
 * jittered iteration count up front, then bounded-loops until
 * either the count or the BUDGET_NS wall-clock ceiling is hit.
 * The start timespec, iter counter, and per-iter scratch (op
 * selector, event mask, evs[] buffer) all stay local to this
 * helper -- only ctx fields cross helper boundaries.
 *
 * Caller must have run epoll_volatility_iter_setup() and seen
 * it return 0, so ctx.n_epfds > 0 and ctx.n_target_fds > 0 are
 * the helper's precondition (rnd_modulo_u32() on them would
 * otherwise divide by zero).
 */
static void epoll_volatility_iter_drive(struct epoll_volatility_iter_ctx *ctx)
{
	struct timespec start;
	unsigned int iters = JITTER_RANGE(MAX_ITERATIONS);
	unsigned int iter;

	clock_gettime(CLOCK_MONOTONIC, &start);

	for (iter = 0; iter < iters; iter++) {
		unsigned int op = rnd_modulo_u32(16);
		unsigned int epfd_idx = rnd_modulo_u32(ctx->n_epfds);
		struct epoll_event ev;
		unsigned int fd_idx;
		int rc;

		if (op < 5) {
			/* EPOLL_CTL_ADD: prefer an unregistered slot so the
			 * op succeeds and grows the per-fd epitem list. */
			fd_idx = pick_fd_idx(ctx->registered, epfd_idx, ctx->n_target_fds, false);
			memset(&ev, 0, sizeof(ev));
			ev.events  = (uint32_t)RAND_NEGATIVE_OR(random_events());
			ev.data.fd = ctx->target_fds[fd_idx];
			rc = epoll_ctl(ctx->epfds[epfd_idx], EPOLL_CTL_ADD,
				       ctx->target_fds[fd_idx], &ev);
			__atomic_add_fetch(&shm->stats.epoll_volatility.ctl_calls,
					   1, __ATOMIC_RELAXED);
			if (rc == 0) {
				if (fd_idx < NR_TARGET_FDS)
					ctx->registered[epfd_idx][fd_idx] = true;
			} else {
				__atomic_add_fetch(&shm->stats.epoll_volatility.failed,
						   1, __ATOMIC_RELAXED);
			}
		} else if (op < 10) {
			/* EPOLL_CTL_MOD: prefer a registered slot so the
			 * events_update path inside ep_modify is exercised
			 * with a real mask transition.  Random new mask
			 * each time. */
			fd_idx = pick_fd_idx(ctx->registered, epfd_idx, ctx->n_target_fds, true);
			memset(&ev, 0, sizeof(ev));
			ev.events  = random_events();
			ev.data.fd = ctx->target_fds[fd_idx];
			rc = epoll_ctl(ctx->epfds[epfd_idx], EPOLL_CTL_MOD,
				       ctx->target_fds[fd_idx], &ev);
			__atomic_add_fetch(&shm->stats.epoll_volatility.ctl_calls,
					   1, __ATOMIC_RELAXED);
			if (rc != 0)
				__atomic_add_fetch(&shm->stats.epoll_volatility.failed,
						   1, __ATOMIC_RELAXED);
		} else if (op < 14) {
			/* EPOLL_CTL_DEL: prefer a registered slot so the
			 * per-fd epitem unlink + waitqueue removal path
			 * inside ep_remove is exercised. */
			fd_idx = pick_fd_idx(ctx->registered, epfd_idx, ctx->n_target_fds, true);
			rc = epoll_ctl(ctx->epfds[epfd_idx], EPOLL_CTL_DEL,
				       ctx->target_fds[fd_idx], NULL);
			__atomic_add_fetch(&shm->stats.epoll_volatility.ctl_calls,
					   1, __ATOMIC_RELAXED);
			if (rc == 0) {
				if (fd_idx < NR_TARGET_FDS)
					ctx->registered[epfd_idx][fd_idx] = false;
			} else {
				__atomic_add_fetch(&shm->stats.epoll_volatility.failed,
						   1, __ATOMIC_RELAXED);
			}
		} else {
			/* epoll_wait with a 1ms timeout and a small events
			 * buffer.  Eventfds at value 0 aren't ready, so the
			 * wait will return 0 (timeout) without delivering
			 * events — the point is to exercise the wait-list
			 * walk and timeout path, not to harvest events. */
			struct epoll_event evs[4];

			(void) epoll_wait(ctx->epfds[epfd_idx], evs,
					  (int) ARRAY_SIZE(evs), 1);
		}

		if (budget_elapsed_ns(&start, BUDGET_NS))
			break;
	}
}

/*
 * Teardown phase: close every successfully-created epfd, then
 * every target fd.  Safe to call after a partial setup -- the
 * helper walks exactly ctx->n_epfds / ctx->n_target_fds entries,
 * which the setup helper bumped only on successful create.  Per-
 * epfd epitem cleanup runs in the kernel's ep_eventpoll release
 * path when each epfd closes; that release-side cross-epfd
 * waitqueue walk is core to the test surface, so the close order
 * here (epfds first, target fds second) is preserved.
 */
static void epoll_volatility_iter_teardown(struct epoll_volatility_iter_ctx *ctx)
{
	unsigned int i;

	for (i = 0; i < ctx->n_epfds; i++)
		close(ctx->epfds[i]);
	for (i = 0; i < ctx->n_target_fds; i++)
		close(ctx->target_fds[i]);
}

bool epoll_volatility(struct childdata *child)
{
	struct epoll_volatility_iter_ctx ctx = {
		.n_epfds = 0,
		.n_target_fds = 0,
	};

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.epoll_volatility.runs, 1, __ATOMIC_RELAXED);

	if (epoll_volatility_iter_setup(&ctx) == 0) {
		if (valid_op) {
			__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
					   1, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.childop.data_path[op],
					   1, __ATOMIC_RELAXED);
		}
		epoll_volatility_iter_drive(&ctx);
	}

	epoll_volatility_iter_teardown(&ctx);
	return true;
}
