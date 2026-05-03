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
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

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
		if (rand() % 2 == 0)
			ev |= event_bits[i];
	}
	if ((ev & (EPOLLIN | EPOLLOUT)) == 0)
		ev |= EPOLLIN;
	return ev;
}

static bool budget_elapsed(const struct timespec *start)
{
	struct timespec now;
	long elapsed_ns;

	clock_gettime(CLOCK_MONOTONIC, &now);
	elapsed_ns = (now.tv_sec  - start->tv_sec)  * 1000000000L
		   + (now.tv_nsec - start->tv_nsec);
	return elapsed_ns >= BUDGET_NS;
}

/* Find a target_fd slot in the chosen epfd that matches the desired
 * registration state (true = registered, false = unregistered).  Probe
 * up to NR_TARGET_FDS random indices; if none match, fall back to a
 * random index (the resulting op will return -EEXIST or -ENOENT, which
 * is benign and exercises the error-return paths). */
static unsigned int pick_fd_idx(const bool registered[NR_EPFDS][NR_TARGET_FDS],
				unsigned int epfd_idx, bool want_registered)
{
	unsigned int tries;

	for (tries = 0; tries < NR_TARGET_FDS; tries++) {
		unsigned int idx = (unsigned int) rand() % NR_TARGET_FDS;

		if (registered[epfd_idx][idx] == want_registered)
			return idx;
	}
	return (unsigned int) rand() % NR_TARGET_FDS;
}

bool epoll_volatility(struct childdata *child)
{
	int epfds[NR_EPFDS];
	int target_fds[NR_TARGET_FDS];
	bool registered[NR_EPFDS][NR_TARGET_FDS];
	struct timespec start;
	unsigned int n_epfds = 0;
	unsigned int n_target_fds = 0;
	unsigned int iter;
	unsigned int i, j;

	(void) child;

	__atomic_add_fetch(&shm->stats.epoll_volatility_runs, 1, __ATOMIC_RELAXED);

	for (i = 0; i < NR_EPFDS; i++) {
		int fd = epoll_create1(EPOLL_CLOEXEC);

		if (fd < 0)
			break;
		epfds[n_epfds++] = fd;
	}

	for (i = 0; i < NR_TARGET_FDS; i++) {
		int fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);

		if (fd < 0)
			break;
		target_fds[n_target_fds++] = fd;
	}

	if (n_epfds == 0 || n_target_fds == 0)
		goto out;

	memset(registered, 0, sizeof(registered));

	clock_gettime(CLOCK_MONOTONIC, &start);

	for (iter = 0; iter < MAX_ITERATIONS; iter++) {
		unsigned int op = (unsigned int) rand() % 16;
		unsigned int epfd_idx = (unsigned int) rand() % n_epfds;
		struct epoll_event ev;
		unsigned int fd_idx;
		int rc;

		if (op < 5) {
			/* EPOLL_CTL_ADD: prefer an unregistered slot so the
			 * op succeeds and grows the per-fd epitem list. */
			fd_idx = pick_fd_idx(registered, epfd_idx, false);
			memset(&ev, 0, sizeof(ev));
			ev.events  = random_events();
			ev.data.fd = target_fds[fd_idx];
			rc = epoll_ctl(epfds[epfd_idx], EPOLL_CTL_ADD,
				       target_fds[fd_idx], &ev);
			__atomic_add_fetch(&shm->stats.epoll_volatility_ctl_calls,
					   1, __ATOMIC_RELAXED);
			if (rc == 0) {
				if (fd_idx < NR_TARGET_FDS)
					registered[epfd_idx][fd_idx] = true;
			} else {
				__atomic_add_fetch(&shm->stats.epoll_volatility_failed,
						   1, __ATOMIC_RELAXED);
			}
		} else if (op < 10) {
			/* EPOLL_CTL_MOD: prefer a registered slot so the
			 * events_update path inside ep_modify is exercised
			 * with a real mask transition.  Random new mask
			 * each time. */
			fd_idx = pick_fd_idx(registered, epfd_idx, true);
			memset(&ev, 0, sizeof(ev));
			ev.events  = random_events();
			ev.data.fd = target_fds[fd_idx];
			rc = epoll_ctl(epfds[epfd_idx], EPOLL_CTL_MOD,
				       target_fds[fd_idx], &ev);
			__atomic_add_fetch(&shm->stats.epoll_volatility_ctl_calls,
					   1, __ATOMIC_RELAXED);
			if (rc != 0)
				__atomic_add_fetch(&shm->stats.epoll_volatility_failed,
						   1, __ATOMIC_RELAXED);
		} else if (op < 14) {
			/* EPOLL_CTL_DEL: prefer a registered slot so the
			 * per-fd epitem unlink + waitqueue removal path
			 * inside ep_remove is exercised. */
			fd_idx = pick_fd_idx(registered, epfd_idx, true);
			rc = epoll_ctl(epfds[epfd_idx], EPOLL_CTL_DEL,
				       target_fds[fd_idx], NULL);
			__atomic_add_fetch(&shm->stats.epoll_volatility_ctl_calls,
					   1, __ATOMIC_RELAXED);
			if (rc == 0) {
				if (fd_idx < NR_TARGET_FDS)
					registered[epfd_idx][fd_idx] = false;
			} else {
				__atomic_add_fetch(&shm->stats.epoll_volatility_failed,
						   1, __ATOMIC_RELAXED);
			}
		} else {
			/* epoll_wait with a 1ms timeout and a small events
			 * buffer.  Eventfds at value 0 aren't ready, so the
			 * wait will return 0 (timeout) without delivering
			 * events — the point is to exercise the wait-list
			 * walk and timeout path, not to harvest events. */
			struct epoll_event evs[4];

			(void) epoll_wait(epfds[epfd_idx], evs,
					  (int) ARRAY_SIZE(evs), 1);
		}

		if (budget_elapsed(&start))
			break;
	}

out:
	for (i = 0; i < n_epfds; i++)
		close(epfds[i]);
	for (j = 0; j < n_target_fds; j++)
		close(target_fds[j]);

	return true;
}
