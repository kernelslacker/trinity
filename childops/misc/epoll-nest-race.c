/*
 * epoll_nest_race - epoll reverse-path walk under concurrent fd-slot churn.
 *
 * MOTIVATION
 * ----------
 * The epoll subsystem's existing childop (epoll_volatility) only ever
 * adds eventfds to epoll instances.  Because the target files are
 * eventfds, is_file_epoll(tfile) is always false and the nesting /
 * reverse-path guard — ep_loop_check() / ep_loop_check_proc() and the
 * associated nested-file-list machinery (epnested_mutex-protected in
 * 6.13; per-ep_ctl_ctx at HEAD) in fs/eventpoll.c — is never entered.
 *
 * This childop closes that gap.  It builds a chain of epoll fds where
 * each one monitors the next (epfd[0] → epfd[1] → ... → epfd[N-1] →
 * leaf eventfd).  When EPOLL_CTL_ADD is issued with an epfd target,
 * is_file_epoll(tfile) returns true and the kernel enters ep_loop_check,
 * which acquires tfile_check_lock and walks the reverse-path list via
 * ep_loop_check_proc.  A sibling thread races by hammer-close()ing and
 * immediately open()ing /dev/null to force fd-slot reuse, putting
 * concurrent pressure on the per-slot file-pointer transitions that the
 * walk dereferences.
 *
 * BUG CLASS AND DETECTOR
 * ----------------------
 * The signature of the bug class exercised here is:
 *
 *     BUG: spinlock already unlocked in clear_tfile_check_list
 *
 * arising from a use-after-free of an epitem whose backing file was
 * recycled in the SLAB_TYPESAFE_BY_RCU file cache before the reverse-
 * path walk completed.  The slab layer intentionally leaves the slot
 * unpoisoned between free and reallocation under SLAB_TYPESAFE_BY_RCU,
 * so KASAN is blind to this class by construction — poisoning the slot
 * would break the RCU guarantee.
 *
 * DO NOT add this childop to KASAN-only runs.  The required detector is:
 *   CONFIG_DEBUG_SPINLOCK=y  (catches the already-unlocked spinlock)
 * CONFIG_PROVE_LOCKING / CONFIG_LOCKDEP is not set on the target config;
 * DEBUG_SPINLOCK is the sole live detector in the standard fuzz fleet.
 *
 * STRUCTURE
 * ---------
 * Each invocation:
 *
 *   1. Creates CHAIN_DEPTH epoll instances.
 *   2. Creates one leaf eventfd.
 *   3. Builds the watch chain by calling EPOLL_CTL_ADD for each
 *      epfd[i] with epfd[i+1] as the target (triggering the reverse-
 *      path check), then registering the leaf eventfd on epfd[N-1].
 *   4. Spawns a racer thread that loops for RACER_LAPS iterations,
 *      closing and reopening /dev/null to hammer fd-slot reuse.
 *   5. Races the racer against additional EPOLL_CTL_DEL / EPOLL_CTL_ADD
 *      cycles on the leaf eventfd slot to keep the reverse-path walk
 *      active across the window the racer creates.
 *   6. Joins the racer thread, then tears down all fds.
 *
 * CHAIN DEPTH
 * -----------
 * CHAIN_DEPTH is 5 (in the 4–8 range).  This is deep enough to reach
 * ep_loop_check_proc on every ADD of an epfd target without approaching
 * the kernel's existing nesting limit (EP_MAX_NESTS = 4 levels of epfd-
 * in-epfd nesting, enforced separately in ep_loop_check).  A depth of 5
 * links means 4 epfd→epfd ADD steps, landing exactly at the nesting
 * limit from below — the kernel accepts the chain, exercises the full
 * reverse-path walk on each step, and returns 0.  Depths beyond 8 would
 * enter the nesting-limit rejection path, which is tested by other means.
 *
 * SELF-BOUNDING
 * -------------
 *   - BUDGET_NS (200 ms) matches the band used by other recent thrash ops.
 *   - MAX_RACE_ITERS caps the main loop.
 *   - RACER_LAPS caps the racer thread; each lap is two syscalls (close +
 *     open), so the racer's total syscall count is bounded.
 *   - All fds (epfds, leaf eventfd, racer's /dev/null fds) are closed
 *     before return.
 *   - The racer thread is always joined before teardown, so no fd
 *     escapes into a detached thread.
 */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
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

/*
 * Number of epoll fds in the watch chain.  Five links produce four
 * epfd→epfd ADD steps (depth 4 = EP_MAX_NESTS exactly), exercising the
 * full reverse-path walk on each step without triggering the nesting-
 * limit rejection that kicks in at depth > EP_MAX_NESTS.
 */
#define CHAIN_DEPTH	5

/* Hard cap on inner-loop iterations.  Each iteration issues one or two
 * epoll_ctl calls (DEL + ADD on the leaf slot), so total syscalls in
 * the main loop stay well under the 1 s SIGALRM window. */
#define MAX_RACE_ITERS	48

/* Wall-clock ceiling for the main race loop. */
#define BUDGET_NS	200000000L	/* 200 ms */

/*
 * Number of close/open cycles the racer thread performs.  Each lap is
 * two syscalls; sized to complete within the BUDGET_NS window without
 * needing synchronisation with the main thread. */
#define RACER_LAPS	256

/* Argument block passed to the racer thread.  The racer owns fd_to_race
 * for the duration — the main thread must not touch it after handing
 * it off.  The racer replaces it on every lap; the main thread reads
 * the final value only after join. */
struct racer_arg {
	int		fd_to_race;	/* initial fd to close (leaf efd) */
	unsigned long	laps_done;	/* filled in by racer before exit */
	unsigned long	racer_syscalls;	/* close+open count across all laps */
};

/*
 * Racer thread: hammer close()/open(/dev/null) on the fd slot handed to
 * us.  The rapid free-and-reuse of the fd number forces the kernel's
 * file-descriptor table to recycle the slot — and the SLAB_TYPESAFE_BY_RCU
 * slab to reallocate the struct file at the same address — while the main
 * thread is running EPOLL_CTL_ADD with that slot as a target.  The race
 * window is the gap between ep_find() locating the tfile pointer and
 * ep_loop_check() finishing its reverse-path walk.
 */
static void *racer_fn(void *arg)
{
	struct racer_arg *ra = arg;
	unsigned long lap;

	for (lap = 0; lap < RACER_LAPS; lap++) {
		int fd;
		int cur = __atomic_load_n(&ra->fd_to_race, __ATOMIC_RELAXED);

		if (cur >= 0)
			close(cur);
		ra->racer_syscalls++;	/* close */
		fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
		ra->racer_syscalls++;	/* open */
		__atomic_store_n(&ra->fd_to_race,
				 fd >= 0 ? fd : -1, __ATOMIC_RELAXED);
	}

	ra->laps_done = lap;
	return NULL;
}

bool epoll_nest_race(struct childdata *child)
{
	int epfds[CHAIN_DEPTH];
	int leaf_efd = -1;
	unsigned int n_epfds = 0;
	unsigned int i;
	struct epoll_event ev;
	struct racer_arg ra;
	pthread_t racer;
	bool racer_spawned = false;
	struct timespec start;
	unsigned int iters;
	unsigned long direct_calls = 0;
	unsigned long ctl_calls = 0;
	unsigned long failed = 0;
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.epoll_nest_race.runs, 1, __ATOMIC_RELAXED);

	/* Step 1: create CHAIN_DEPTH epoll instances. */
	for (i = 0; i < CHAIN_DEPTH; i++) {
		int fd = epoll_create1(EPOLL_CLOEXEC);

		if (fd < 0)
			goto teardown;
		epfds[n_epfds++] = fd;
	}

	/* Step 2: create the leaf eventfd. */
	leaf_efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (leaf_efd < 0)
		goto teardown;

	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}

	direct_calls += n_epfds + 1;	/* epoll_create1 × n + eventfd */

	/*
	 * Step 3: build the epfd chain.
	 *
	 * epfd[0] watches epfd[1], epfd[1] watches epfd[2], ...,
	 * epfd[N-2] watches epfd[N-1], epfd[N-1] watches leaf_efd.
	 *
	 * Each epfd→epfd ADD causes is_file_epoll(tfile) == true inside
	 * do_epoll_ctl, which calls ep_loop_check() and enters the
	 * reverse-path walk in ep_loop_check_proc().
	 */
	for (i = 0; i + 1 < n_epfds; i++) {
		int target = epfds[i + 1];

		memset(&ev, 0, sizeof(ev));
		ev.events  = EPOLLIN;
		ev.data.fd = target;
		if (epoll_ctl(epfds[i], EPOLL_CTL_ADD, target, &ev) != 0)
			failed++;
		ctl_calls++;
		direct_calls++;
	}

	/* Register the leaf eventfd on the deepest epfd. */
	memset(&ev, 0, sizeof(ev));
	ev.events  = EPOLLIN;
	ev.data.fd = leaf_efd;
	if (epoll_ctl(epfds[n_epfds - 1], EPOLL_CTL_ADD, leaf_efd, &ev) != 0)
		failed++;
	ctl_calls++;
	direct_calls++;

	/*
	 * Step 4: spawn the racer thread.
	 *
	 * Hand off leaf_efd to the racer.  The racer closes it on every
	 * lap and opens /dev/null to reuse the slot number.  Meanwhile
	 * the main thread below repeatedly removes and re-adds the leaf
	 * slot to epfds[n_epfds - 1], keeping the reverse-path walk
	 * active across the window the racer creates.
	 */
	ra.fd_to_race = leaf_efd;
	ra.laps_done  = 0;
	leaf_efd = -1;		/* ownership transferred to racer */

	if (pthread_create(&racer, NULL, racer_fn, &ra) == 0) {
		racer_spawned = true;
	}

	/*
	 * Step 5: race the main thread against the racer.
	 *
	 * Issue DEL + ADD on the deepest epfd's leaf slot in a tight
	 * loop.  After the racer closes the slot and /dev/null reuses
	 * the number, our ADD targets a different struct file via the
	 * same fd integer — exercising the race between fd-slot reuse
	 * and the reverse-path walk's tfile dereference.
	 */
	iters = JITTER_RANGE(MAX_RACE_ITERS);
	clock_gettime(CLOCK_MONOTONIC, &start);

	for (i = 0; i < iters; i++) {
		int slot = __atomic_load_n(&ra.fd_to_race, __ATOMIC_RELAXED);	/* may change between laps */

		/* DEL: tolerate ENOENT (racer closed it already). */
		epoll_ctl(epfds[n_epfds - 1], EPOLL_CTL_DEL, slot, NULL);
		ctl_calls++;
		direct_calls++;

		/* ADD: the slot may now point to /dev/null (not an epfd,
		 * not an eventfd) — that's fine; a -EPERM or -EINVAL from
		 * a non-pollable file is benign and exercises the error
		 * paths in do_epoll_ctl.  An ADD of a still-valid eventfd
		 * goes through the normal insert path. */
		memset(&ev, 0, sizeof(ev));
		ev.events  = EPOLLIN;
		ev.data.fd = slot;
		if (epoll_ctl(epfds[n_epfds - 1], EPOLL_CTL_ADD,
			      slot, &ev) != 0)
			failed++;
		ctl_calls++;
		direct_calls++;

		if (budget_elapsed_ns(&start, BUDGET_NS))
			break;
	}

	if (racer_spawned)
		pthread_join(racer, NULL);

	/* Fold racer-thread syscalls into the main tally now that join
	 * provides the happens-before barrier. */
	direct_calls += ra.racer_syscalls;

	__atomic_add_fetch(&shm->stats.epoll_nest_race.racer_laps,
			   ra.laps_done, __ATOMIC_RELAXED);

	/* The racer may have left its last open fd in ra.fd_to_race.
	 * Close it so we don't leak. */
	if (ra.fd_to_race >= 0) {
		direct_calls++;
		close(ra.fd_to_race);
	}

teardown:
	/* Close all epfds.  The ep_eventpoll release path runs per-epfd
	 * cleanup, walking the registered epitem list — this is also part
	 * of the test surface.  Close epfds first so the reverse-path
	 * list is torn down before the targets it referenced disappear. */
	for (i = 0; i < n_epfds; i++) {
		direct_calls++;
		close(epfds[i]);
	}

	if (leaf_efd >= 0) {
		direct_calls++;
		close(leaf_efd);
	}

	__atomic_add_fetch(&shm->stats.epoll_nest_race.ctl_calls,
			   ctl_calls, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.epoll_nest_race.failed,
			   failed, __ATOMIC_RELAXED);

	if (valid_op)
		childop_direct_syscalls_add(op, direct_calls);

	return true;
}
