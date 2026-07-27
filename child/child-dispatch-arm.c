/*
 * Childop dispatch-arm helpers carved out of child.c: the
 * lowest-free-fd probe that brackets each alt-op dispatch to detect
 * fd leaks, and the per-child corruption-rate storm-recycle check the
 * loop consults on the LOCAL_STORM_CHECK_PERIOD gate.  Split out so
 * make -j can compile the alt-op dispatch bookkeeping concurrently
 * with the periodic-tick and watchdog helpers.
 *
 * probe_lowest_free_fd and storm_rate_recycle shed their `static`
 * linkage here so the child_process() main loop (still in child.c) can
 * reach them across the TU boundary; declarations are in
 * include/child-internal.h.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "child-internal.h"

/*
 * Cheap "lowest unused fd" probe.  open("/dev/null", O_RDONLY|O_CLOEXEC)
 * returns the smallest free fd in this child's fd table; close it
 * immediately so the probe itself has no net effect.  Sampling this
 * value before and after each dispatched alt-op yields a monotonic
 * proxy for the op's net fd-table growth: a childop that opens fds
 * and forgets to close some on an error path bumps the returned
 * number, and the delta is non-zero on the leaking invocation.
 *
 * Returns -1 on non-EMFILE failures so the caller's delta computation
 * short-circuits (the caller treats a -1 as "no observation" and skips
 * the per-op bump); the probe is diagnostic only, never load-bearing.
 * EMFILE is special-cased: the fd table is at RLIMIT_NOFILE, which is
 * exactly the leak signature we want to catch, so return the ceiling
 * (rlim_cur) and set *at_ceiling = true so the caller can record the
 * exhaustion event without inflating fd_delta_positive_sum by
 * (ceiling - N) -- a single leaked fd at the ceiling would otherwise
 * masquerade as a ~rlim_cur-sized single-op leak.  The caller caps the
 * observed delta to 1 in that case and bumps fd_leak_at_ceiling[op]
 * as the sentinel signal.  If getrlimit itself fails or reports a
 * ceiling that would not fit in int, fall back to -1.
 * Two syscalls per alt-op dispatch is well inside the syscall-per-op
 * budget the alarm(1) watchdog and the childop_wall_ns bracket already
 * pay.
 */
int probe_lowest_free_fd(bool *at_ceiling)
{
	int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);

	*at_ceiling = false;

	if (fd < 0) {
		if (errno == EMFILE) {
			struct rlimit rl;

			if (getrlimit(RLIMIT_NOFILE, &rl) == 0 &&
			    rl.rlim_cur > 0 && rl.rlim_cur <= INT_MAX) {
				*at_ceiling = true;
				return (int)rl.rlim_cur;
			}
		}
		return -1;
	}
	close(fd);
	return fd;
}

/*
 * Per-child corruption-rate storm check.  Cheap modulo-gated probe of
 * the three local_* counters maintained alongside their global shm
 * stats siblings; returns true when any counter has been climbing at
 * LOCAL_STORM_RATE_THRESHOLD events/sec or more for at least
 * LOCAL_STORM_WINDOW_SEC seconds, in which case the caller should
 * exit its main loop so the parent can recycle the slot.
 *
 * The window-floor (LOCAL_STORM_WINDOW_SEC) suppresses single-spike
 * false positives -- a transient burst that cannot sustain absorbs
 * into the next snapshot roll instead of recycling the child.  When
 * the window has aged past the floor without any signal exceeding the
 * rate threshold, the snapshot is rolled forward so the next check
 * measures a fresh window rather than a smeared cumulative rate.
 *
 * Returns false (and may roll the snapshot) when no recycle is needed.
 */
bool storm_rate_recycle(struct childdata *child)
{
	struct timespec now;
	long window_sec;
	unsigned long delta_post;

	clock_gettime(CLOCK_MONOTONIC, &now);
	window_sec = (long)(now.tv_sec - child->storm_check_last_time.tv_sec);
	if (window_sec < LOCAL_STORM_WINDOW_SEC)
		return false;

	delta_post = child->local_post_handler_corrupt_ptr -
		     child->storm_check_last_post_handler;

	if ((delta_post / (unsigned long)window_sec) >= LOCAL_STORM_RATE_THRESHOLD)
		return true;

	/* Quiet window: roll the snapshot so the next check measures the
	 * next window in isolation rather than smearing a years-long
	 * cumulative count against a fresh interval. */
	child->storm_check_last_time = now;
	child->storm_check_last_post_handler = child->local_post_handler_corrupt_ptr;
	return false;
}
