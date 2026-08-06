/*
 * child-canary-liveness.c -- Pid-liveness probes and three-stage slot
 * teardown for the dormant-childop canary promotion queue.
 *
 * Owns kill_canary_slot_children(): SIGTERM → grace window → SIGKILL
 * sequence used by enter_canarying() to flush the previous canary slot
 * child before staging a new op.
 *
 * All other canary state lives in child-canary-state.c,
 * child-canary-stats.c, child-canary-picker.c, child-canary-policy.c,
 * child-canary-report.c, and child-canary-grace.c; all share
 * child-canary-internal.h.
 */
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>

#include "child-canary-internal.h"
#include "params.h"
#include "pids.h"
#include "trinity.h"
#include "utils-proc.h"

/*
 * Three-stage teardown: request graceful exit via SIGTERM, give slots a
 * brief grace window to drop locks / finish cleanup, then SIGKILL any
 * that ignored the request.  kill_pid() itself is SIGKILL-only by
 * contract, so stage 1 uses kill(pid, SIGTERM) directly; stage 3
 * routes through kill_pid() to inherit its mainpid / pid_is_valid
 * safety guards.  Slot pids are re-read on every pass because the
 * main reaper races us.
 */
#define CANARY_SIGTERM_GRACE_ITERS	20
#define CANARY_SIGTERM_GRACE_USLEEP	1000

void kill_canary_slot_children(void)
{
	unsigned int i, iter;
	unsigned int n = canary_slots;

	if (n > max_children)
		n = max_children;

	/* Shutdown stage 1: request graceful exit. */
	for (i = 0; i < n; i++) {
		pid_t pid = __atomic_load_n(&pids[i], __ATOMIC_ACQUIRE);

		if (pid == EMPTY_PIDSLOT || pid <= 0)
			continue;
		if (pid == mainpid)
			continue;
		kill(pid, SIGTERM);
	}

	/* Shutdown stage 2: ~20 ms grace window, polling for liveness only.  We
	 * must NOT waitpid() the canary child here -- the parent's main
	 * reaper owns that path and is what updates pids[]/running_childs
	 * via reap_child().  A self-reap in this loop would race the main
	 * reaper, which then sees ECHILD and leaves the slot parked in
	 * the deferred-recovery window for ~30-40s.  kill(pid, 0) treats
	 * a not-yet-reaped zombie as still alive, which is exactly what
	 * we want: we keep waiting until the main reaper has fully torn
	 * the task down. */
	for (iter = 0; iter < CANARY_SIGTERM_GRACE_ITERS; iter++) {
		bool any_alive = false;

		for (i = 0; i < n; i++) {
			pid_t pid = __atomic_load_n(&pids[i], __ATOMIC_ACQUIRE);

			if (pid == EMPTY_PIDSLOT || pid <= 0)
				continue;
			if (kill(pid, 0) == -1 && errno == ESRCH)
				continue;
			any_alive = true;
		}
		if (!any_alive)
			return;
		usleep(CANARY_SIGTERM_GRACE_USLEEP);
	}

	/* Shutdown stage 3: SIGKILL anything still alive. */
	for (i = 0; i < n; i++) {
		pid_t pid = __atomic_load_n(&pids[i], __ATOMIC_ACQUIRE);

		if (pid != EMPTY_PIDSLOT && pid > 0)
			kill_pid(pid);
	}
}
