#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/types.h>
#include <unistd.h>

#include "self_cgroup.h"
#include "trinity.h"
#include "utils.h"

#include "self-cgroup-internal.h"

/*
 * Phase 2: memory.events back-pressure.
 *
 * The Phase 1 cap is reactive: when memory.max is hit the kernel evicts
 * trinity processes, dropping bandit convergence state every cycle.
 * Phase 2 listens to the kernel's memory.events file (rewritten each
 * time low/high/max/oom counters bump) and applies back-pressure
 * before the cap is reached: a doubling fork-rate throttle on
 * memory.high crossings.
 *
 * In split mode the watcher attaches to children/memory.events — that's
 * where the workload's memory pressure shows up.  memory.max crossings
 * are tracked for diagnostics only: with children/memory.oom.group=1 the
 * kernel kills the entire worker pool atomically when the cap fires, the
 * parent re-spawns from a clean state, and any userspace shed-on-top
 * would just race the kernel.
 *
 * The watch is parent-only.  Inotify on cgroupfs delivers IN_MODIFY
 * each time the kernel rewrites memory.events; the parent drains those
 * notifications from its main_loop tick (~25ms cadence at the busiest)
 * and re-reads the file to compare counts against the last snapshot.
 *
 * Failure paths (inotify_init1 EMFILE, watch add denied, file open
 * denied) all degrade silently: the kernel will still scope the OOM kill
 * to children/, just without the proactive throttle.
 */

unsigned int fork_throttle_us;

#define THROTTLE_MIN_US		1000U		/* 1 ms initial step */
#define THROTTLE_MAX_US		1000000U	/* 1 s cap under sustained pressure */
#define THROTTLE_DECAY_TICKS	40U		/* ~1s of quiet at 25ms cadence */

/*
 * The cap and the decay schedule together set how aggressively we back
 * off respawn under memory.high reclaim-throttle pressure.
 *
 *   Cap (THROTTLE_MAX_US = 1 s):
 *     A small cap (e.g. 100 ms) lets per-spawn sleep slow the fork rate
 *     but not enough to keep up with the kernel's reclaim throttle once
 *     children/ memory is sitting at the soft limit.  Each fresh child
 *     immediately hits the same reclaim slowdown in its post-syscall
 *     userspace path, the parent watchdog times it out, kills, respawns
 *     -- positive feedback into a death spiral.  Capping at 1 s gives
 *     the parent room to genuinely pause spawning so the cgroup's
 *     reclaim drains before the next worker lands on it.
 *
 *   Decay (halving per quiet window, not snap-to-zero):
 *     A binary "any quiet window resets the throttle to 0" decay
 *     re-ignites the spiral: pressure subsides briefly, throttle snaps
 *     off, spawn rate slams back to full, pressure returns immediately.
 *     Halving lets the throttle decay over several windows so a transient
 *     dip in memory.high firings doesn't undo the prior backoff.
 */

static int events_inotify_fd = -1;
static int events_file_fd = -1;
static unsigned long last_high_count;
static unsigned long last_max_count;
static unsigned int high_event_seq;
static unsigned int max_event_seq;
static unsigned int quiet_streak;

/*
 * Re-read the cgroup memory.events file (rewritten in place by the
 * kernel) and pull out the high and max counters.  The file is small
 * (~96 bytes) and uses a stable "key value\n" format documented in
 * cgroup-v2.rst.  Counters increase monotonically across the cgroup's
 * lifetime, so a delta against the prior snapshot is the new-event
 * count for that counter.
 */
static bool read_event_counts(unsigned long *high_out, unsigned long *max_out)
{
	char buf[512];
	ssize_t n;
	char *line, *save = NULL;
	unsigned long high = 0, max = 0;

	if (events_file_fd < 0)
		return false;
	if (lseek(events_file_fd, 0, SEEK_SET) == (off_t)-1)
		return false;
	n = read(events_file_fd, buf, sizeof(buf) - 1);
	if (n <= 0)
		return false;
	buf[n] = '\0';
	for (line = strtok_r(buf, "\n", &save); line != NULL;
	     line = strtok_r(NULL, "\n", &save)) {
		unsigned long v;

		if (sscanf(line, "high %lu", &v) == 1)
			high = v;
		else if (sscanf(line, "max %lu", &v) == 1)
			max = v;
	}
	*high_out = high;
	*max_out = max;
	return true;
}

void events_setup(void)
{
	char path[PATH_MAX];

	if (cg_workload == NULL)
		return;

	if ((size_t)snprintf(path, sizeof(path), "%s/memory.events",
			     cg_workload) >= sizeof(path))
		return;

	events_inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	if (events_inotify_fd < 0) {
		outputerr("self-cgroup: inotify_init1 failed: %s; "
			  "memory.events watcher disabled\n",
			  strerror(errno));
		return;
	}

	if (inotify_add_watch(events_inotify_fd, path, IN_MODIFY) < 0) {
		outputerr("self-cgroup: inotify_add_watch(%s) failed: %s; "
			  "memory.events watcher disabled\n",
			  path, strerror(errno));
		close(events_inotify_fd);
		events_inotify_fd = -1;
		return;
	}

	events_file_fd = open(path, O_RDONLY | O_CLOEXEC);
	if (events_file_fd < 0) {
		outputerr("self-cgroup: open(%s) failed: %s; "
			  "memory.events watcher disabled\n",
			  path, strerror(errno));
		close(events_inotify_fd);
		events_inotify_fd = -1;
		return;
	}

	/* Seed the prior-snapshot so a fresh cgroup with non-zero
	 * counters from a previous tenant (shouldn't happen for a
	 * trinity-<pid> dir we just mkdir'd, but be defensive) doesn't
	 * trigger a phantom event on the first tick. */
	read_event_counts(&last_high_count, &last_max_count);

	output(0, "self-cgroup: memory.events watcher armed on %s\n", path);
}

void events_cleanup(void)
{
	if (events_file_fd >= 0) {
		close(events_file_fd);
		events_file_fd = -1;
	}
	if (events_inotify_fd >= 0) {
		close(events_inotify_fd);
		events_inotify_fd = -1;
	}
}

void self_cgroup_drop_fds_in_child(void)
{
	if (events_file_fd >= 0) {
		close(events_file_fd);
		events_file_fd = -1;
	}
	if (events_inotify_fd >= 0) {
		close(events_inotify_fd);
		events_inotify_fd = -1;
	}
	/* The workload-cgroup dirfd is parent-only: the parent uses it for
	 * clone3(CLONE_INTO_CGROUP) (and openat-on-cgroup.procs in the
	 * post-migrate fallback) before the child reaches this hook, and
	 * nothing in the child path needs it.  Leaving it inherited lets a
	 * fuzzed dup2 redirect future spawns into the wrong cgroup
	 * (escaping memory.max + oom.group containment) or a fuzzed close
	 * turn the next spawn into EBADF. */
	if (cg_workload_fd >= 0) {
		close(cg_workload_fd);
		cg_workload_fd = -1;
	}
}

void self_cgroup_events_check(void)
{
	char drain[4096];
	bool any_event = false;
	unsigned long high, max;

	if (events_inotify_fd < 0)
		return;

	/* Re-assert O_NONBLOCK before the drain.  A fuzzed
	 * fcntl(fd, F_SETFL, ...) in a pre-fd-drop child (or any other
	 * path that touches the shared OFD) can clear O_NONBLOCK on the
	 * description we set at inotify_init1(IN_NONBLOCK) time.  Without
	 * this re-assert the read() below blocks forever on an empty queue
	 * and the main loop wedges. */
	{
		int fl = fcntl(events_inotify_fd, F_GETFL);

		if (fl >= 0 && !(fl & O_NONBLOCK))
			(void) fcntl(events_inotify_fd, F_SETFL,
				     fl | O_NONBLOCK);
	}

	/* Drain the inotify queue.  We don't care which event fired
	 * (memory.events only carries IN_MODIFY for us) — only that
	 * something fired.  EAGAIN on the trailing call is the normal
	 * empty-queue signal under O_NONBLOCK. */
	while (read(events_inotify_fd, drain, sizeof(drain)) > 0)
		any_event = true;

	if (!any_event) {
		if (fork_throttle_us > 0 &&
		    ++quiet_streak >= THROTTLE_DECAY_TICKS) {
			unsigned int halved = fork_throttle_us / 2;

			if (halved < THROTTLE_MIN_US)
				halved = 0;
			if (halved == 0)
				output(0, "self-cgroup: HIGH cleared -- fork throttle off\n");
			else
				output(0, "self-cgroup: HIGH quiet -- fork throttle halved to %uus\n",
				       halved);
			fork_throttle_us = halved;
			quiet_streak = 0;
		}
		return;
	}

	quiet_streak = 0;

	if (!read_event_counts(&high, &max))
		return;

	if (high > last_high_count) {
		unsigned int next;

		last_high_count = high;
		high_event_seq++;
		if (fork_throttle_us == 0)
			next = THROTTLE_MIN_US;
		else if (fork_throttle_us >= THROTTLE_MAX_US / 2)
			next = THROTTLE_MAX_US;
		else
			next = fork_throttle_us * 2;
		fork_throttle_us = next;
		output(0, "self-cgroup: HIGH event #%u -- fork throttle now %uus\n",
		       high_event_seq, fork_throttle_us);
	}

	/*
	 * memory.events:max means the kernel has already OOM-killed in the
	 * children/ cgroup.  With memory.oom.group=1 the kill takes the
	 * whole worker pool atomically and the parent (which lives in the
	 * sibling parent/ cgroup with no memory.max) survives untouched —
	 * the existing reap loop in main_loop sees all the SIGCHLDs and
	 * re-spawns the pool from scratch.  No userspace shed required.
	 * The HIGH-event-driven fork throttle above gives back-pressure
	 * before max events fire in the first place.
	 */
	if (max > last_max_count) {
		unsigned long delta = max - last_max_count;

		last_max_count = max;
		max_event_seq++;
		output(0, "self-cgroup: MAX event #%u (delta=%lu) -- "
		       "kernel %s; parent re-spawns worker pool\n",
		       max_event_seq, delta,
		       cg_split_mode ? "group-killed children cgroup atomically"
				     : "OOM-killed in single-cgroup mode");
	}
}
