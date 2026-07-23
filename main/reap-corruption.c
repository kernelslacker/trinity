#include <stdbool.h>

#include "child.h"
#include "debug.h"
#include "params.h"
#include "pids.h"
#include "shm.h"
#include "stats.h"
#include "stats_ring.h"
#include "trinity.h"
#include "utils.h"
#include "main-internal.h"

/*
 * Make sure various entries in the shm look sensible.
 * We use this to make sure that random syscalls haven't corrupted it.
 *
 * also check the pids for sanity.
 */
int shm_is_corrupt(void)
{
	unsigned int i;

	/* Both op_count and previous_op_count are now parent-private (live
	 * in the stats_aggregate, not in shm).  A wild kernel write through
	 * a child syscall arg cannot reach either field, so this regression
	 * check no longer fires for that scribble class.  Kept as defence
	 * in depth: it still trips on a parent-side bug that decrements
	 * op_count or on a stale read of either field, both of which would
	 * be real corruption signals. */
	unsigned long current_previous_op_count = parent_stats.previous_op_count;
	unsigned long current_op_count = parent_stats.op_count;

	if (current_op_count < current_previous_op_count) {
		output(0, "Execcount went backwards! (old:%lu new:%lu):\n",
			current_previous_op_count, current_op_count);
		dump_pids_page_state();
		panic(EXIT_SHM_CORRUPTION);
		return true;
	}
	parent_stats.previous_op_count = current_op_count;

	/* Mirror page integrity check: stats_publish_locked() in the
	 * parent's drain wrote parent_stats.op_count into
	 * shm_published->fleet_op_count, and each child has the page
	 * mprotected PROT_READ in its own address space via the
	 * stats_published_freeze() called from init_child().  A read-back
	 * here that disagrees with the canonical aggregate means somebody
	 * found a write window (a freeze gap before the per-child mprotect
	 * lands, or somehow a wild write succeeded against the read-only
	 * mapping in a child).  Log + bump rather than panic -- the
	 * canonical value is still trustworthy. */
	if (shm_published != NULL) {
		unsigned long mirror =
			__atomic_load_n(&shm_published->fleet_op_count,
					__ATOMIC_RELAXED);
		if (mirror != current_op_count) {
			output(0, "shm_published mirror: fleet_op_count=%lu, "
				  "aggregate=%lu (mirror scribbled?)\n",
				  mirror, current_op_count);
			parent_stats.shm_published_corrupt++;
		}
	}

	for_each_child(i) {
		struct childdata *child;
		pid_t pid;

		if (children == NULL)
			return true;

		child = __atomic_load_n(&children[i], __ATOMIC_ACQUIRE);
		pid = __atomic_load_n(&pids[i], __ATOMIC_RELAXED);
		if (child == NULL)
			continue;
		if (pid == EMPTY_PIDSLOT)
			continue;

		if (pid_is_valid(pid) == false) {
			static bool once = false;

			if (once != false)
				return true;

			output(0, "Sanity check failed! Found pid %d at pidslot %u!\n", pid, i);

			dump_childnos();
			dump_pids_page_state();

			if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) == STILL_RUNNING)
				panic(EXIT_PID_OUT_OF_RANGE);
			dump_childdata(child);
			once = true;
			return true;
		}
	}

	return false;
}
