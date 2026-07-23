/*
 * Periodic mid-run snapshot trigger.
 *
 * The save path itself is set in the parent before fork via
 * minicorpus_enable_snapshots() and inherited COW by every child.  All
 * children call minicorpus_maybe_snapshot() after each kcov edge event;
 * the function early-returns cheaply unless the fleet-wide edge count
 * has advanced MINICORPUS_SNAPSHOT_EDGES past the last snapshot's
 * high-water-mark.  When the gap is reached, a single CAS on
 * minicorpus_shm->edges_at_last_snapshot picks one caller as the saver
 * — it runs minicorpus_save_file() while everyone else loses the CAS
 * and returns.  The next snapshot opportunity opens once the next
 * MINICORPUS_SNAPSHOT_EDGES window has accumulated.
 */

#include <limits.h>
#include <string.h>

#include "kcov.h"
#include "minicorpus.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#include "minicorpus-internal.h"

static char snapshot_path[PATH_MAX];
static bool snapshot_enabled;

void minicorpus_enable_snapshots(const char *path)
{
	size_t len;

	if (path == NULL)
		return;
	len = strlen(path);
	if (len == 0 || len >= sizeof(snapshot_path))
		return;
	memcpy(snapshot_path, path, len + 1);
	snapshot_enabled = true;

	/* Anchor the monotonic floor to fuzz-start so the first time-trigger
	 * fires MINICORPUS_SNAPSHOT_INTERVAL_SEC after enable rather than
	 * immediately on the first child's first call against an empty
	 * corpus.  CLOCK_MONOTONIC seconds: a wall-clock backward step would
	 * starve the cadence (now_sec never reaches old_time + interval),
	 * and a forward step would fire a burst of snapshots.  Defensive
	 * shm guard mirrors minicorpus_maybe_snapshot(). */
	if (shm != NULL)
		__atomic_store_n(&shm->stats.minicorpus.last_snapshot_time,
				 (unsigned long)(mono_ns() / 1000000000ULL),
				 __ATOMIC_RELAXED);
}

void minicorpus_maybe_snapshot(void)
{
	unsigned long edges_now, old, new_edges;
	unsigned long now_sec, old_time;
	bool edges_trigger, time_trigger;

	if (!snapshot_enabled || minicorpus_shm == NULL ||
	    kcov_shm == NULL || shm == NULL)
		return;

	edges_now = __atomic_load_n(&kcov_shm->coverage.edges_found, __ATOMIC_RELAXED);
	old = __atomic_load_n(&minicorpus_shm->edges_at_last_snapshot,
			      __ATOMIC_RELAXED);
	old_time = __atomic_load_n(&shm->stats.minicorpus.last_snapshot_time,
				   __ATOMIC_RELAXED);
	now_sec = (unsigned long)(mono_ns() / 1000000000ULL);

	edges_trigger = (edges_now >= old + MINICORPUS_SNAPSHOT_EDGES);
	time_trigger = (now_sec >= old_time + MINICORPUS_SNAPSHOT_INTERVAL_SEC);

	if (!edges_trigger && !time_trigger)
		return;

	/* Race for the slot.  Whoever wins the CAS is responsible for the
	 * save; the others see the new high-water-mark on their next call
	 * and early-return.  RELAXED ordering is enough — the save itself
	 * is independently consistent (per-ring lock during read), and the
	 * counter is just gating who runs, not what they observe.
	 *
	 * When only the time trigger fires, edges_now may equal `old` (no
	 * new edges since the last snapshot, but 5min has elapsed), and a
	 * CAS of (old -> old) would succeed for every concurrent caller
	 * rather than electing one.  Force the new value to be strictly
	 * greater in that case so the CAS is a real change and contested
	 * calls actually serialise.  The +1 skew on the next edge-trigger
	 * boundary is irrelevant against a 10000-edge window. */
	new_edges = (edges_now > old) ? edges_now : old + 1;
	if (!__atomic_compare_exchange_n(&minicorpus_shm->edges_at_last_snapshot,
					 &old, new_edges,
					 false,
					 __ATOMIC_RELAXED, __ATOMIC_RELAXED))
		return;

	minicorpus_save_file(snapshot_path);

	/* Advance the wall-clock baseline so the next time-trigger window
	 * starts cleanly regardless of which trigger fired this time.  No
	 * CAS needed: the window-CAS above already elected us as the sole
	 * writer for this snapshot boundary. */
	__atomic_store_n(&shm->stats.minicorpus.last_snapshot_time, now_sec,
			 __ATOMIC_RELAXED);
}
