#include <errno.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>

#include "child.h"
#include "debug.h"
#include "pids.h"
#include "shm.h"
#include "stats.h"
#include "syscall.h"
#include "sysv-msg.h"
#include "sysv-sem.h"
#include "sysv-shm.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"
#include "main-internal.h"
#include "reap-internal.h"

/*
 * Parent-local tracking of slots whose former occupant is in the kernel
 * as an unkillable D-state task.  We have already cleared the pid slot
 * (via reap_child), but the kernel may still wake the task to finish its
 * syscall and let it write back into our shared childdata.  If we hand
 * the slot to a freshly-forked replacement child before the kernel has
 * fully torn the zombie down, those late writes corrupt fields the new
 * child owns (tp, fd_event_ring head/tail, etc.).
 *
 * One observed corruption case traces back to exactly this race:
 * fd_event_ring contents containing a non-canonical pointer
 * 0x9c000000890000 that segfaulted fd_event_drain — a half-written
 * ring index from a ghost producer that no longer existed by the time
 * the parent looked.
 *
 * zombie_pids[childno] holds the pid we are still waiting on, or
 * EMPTY_PIDSLOT if the slot is not in zombie-pending state.
 * zombie_since[childno] is the CLOCK_MONOTONIC second at which we
 * registered the zombie, used to bound the wait.
 */
pid_t *zombie_pids;
time_t *zombie_since;

/* If the kernel still hasn't released a zombie task after this long,
 * something is badly wrong (likely a kernel bug worth investigating).
 * We log loudly and reuse the slot anyway, accepting a possible
 * one-shot corruption in exchange for not stalling fuzzing forever. */
#define ZOMBIE_REAP_TIMEOUT_SEC 300

/*
 * Move a slot into zombie-pending state.  The child is unkillable
 * (D-state) and we have given up trying to make it die, but the kernel
 * still owns the task struct and may run it again.  Clear the slot so
 * stats stay sensible, but do NOT spawn a replacement: we have to wait
 * until waitpid confirms the kernel released the task, otherwise the
 * zombie's last writes will land in the replacement child's childdata.
 */
void register_zombie_slot(int childno, pid_t pid)
{
	struct timespec now;
	pid_t wpid;

	/*
	 * Catch the silent-leak shape directly: re-registering an
	 * already-zombie slot would overwrite zombie_pids[childno] and
	 * leave the prior pid waiting on a waitpid() nobody runs any
	 * more, while zombie_slots_pending double-counts.  The slot
	 * stays parked in zombie-pending state forever and the kernel's
	 * task struct is never released.  pids[childno] is cleared by
	 * reap_child() before we get here, so no fresh signal/death
	 * event can target the slot until process_zombie_pending()
	 * clears zombie_pids[childno] -- a non-empty value at entry is
	 * a state-machine violation, not a legitimate race.
	 */
	BUG_ON(zombie_pids[childno] != EMPTY_PIDSLOT);

	/* Fast path: it's not uncommon for the kernel to release a
	 * transient D-state task between our kill loop giving up and
	 * us reaching this function.  A non-blocking waitpid here
	 * tells us if the task is already gone — if so, skip the whole
	 * deferral machinery and just reap+replace immediately and
	 * silently.  Saves the unkillable-log + stack/syscall dump +
	 * zombie_pids[] bookkeeping that would otherwise fire and then
	 * unwind on the very next process_zombie_pending() pass. */
	wpid = waitpid_eintr(pid, NULL, WNOHANG);
	if (wpid == pid || (wpid == -1 && errno == ECHILD)) {
		if (pidstatfiles[childno] >= 0) {
			close(pidstatfiles[childno]);
			pidstatfiles[childno] = -1;
		}
		reap_child(children[childno], childno, true);
		replace_child(childno);
		__atomic_add_fetch(&shm->stats.zombie_reaper.reaped, 1,
				   __ATOMIC_RELAXED);
		return;
	}

	{
		struct syscallrecord *rec = &children[childno]->syscall;
		struct syscallentry *entry;
		unsigned int nr = rec->nr;
		bool do32 = rec->do32bit;
		const char *name;

		entry = get_syscall_entry(nr, do32);
		name = (entry != NULL) ? entry->name : "?";

		output(0, "child %d (pid %u) unkillable in nr=%u (%s)%s, "
			"deferring slot reuse until kernel releases the "
			"D-state task.\n",
			childno, pid, nr, name, do32 ? " (32bit)" : "");
	}

	/* /proc/$pid/stack and /proc/$pid/syscall reads can block for up
	 * to ~12s waiting on the kernel when the task is wedged in D-state.
	 * The parent main loop is single-threaded, so a stall here halves
	 * the fleet iter rate for the rest of the 10k-iter window.  Gate
	 * these diagnostics on shm->debug, matching stuck_syscall_info().
	 */
	if (shm->debug == true) {
		dump_pid_stack(pid);
		dump_pid_syscall(pid);
	}

	if (pidstatfiles[childno] >= 0) {
		close(pidstatfiles[childno]);
		pidstatfiles[childno] = -1;
	}

	/* Child still alive here (D-state / stopped / signaled-but-running):
	 * the WNOHANG waitpid above returned 0.  Pass child_dead=false so the
	 * shm-ring drain is deferred to process_zombie_pending(); everything
	 * else reap_child() does is safe to run against the frozen slot now. */
	reap_child(children[childno], childno, false);

	clock_gettime(CLOCK_MONOTONIC, &now);
	zombie_pids[childno] = pid;
	zombie_since[childno] = now.tv_sec;
	__atomic_add_fetch(&shm->stats.zombie_reaper.slots_pending, 1, __ATOMIC_RELAXED);
}

/*
 * Walk the zombie-pending slots and try to retire each one.
 * waitpid(WNOHANG) returns the pid once the kernel has fully torn down
 * the task — at that point no further writes to the slot are possible
 * and we can safely spawn a replacement.  If the wait times out
 * (ZOMBIE_REAP_TIMEOUT_SEC), log loudly and reuse the slot anyway:
 * indefinite throughput loss is worse than one possible corruption.
 */
void process_zombie_pending(void)
{
	struct timespec now;
	unsigned int i;

	if (zombie_pids == NULL)
		return;

	if (__atomic_load_n(&shm->stats.zombie_reaper.slots_pending,
			    __ATOMIC_RELAXED) == 0)
		return;

	clock_gettime(CLOCK_MONOTONIC, &now);

	for_each_child(i) {
		pid_t pid = zombie_pids[i];
		pid_t wpid;
		bool retire = false;
		bool timed_out = false;

		if (pid == EMPTY_PIDSLOT)
			continue;

		wpid = waitpid_eintr(pid, NULL, WNOHANG);
		if (wpid == pid) {
			retire = true;
		} else if (wpid == -1 && errno == ECHILD) {
			/* Kernel has no record of this pid as our child
			 * — it's gone (already reaped or never existed in
			 * a way we can wait on).  Safe to reuse the slot. */
			retire = true;
		} else if ((now.tv_sec - zombie_since[i]) >= ZOMBIE_REAP_TIMEOUT_SEC) {
			retire = true;
			timed_out = true;
		}

		if (!retire)
			continue;

		if (timed_out) {
			struct childdata *child =
				__atomic_load_n(&children[i], __ATOMIC_ACQUIRE);
			bool from_bug = (child != NULL &&
				__atomic_load_n(&child->hit_bug, __ATOMIC_ACQUIRE));

			if (from_bug) {
				output(0, "child %d zombie (pid %u) still pending "
					"after %d seconds — child hit __BUG() "
					"(\"%s\" at %s:%u) and exited; kernel is "
					"finishing the SIGKILL teardown. Not a "
					"kernel bug.\n",
					i, pid, ZOMBIE_REAP_TIMEOUT_SEC,
					child->bug_text ? child->bug_text : "?",
					child->bug_func ? child->bug_func : "?",
					child->bug_lineno);
			} else {
				output(0, "child %d zombie (pid %u) still pending "
					"after %d seconds — forcing slot reuse. "
					"Possible causes: a D-state task in the "
					"kernel finishing a cancelled syscall, or "
					"a real kernel bug holding the task table "
					"entry.\n",
					i, pid, ZOMBIE_REAP_TIMEOUT_SEC);
			}
			__atomic_add_fetch(&shm->stats.zombie_reaper.timed_out, 1,
					   __ATOMIC_RELAXED);
		} else {
			long elapsed = (long)(now.tv_sec - zombie_since[i]);
			/* Only report when the kernel actually held the
			 * zombie around long enough to be operationally
			 * interesting.  Sub-second hold times are normal
			 * when the D-state was transient and the kernel
			 * reaped between our kill loop giving up and the
			 * next process_zombie_pending() pass — silent
			 * stats counter is enough. */
			if (elapsed >= 1)
				output(0, "child %d zombie (pid %u) finally "
					"released by kernel after %ld seconds; "
					"reusing slot.\n", i, pid, elapsed);
			__atomic_add_fetch(&shm->stats.zombie_reaper.reaped, 1,
					   __ATOMIC_RELAXED);
		}

		zombie_pids[i] = EMPTY_PIDSLOT;
		zombie_since[i] = 0;
		__atomic_sub_fetch(&shm->stats.zombie_reaper.slots_pending, 1,
				   __ATOMIC_RELAXED);

		/* Deferred child is now confirmed gone (waitpid above, or the
		 * long-stuck timeout).  reap_child() at the deferral point ran
		 * with child_dead=false, so drain its fuzzed shm ring here --
		 * before replace_child() recycles the slot and clean_childdata()
		 * zeroes the count. */
		reap_child_sysv_shm(children[i]);
		reap_child_sysv_msg(children[i]);
		reap_child_sysv_sem(children[i]);

		replace_child(i);
	}
}

/*
 * Pick a slot for a freshly-forked child.  A slot is only usable when
 * BOTH the live-pid slot and the zombie-pending slot are empty: a
 * pids[i] == EMPTY_PIDSLOT alone does not mean the kernel has finished
 * tearing down the previous occupant.  If the previous occupant is
 * still in the kernel as a D-state task, handing the slot to a new
 * child lets the dying task's late writes corrupt the new child's
 * childdata (same race shape documented at the top of this file).
 *
 * Returns CHILD_NOT_FOUND when no slot is available; the caller
 * decides whether that means "pid map exhausted" (fatal) or "all empty
 * slots are zombie-pending" (transient, retry once
 * process_zombie_pending() has run).
 */
int find_free_childno(void)
{
	unsigned int i;

	for_each_child(i) {
		if (__atomic_load_n(&pids[i], __ATOMIC_RELAXED) != EMPTY_PIDSLOT)
			continue;
		if (zombie_pids[i] != EMPTY_PIDSLOT)
			continue;
		return i;
	}
	return CHILD_NOT_FOUND;
}
