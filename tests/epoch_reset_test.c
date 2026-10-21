/*
 * Self-check for reset_epoch_state() (main/loop.c) against the parked
 * slot lifecycle in main/reap-zombie.c.  A zombie-pending slot must come
 * out of an epoch reset still parked: nothing at the boundary proves its
 * task is gone.  Forked children held in pause() stand in for tasks the
 * kernel has not released.
 */

#include <signal.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "debug.h"		/* BUG */
#include "main-internal.h"
#include "pids.h"
#include "shm.h"
#include "trinity.h"		/* reset_epoch_state */
#include "utils.h"		/* waitpid_eintr */

#include "fake_parent.h"

/* A task that stays alive until killed, and dies with the test. */
static pid_t hold_task(void)
{
	pid_t parent = getpid();
	pid_t pid = fork();

	if (pid < 0)
		BUG("epoch reset: fork failed");
	if (pid == 0) {
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		if (getppid() == parent) {
			for (;;)
				pause();
		}
		_exit(0);
	}
	return pid;
}

/* Park @slot the way park_surviving_children() does at shutdown. */
static pid_t park_slot(unsigned int slot)
{
	pid_t pid = hold_task();

	register_zombie_slot(slot, pid);
	if (zombie_pids[slot] != pid)
		BUG("epoch reset: register_zombie_slot did not park the slot");
	return pid;
}

/* The reset reinitialised every slot but @parked, and a fresh child
 * cannot be given @parked. */
static void check_parked_through_reset(unsigned int parked)
{
	unsigned int i;

	for_each_child(i) {
		unsigned int want = (i == parked) ? 0 : 1;

		if (fake_slot_log[i].cleaned != want ||
		    fake_slot_log[i].ring_reset != want)
			BUG("epoch reset: reinitialised the wrong slots");
		if (i != parked)
			pids[i] = getpid();
	}
	if (find_free_childno() != CHILD_NOT_FOUND)
		BUG("epoch reset: a parked slot is free for a fresh child");
	for_each_child(i)
		pids[i] = EMPTY_PIDSLOT;
}

/* process_zombie_pending() finished @slot's deferred reap: bug-log
 * classification with the parked pid, the SysV drains, the refill,
 * and release of the slot. */
static void check_deferred_reap(unsigned int slot, pid_t pid)
{
	if (fake_slot_log[slot].classified_pid != pid ||
	    fake_slot_log[slot].sysv_drained != 3 ||
	    fake_slot_log[slot].replaced != 1)
		BUG("epoch reset: a carried-over slot skipped its deferred reap");
	if (zombie_pids[slot] != EMPTY_PIDSLOT ||
	    shm->stats.zombie_reaper.slots_pending != 0)
		BUG("epoch reset: a reaped slot was not released");
}

/* A slot parked at shutdown keeps its deferred reap into the next
 * epoch, here through the waitpid(pid) that process_zombie_pending()
 * issues itself. */
static void zombie_pending_survives_reset(void)
{
	siginfo_t si;
	time_t since;
	pid_t pid;

	fake_parent_reset();
	pid = park_slot(3);
	since = zombie_since[3];

	/* A stray child write to the gauge; left at 0 it would stop
	 * process_zombie_pending() from ever walking the slots. */
	shm->stats.zombie_reaper.slots_pending = 0;

	reset_epoch_state();

	if (zombie_pids[3] != pid || zombie_since[3] != since)
		BUG("epoch reset: a zombie-pending slot was recycled");
	if (shm->stats.zombie_reaper.slots_pending != 1)
		BUG("epoch reset: slots_pending disagrees with zombie_pids[]");
	check_parked_through_reset(3);

	/* Exit without being reaped: process_zombie_pending() reaps it. */
	if (kill(pid, SIGKILL) != 0 ||
	    waitid(P_PID, pid, &si, WEXITED | WNOWAIT) != 0)
		BUG("epoch reset: cannot release the held task");
	process_zombie_pending();

	check_deferred_reap(3, pid);
}

/* The usual case next epoch: the waitpid(-1) drain in handle_children()
 * reaps the exited task as an untracked pid first, and
 * process_zombie_pending() must still retire the slot on ECHILD. */
static void carried_slot_reaped_by_drain(void)
{
	pid_t pid;

	fake_parent_reset();
	pid = park_slot(3);

	reset_epoch_state();

	kill(pid, SIGKILL);
	(void)waitpid_eintr(pid, NULL, 0);
	process_zombie_pending();

	check_deferred_reap(3, pid);
}

void epoch_reset_self_check(void);
void epoch_reset_self_check(void)
{
	zombie_pending_survives_reset();
	carried_slot_reaped_by_drain();
}
