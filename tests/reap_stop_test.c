/*
 * Self-check for the reaper's handling of a stopped child (main/reap.c).
 * The reaper asks kill_pid() to kill it and parks its slot for the
 * zombie reaper (main/reap-zombie.c); it must not report it as a
 * D-state task the kernel will not let go of.
 */

#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "debug.h"		/* BUG */
#include "main-internal.h"
#include "pids.h"
#include "shm.h"

#include "fake_parent.h"

/* @slot's child stops itself with @sig.  handle_children() must ask
 * kill_pid() to kill it and park the slot until the task is gone, and
 * must log it as stopped: not as a D-state task, and not as killed. */
static void stopped_child_is_killed(int sig, unsigned int slot)
{
	siginfo_t si;
	pid_t pid;

	fake_parent_reset();
	pid = fake_hold_task(sig);
	/* WNOWAIT leaves the stop for handle_children() to collect.  The
	 * alarm turns a stop that never comes into a failure, not a hang. */
	alarm(10);
	if (waitid(P_PID, pid, &si, WSTOPPED | WNOWAIT) != 0)
		BUG("reap stop: the held task did not stop");
	alarm(0);
	pids[slot] = pid;
	shm->running_childs = 1;

	handle_children();

	if (fake_killed_pid != pid)
		BUG("reap stop: a stopped child was not killed");
	if (pids[slot] != EMPTY_PIDSLOT || zombie_pids[slot] != pid)
		BUG("reap stop: a stopped child's slot was not parked");
	if (strstr(fake_output_log, "unkillable") != NULL ||
	    strstr(fake_output_log, "D-state") != NULL)
		BUG("reap stop: a stopped child was logged as a D-state task");
	if (strstr(fake_output_log, "stopped") == NULL)
		BUG("reap stop: a stopped child was not logged as stopped");
	/* kill_pid() can withhold the kill, as this fake one always does,
	 * so the line must not say the child was killed. */
	if (strstr(fake_output_log, "killed") != NULL)
		BUG("reap stop: a stopped child was logged as killed");

	/* The fake kill_pid() sends nothing: end the task here, and the
	 * zombie reaper must put the slot back into service. */
	if (kill(pid, SIGKILL) != 0 ||
	    waitid(P_PID, pid, &si, WEXITED | WNOWAIT) != 0)
		BUG("reap stop: cannot end the held task");
	process_zombie_pending();

	if (zombie_pids[slot] != EMPTY_PIDSLOT ||
	    fake_slot_log[slot].replaced != 1 ||
	    live_child_slots != FAKE_NR_CHILDREN)
		BUG("reap stop: a stopped child's slot did not return to service");
}

void reap_stop_self_check(void);
void reap_stop_self_check(void)
{
	stopped_child_is_killed(SIGSTOP, 2);
	/* A job-control stop, which can only catch a child that has not
	 * reached its setsid() yet. */
	stopped_child_is_killed(SIGTSTP, 4);
}
