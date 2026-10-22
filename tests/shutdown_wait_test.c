/*
 * Self-check for the shutdown wait (main/loop.c).  A task the kernel
 * will not release (D-state) never leaves the pid map, so after the
 * wait's bound wait_for_children_to_exit() hands every survivor to the
 * zombie reaper and returns.  Held tasks stand in for the children and
 * the fake clock runs the bound out at once.
 */

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "debug.h"		/* BUG */
#include "main-internal.h"
#include "pids.h"
#include "shm.h"
#include "utils.h"		/* waitpid_eintr */

#include "fake_parent.h"

/* The bound the wait documents, SHUTDOWN_WAIT_SECS in main/loop.c. */
#define SHUTDOWN_WAIT_SECS	30

/* A task that stays up, in @slot, as a running child. */
static pid_t occupy_slot(unsigned int slot)
{
	pid_t pid = fake_hold_task(0);

	pids[slot] = pid;
	shm->running_childs++;
	return pid;
}

static void end_task(pid_t pid)
{
	if (kill(pid, SIGKILL) != 0 || waitpid_eintr(pid, NULL, 0) != pid)
		BUG("shutdown wait: cannot end the held task");
}

static void check_parked(unsigned int slot, pid_t pid)
{
	char line[96];

	if (zombie_pids[slot] != pid || pids[slot] != EMPTY_PIDSLOT)
		BUG("shutdown wait: a stuck child's slot was not parked");
	snprintf(line, sizeof(line), "child %u (pid %d) did not exit within %us",
		 slot, pid, SHUTDOWN_WAIT_SECS);
	if (strstr(fake_output_log, line) == NULL)
		BUG("shutdown wait: a parked child was not reported");
}

/* Children that never leave: the wait runs out its bound, parks both
 * slots for the zombie reaper and returns, without calling it a
 * timeout. */
static void stuck_children_are_parked_at_the_bound(void)
{
	pid_t a, b;

	fake_parent_reset();
	fake_clock_start();
	a = occupy_slot(3);
	b = occupy_slot(7);

	wait_for_children_to_exit();

	if (fake_clock_elapsed_ns() != SHUTDOWN_WAIT_SECS * 1000000000ULL)
		BUG("shutdown wait: did not stop waiting at the bound");
	check_parked(3, a);
	check_parked(7, b);
	if (shm->running_childs != 0)
		BUG("shutdown wait: parking left the running count up");
	if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) != STILL_RUNNING)
		BUG("shutdown wait: parked children were put down as a timeout");

	end_task(a);
	end_task(b);
}

static pid_t dying_pid;

/* Five seconds in, the task dies, as a SIGKILLed one does once the
 * kernel gets to it.  WNOWAIT leaves the exit for the wait to collect. */
static void kill_dying_task(void)
{
	siginfo_t si;

	if (fake_sleeps != 5)
		return;
	if (kill(dying_pid, SIGKILL) != 0 ||
	    waitid(P_PID, dying_pid, &si, WEXITED | WNOWAIT) != 0)
		BUG("shutdown wait: cannot end the held task");
}

/* A child that goes inside the bound is reaped the usual way: the wait
 * does not give up on it early. */
static void child_that_exits_in_time_is_reaped(void)
{
	fake_parent_reset();
	fake_clock_start();
	dying_pid = occupy_slot(5);
	fake_sleep_hook = kill_dying_task;

	wait_for_children_to_exit();

	if (zombie_pids[5] != EMPTY_PIDSLOT ||
	    strstr(fake_output_log, "did not exit within") != NULL)
		BUG("shutdown wait: parked a child that exited inside the bound");
	if (pids[5] != EMPTY_PIDSLOT || shm->running_childs != 0)
		BUG("shutdown wait: did not reap a child that exited");
	if (fake_clock_elapsed_ns() >= SHUTDOWN_WAIT_SECS * 1000000000ULL)
		BUG("shutdown wait: kept waiting after the child exited");
}

void shutdown_wait_self_check(void);
void shutdown_wait_self_check(void)
{
	stuck_children_are_parked_at_the_bound();
	child_that_exits_in_time_is_reaped();

	/* Stop the fake clock and clear the exit state for later suites. */
	fake_parent_reset();
}
