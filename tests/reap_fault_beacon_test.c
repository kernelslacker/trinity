/*
 * Self-check for the canary feed on a child's exit (main/reap.c).  A
 * child that faults without -D leaves through _exit(EXIT_SUCCESS), so
 * only its fault beacon says it crashed.  The reaper must feed the
 * canary queue from the beacon on that exit, once per crash like a
 * child killed by the signal, and keep the exit status clean.
 */

#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "child.h"		/* struct childdata */
#include "debug.h"		/* BUG */
#include "main-internal.h"
#include "pids.h"
#include "shm.h"
#include "utils-macros.h"	/* ARRAY_SIZE */

#include "fake_parent.h"

/* @slot's child has exited, with status 0 or killed by SIGKILL.  The
 * wait leaves the exit for handle_children() to collect, and the alarm
 * turns an exit that never comes into a failure, not a hang. */
static void occupy_with_ended_child(unsigned int slot, bool killed)
{
	siginfo_t si;
	pid_t pid = fork();

	if (pid < 0)
		BUG("reap fault beacon: fork failed");
	if (pid == 0) {
		if (killed)
			kill(getpid(), SIGKILL);
		_exit(EXIT_SUCCESS);
	}
	alarm(10);
	if (waitid(P_PID, pid, &si, WEXITED | WNOWAIT) != 0)
		BUG("reap fault beacon: the task did not end");
	alarm(0);
	pids[slot] = pid;
	shm->running_childs = 1;
}

/* What child_fault_handler() leaves in the shared childdata: the signal
 * first, then the release store that says it is there. */
static void stamp_beacon(unsigned int slot, int sig)
{
	children[slot]->fault_beacon.signo = sig;
	__atomic_store_n(&children[slot]->fault_beacon.written, 1U,
			 __ATOMIC_RELEASE);
}

static const int fault_signals[] = { SIGSEGV, SIGBUS, SIGILL, SIGABRT };

/* A child that faults and exits 0 reaches the reaper as a clean exit.
 * The canary queue must still hear its signal, and the beacon, which
 * reap_child() clears, must be read before that. */
static void faulted_child_is_fed_from_its_beacon(int sig)
{
	const unsigned int slot = 4;
	const struct fake_slot_log *log = &fake_slot_log[slot];

	fake_parent_reset();
	occupy_with_ended_child(slot, false);
	stamp_beacon(slot, sig);

	handle_children();

	if (log->canary_crashes != 1 || log->canary_signo != sig)
		BUG("reap fault beacon: a faulted child's clean exit did not feed the canary queue");
	if (log->reaps != 1 || !WIFEXITED(log->reap_status) ||
	    WEXITSTATUS(log->reap_status) != EXIT_SUCCESS)
		BUG("reap fault beacon: the fault changed the exit status the fast-die ring sees");
	if (pids[slot] != EMPTY_PIDSLOT ||
	    __atomic_load_n(&children[slot]->fault_beacon.written,
			    __ATOMIC_RELAXED) != 0)
		BUG("reap fault beacon: the slot was not reaped with its beacon cleared");
}

/* An ordinary clean exit leaves no beacon, and is no crash. */
static void clean_exit_is_not_fed(void)
{
	const unsigned int slot = 4;

	fake_parent_reset();
	occupy_with_ended_child(slot, false);

	handle_children();

	if (fake_slot_log[slot].canary_crashes != 0)
		BUG("reap fault beacon: a clean exit was fed to the canary queue");
	if (pids[slot] != EMPTY_PIDSLOT)
		BUG("reap fault beacon: a clean exit was not reaped");
}

/* With -D the handler stamps the beacon and then dies by the signal.
 * The beacon is on the exit path only: this crash is fed once, with the
 * signal the status carries. */
static void killed_child_is_fed_once(void)
{
	const unsigned int slot = 4;

	fake_parent_reset();
	occupy_with_ended_child(slot, true);
	stamp_beacon(slot, SIGSEGV);

	handle_children();

	if (fake_slot_log[slot].canary_crashes != 1 ||
	    fake_slot_log[slot].canary_signo != SIGKILL)
		BUG("reap fault beacon: a killed child was not fed once, by its status");
}

void reap_fault_beacon_self_check(void);
void reap_fault_beacon_self_check(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(fault_signals); i++)
		faulted_child_is_fed_from_its_beacon(fault_signals[i]);
	clean_exit_is_not_fed();
	killed_child_is_fed_once();

	/* Leave no stamped beacon or counts for later suites. */
	fake_parent_reset();
}
