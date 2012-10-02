#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

#include "trinity.h"
#include "shm.h"
#include "files.h"
#include "syscall.h"

void init_watchdog()
{
	pid_t pid;

	fflush(stdout);
	pid = fork();

	if (pid == 0)
		watchdog();     // Never returns.

	while (shm->watchdog_pid == 0)
		sleep(0.1);

	output("[%d] Started watchdog thread %d\n", getpid(), shm->watchdog_pid);
}

static int check_shm_sanity(void)
{
	unsigned int i;
	pid_t pid;

	for (i = 0; i < shm->max_children; i++) {
		pid = shm->pids[i];
		if (pid == EMPTY_PIDSLOT)
			continue;

		if (pid_is_valid(pid) == FALSE) {
			shm->exit_reason = EXIT_PID_OUT_OF_RANGE;
			return SHM_CORRUPT;
		}
	}

	// FIXME: The '500000' is magic, and should be dynamically calculated.
	// On startup, we should figure out how many getpid()'s per second we can do,
	// and use that.
	if (shm->execcount - shm->previous_count > 500000) {
		output("Execcount increased dramatically! (old:%ld new:%ld):\n",
			shm->previous_count, shm->execcount);
		shm->exit_reason = EXIT_SHM_CORRUPTION;
	}
	shm->previous_count = shm->execcount;

	return SHM_OK;
}

static void check_children(void)
{
	struct timeval tv;
	time_t diff;
	time_t old, now;
	pid_t pid;
	unsigned int i;

	gettimeofday(&tv, NULL);
	now = tv.tv_sec;

	for (i = 0; i < shm->max_children; i++) {
		pid = shm->pids[i];

		if (pid == EMPTY_PIDSLOT)
			continue;

		/* first things first, does the pid still exist ? */
		if (getpgid(pid) == -1) {
			if (errno == ESRCH) {
				output("pid %d has disappeared (oom-killed maybe?). Reaping.\n", pid);
				reap_child(pid);
			} else {
				output("problem running getpgid on pid %d (%d:%s)\n", pid, errno, strerror(errno));
			}
			continue;
		}

		old = shm->tv[i].tv_sec;

		if (old == 0)
			continue;

		/* if we wrapped, just reset it, we'll pick it up next time around. */
		if (old > now) {
			printf("child %d wrapped! old=%ld now=%ld\n", i, old, now);
			shm->tv[i].tv_sec = now;
			continue;
		}

		diff = now - old;

		/* if we're way off, we're comparing garbage. Reset it. */
		if (diff > 1000) {
			output("huge delta! pid slot %d [%d]: old:%ld now:%ld diff:%d.  Setting to now.\n", i, pid, old, now, diff);
			shm->tv[i].tv_sec = now;
			continue;
		}
//		if (diff > 3)
//			printf("pid slot %d [%d]: old:%ld now:%ld diff= %d\n", i, pid, old, now, diff);

		/* After 30 seconds of no progress, send a kill signal. */
		if (diff == 30) {
			output("pid %d hasn't made progress in 30 seconds! (last:%ld now:%ld diff:%d). Sending SIGKILL.\n",
				pid, old, now, diff);
			kill(pid, SIGKILL);
			break;
		}

		/* If it's still around after 60 seconds, we have bigger problems.
		 * Find out what's going on. */

		if (diff > 60) {
			output("pid %d hasn't made progress in 60 seconds! (last:%ld now:%ld diff:%d)\n",
				pid, old, now, diff);
			shm->tv[i].tv_sec = now;
		}
	}
}

void watchdog(void)
{
	static const char watchdogname[17]="trinity-watchdog";
	static unsigned long lastcount;
	unsigned int reseed_counter = 0;

	shm->watchdog_pid = getpid();
	printf("[%d] Watchdog is alive\n", shm->watchdog_pid);

	prctl(PR_SET_NAME, (unsigned long) &watchdogname);
	(void)signal(SIGSEGV, SIG_DFL);

	while (shm->exit_reason == STILL_RUNNING) {

		while (shm->regenerating == TRUE)
			sleep(0.1);

		if (check_shm_sanity() == SHM_CORRUPT)
			goto corrupt;

		check_children();

		/* Only check taint if it was zero on startup */
		if (do_check_tainted == FALSE) {
			if (check_tainted() != 0) {
				output("kernel became tainted! Last seed was %d:%x\n", shm->seed, shm->seed);
				shm->exit_reason = EXIT_KERNEL_TAINTED;
			}
		}

		if (syscallcount && (shm->execcount >= syscallcount)) {
			output("Reached limit %d. Telling children to start exiting\n", syscallcount);
			shm->exit_reason = EXIT_REACHED_COUNT;
		}

		if (shm->execcount % 1000 == 0)
			synclogs();

		if (quiet && (shm->execcount > 1)) {
			if (shm->execcount != lastcount)
				printf("%ld iterations. [F:%ld S:%ld]\n", shm->execcount, shm->failures, shm->successes);
			lastcount = shm->execcount;
		}

		reseed_counter++;
		if (reseed_counter == 10) {
			shm->need_reseed = TRUE;
			reseed_counter = 0;
		}

		sleep(1);
	}

corrupt:

	/* Wait for all the children to exit. */
	while (shm->running_childs > 0) {
		unsigned int i;

		for (i = 0; i < shm->max_children; i++) {
			pid_t pid;
			pid = shm->pids[i];
			if (pid == EMPTY_PIDSLOT)
				continue;
			kill(pid, SIGKILL);
		}
		sleep(1);
		if (check_shm_sanity()) {
			// FIXME: If we get here, we over-wrote the real exit_reason.
			// We should have saved that, and handled appropriately.
			goto out;
		}
	}

out:
	output("[%d] Watchdog thread exiting\n", getpid());

	_exit(EXIT_SUCCESS);
}
