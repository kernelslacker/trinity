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

void wait_for_watchdog_to_exit(void)
{
	int ret, status;

	if (shm->watchdog_pid == 0)
		return;

	printf("[%d] Waiting for watchdog (%d) to exit.\n", getpid(), shm->watchdog_pid);

	while (shm->watchdog_pid != 0) {

		ret = waitpid(shm->watchdog_pid, &status, 0);
		switch (ret) {
		case 0:
			break;
		case -1:
			return;
		default:
			if (WIFEXITED(status)) {
				if (ret == shm->watchdog_pid) {
					shm->watchdog_pid = 0;
					return;
				}
			}
			break;
		}
		sleep(1);
	}
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

	for (i = 0; i < shm->nr_childs; i++) {
		pid = shm->pids[i];

		if ((pid == 0) || (pid == -1))
			continue;

		/* first things first, does the pid still exist ? */
		if (getpgid(pid) == -1) {
			output("pid %d has disappeared (oom-killed maybe?). (ret=%d:%s) Reaping.\n", pid, errno, strerror(errno));
			reap_child(pid);
			continue;
		}

		old = shm->tv[i].tv_sec;

		if (old == 0)
			continue;

		/* if we wrapped, just reset it, we'll pick it up next time around. */
		if (old > now) {
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

	shm->watchdog_pid = getpid();
	printf("[%d] Watchdog is alive\n", shm->watchdog_pid);

	prctl(PR_SET_NAME, (unsigned long) &watchdogname);
	(void)signal(SIGSEGV, SIG_DFL);

	while (shm->exit_now == FALSE) {

		while (shm->regenerating == TRUE)
			sleep(0.1);

		check_children();

		/* Only check taint if it was zero on startup */
		if (do_check_tainted == FALSE) {
			if (check_tainted() != 0) {
				output("kernel became tainted!\n");
				shm->exit_now = TRUE;
			}
		}

		if (syscallcount && (shm->execcount >= syscallcount)) {
			output("Reached limit %d. Telling children to start exiting\n", syscallcount);
			shm->exit_now = TRUE;
		}

		if (shm->execcount % 1000 == 0)
			synclogs();

		if (quiet && (shm->execcount > 1)) {
			if (shm->execcount != lastcount)
				printf("%ld iterations. [F:%ld S:%ld]\n", shm->execcount, shm->failures, shm->successes);
			lastcount = shm->execcount;
		}

		sleep(1);
	}

	output("[%d] Watchdog thread exitting\n", getpid());

	_exit(EXIT_SUCCESS);
}
