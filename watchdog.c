#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "trinity.h"
#include "shm.h"
#include "files.h"
#include "syscall.h"

pid_t watchdog_pid;

void watchdog(void)
{
	struct timeval tv;
	unsigned int i;
	pid_t pid;
	unsigned int diff;
	time_t old, now;
	static char watchdogname[17]="trinity-watchdog";
	static unsigned long lastcount;

	prctl(PR_SET_NAME, (unsigned long) &watchdogname);

	while (exit_now == FALSE) {

		gettimeofday(&tv, NULL);
		now = tv.tv_sec;

		for (i = 0; i < shm->nr_childs; i++) {
			pid = shm->pids[i];

			if ((pid == 0) || (pid == -1))
				continue;

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
				printf("huge delta! pid slot %d [%d]: old:%ld now:%ld diff:%d.  Setting to now.\n", i, pid, old, now, diff);
				shm->tv[i].tv_sec = now;
				continue;
			}
//			if (diff > 3)
//				printf("pid slot %d [%d]: old:%ld now:%ld diff= %d\n", i, pid, old, now, diff);

			if (diff > 30) {
				output("pid %d hasn't made progress in 30 seconds! (last:%ld now:%ld diff:%d) Killing.\n",
					pid, old, now, diff);
				kill(pid, SIGKILL);
				reap_child(pid);
			}
		}

		/* Only check taint if it was zero on startup */
		if (do_check_tainted == 0) {
			if (check_tainted() != 0) {
				output("kernel became tainted!\n");
				exit_now = TRUE;
			}
		}

		if (syscallcount && (shm->execcount >= syscallcount))
			exit_now = TRUE;

		if (shm->execcount % 1000 == 0)
			synclogs();

		if (quiet && (shm->execcount > 1)) {
			if (shm->execcount != lastcount)
				printf("%ld iterations.\n", shm->execcount);
			lastcount = shm->execcount;
		}

		sleep(1);
	}
	printf("Watchdog thread exitting\n");
}
