#include <time.h>
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

static void watchdog(void);

void init_watchdog(void)
{
	static const struct timespec ts = { .tv_nsec = 100000000 }; /* 100ms */
	pid_t pid;

	fflush(stdout);
	pid = fork();

	if (pid == 0)
		watchdog();     // Never returns.

	while (shm->watchdog_pid == 0)
		nanosleep(&ts, NULL);

	output(0, "[%d] Started watchdog process, PID is %d\n", getpid(), shm->watchdog_pid);
}

static int check_shm_sanity(void)
{
	unsigned int i;
	pid_t pid;

	if (shm->running_childs == 0)
		return SHM_OK;

	for_each_pidslot(i) {
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
	if (shm->total_syscalls_done - shm->previous_count > 500000) {
		output(0, "[watchdog] Execcount increased dramatically! (old:%ld new:%ld):\n",
			shm->previous_count, shm->total_syscalls_done);
		shm->exit_reason = EXIT_SHM_CORRUPTION;
	}
	shm->previous_count = shm->total_syscalls_done;

	return SHM_OK;
}

static unsigned int reap_dead_kids()
{
	unsigned int i;
	unsigned int alive = 0;
	unsigned int reaped = 0;

	for_each_pidslot(i) {
		pid_t pid;
		int ret;

		pid = shm->pids[i];
		if (pid == EMPTY_PIDSLOT)
			continue;

		ret = kill(pid, 0);
		/* If it disappeared, reap it. */
		if (ret == -1) {
			if (errno == ESRCH) {
				output(0, "[watchdog] pid %d has disappeared (oom-killed maybe?). Reaping.\n", pid);
				reap_child(pid);
				reaped++;
			} else {
				output(0, "[watchdog] problem running getpgid on pid %d (%d:%s)\n", pid, errno, strerror(errno));
			}
		} else {
			alive++;
		}

		if (shm->running_childs == 0)
			return 0;
	}

	if (reaped != 0)
		output(0, "[watchdog] Reaped %d dead children\n", reaped);

	return alive;
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

	for_each_pidslot(i) {
		pid = shm->pids[i];

		if (pid == EMPTY_PIDSLOT)
			continue;

		old = shm->tv[i].tv_sec;

		if (old == 0)
			continue;

		/* if we wrapped, just reset it, we'll pick it up next time around. */
		if (old > (now + 3)) {
			printf("[watchdog] child %d wrapped! old=%ld now=%ld\n", i, old, now);
			shm->tv[i].tv_sec = now;
			continue;
		}

		diff = now - old;

		/* if we're way off, we're comparing garbage. Reset it. */
		if (diff > 1000) {
			output(0, "[watchdog] huge delta! pid slot %d [%d]: old:%ld now:%ld diff:%d.  Setting to now.\n", i, pid, old, now, diff);
			shm->tv[i].tv_sec = now;
			continue;
		}
//		if (diff > 3)
//			printf("[watchdog] pid slot %d [%d]: old:%ld now:%ld diff= %d\n", i, pid, old, now, diff);

		/* After 30 seconds of no progress, send a kill signal. */
		if (diff == 30) {
			output(0, "[watchdog] pid %d hasn't made progress in 30 seconds! (last:%ld now:%ld diff:%d). "
				"Stuck in syscall %d:%s%s. Sending SIGKILL.\n",
				pid, old, now, diff,
				shm->syscallno[i],
				print_syscall_name(shm->syscallno[i], shm->do32bit[i]),
				shm->do32bit[i] ? " (32bit)" : "");
			kill(pid, SIGKILL);
			break;
		}

		/* If it's still around after 60 seconds, we have bigger problems.
		 * Find out what's going on. */

		if (diff > 60) {
			output(0, "[watchdog] pid %d hasn't made progress in 60 seconds! (last:%ld now:%ld diff:%d)\n",
				pid, old, now, diff);
			shm->tv[i].tv_sec = now;
		}
	}
}

static void watchdog(void)
{
	static const char watchdogname[17]="trinity-watchdog";
	static unsigned long lastcount;

	shm->watchdog_pid = getpid();
	printf("[%d] Watchdog is alive\n", shm->watchdog_pid);

	prctl(PR_SET_NAME, (unsigned long) &watchdogname);
	(void)signal(SIGSEGV, SIG_DFL);

	while (shm->exit_reason == STILL_RUNNING) {

		if (shm->regenerating == FALSE) {

			if (check_shm_sanity() == SHM_CORRUPT)
				goto corrupt;

			reap_dead_kids();

			check_children();

			if (syscalls_todo && (shm->total_syscalls_done >= syscalls_todo)) {
				output(0, "[watchdog] Reached limit %d. Telling children to exit.\n", syscalls_todo);
				shm->exit_reason = EXIT_REACHED_COUNT;
			}

			// Periodic log syncing. FIXME: This is kinda ugly, and mostly unnecessary.
			if (shm->total_syscalls_done % 1000 == 0)
				synclogs();

			if ((quiet_level > 1) && (shm->total_syscalls_done > 1)) {
				if (shm->total_syscalls_done != lastcount)
					printf("[watchdog] %ld iterations. [F:%ld S:%ld]\n",
						shm->total_syscalls_done, shm->failures, shm->successes);
				lastcount = shm->total_syscalls_done;
			}
		}

		/* Only check taint if it was zero on startup */
		if (ignore_tainted == FALSE) {
			if (check_tainted() != 0) {
				output(0, "[watchdog] kernel became tainted! Last seed was %u\n", shm->seed);
				shm->exit_reason = EXIT_KERNEL_TAINTED;
			}
		}

		if (shm->need_reseed == FALSE) {
			shm->reseed_counter++;
			/* If we haven't reseeded in five minutes, trigger one. */
			if (shm->reseed_counter == 300) {
				output(0, "[watchdog] Triggering periodic reseed.\n");
				shm->need_reseed = TRUE;
				shm->reseed_counter = 0;
			}
		}

		sleep(1);
	}

corrupt:
	/* We don't want to ever exit before main is waiting for us. */
	while (shm->regenerating == TRUE)
		sleep(1);

	/* Wait for all the children to exit. */
	while (shm->running_childs > 0) {
		unsigned int i;
		unsigned int alive;

		/* Make sure there's no dead kids lying around.
		 * We need to do this in case the oom killer has been killing them,
		 * otherwise we end up stuck here with no child processes.
		 */
		alive = reap_dead_kids();
		if (alive == 0)
			goto out;

		/* Ok, some kids are still alive. 'help' them along with a SIGKILL */
		for_each_pidslot(i) {
			pid_t pid;

			pid = shm->pids[i];
			if (pid == EMPTY_PIDSLOT)
				continue;

			kill(pid, SIGKILL);
		}

		/* wait a second to give kids a chance to exit. */
		sleep(1);

		if (check_shm_sanity()) {
			// FIXME: If we get here, we over-wrote the real exit_reason.
			// We should have saved that, and handled appropriately.
			goto out;
		}
	}

out:
	output(0, "[%d] Watchdog exiting\n", getpid());

	_exit(EXIT_SUCCESS);
}
