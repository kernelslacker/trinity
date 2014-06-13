#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <syslog.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

#include "child.h"
#include "files.h"
#include "locks.h"
#include "log.h"
#include "params.h"	// quiet_level
#include "pids.h"
#include "post-mortem.h"
#include "shm.h"
#include "syscall.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h" //check_taint
#include "utils.h"

pid_t watchdog_pid;

static unsigned long hiscore = 0;

/*
 * Make sure various entries in the shm look sensible.
 * We use this to make sure that random syscalls haven't corrupted it.
 *
 * Note: reap_dead_kids will also check the pids for sanity.
 */
static int shm_is_corrupt(void)
{
	// FIXME: The '500000' is magic, and should be dynamically calculated.
	// On startup, we should figure out how many getpid()'s per second we can do,
	// and use that.
	if (shm->total_syscalls_done - shm->previous_op_count > 500000) {
		output(0, "Execcount increased dramatically! (old:%ld new:%ld):\n",
			shm->previous_op_count, shm->total_syscalls_done);
		shm->exit_reason = EXIT_SHM_CORRUPTION;
		return TRUE;
	}
	shm->previous_op_count = shm->total_syscalls_done;

	return FALSE;
}

static unsigned int reap_dead_kids(void)
{
	unsigned int i;
	unsigned int alive = 0;
	unsigned int reaped = 0;

	for_each_child(i) {
		pid_t pid;
		int ret;

		pid = shm->children[i]->pid;
		if (pid == EMPTY_PIDSLOT)
			continue;

		if (pid_is_valid(pid) == FALSE) {
			output(0, "Sanity check failed! Found pid %u at pidslot %u!\n", pid, i);
			if (shm->exit_reason == STILL_RUNNING)
				shm->exit_reason = EXIT_PID_OUT_OF_RANGE;
			return 0;
		}

		ret = kill(pid, 0);
		/* If it disappeared, reap it. */
		if (ret == -1) {
			if (errno == ESRCH) {
				output(0, "pid %u has disappeared. Reaping.\n", pid);
				reap_child(pid);
				reaped++;
			} else {
				output(0, "problem checking on pid %u (%d:%s)\n", pid, errno, strerror(errno));
			}
		} else {
			alive++;
		}

		if (shm->running_childs == 0)
			return 0;
	}

	if (reaped != 0)
		output(0, "Reaped %d dead children\n", reaped);

	return alive;
}

static void kill_all_kids(void)
{
	unsigned int i;

	shm->spawn_no_more = TRUE;

	/* Wait for all the children to exit. */
	while (shm->running_childs > 0) {
		unsigned int alive;

		/* Make sure there's no dead kids lying around.
		 * We need to do this in case the oom killer has been killing them,
		 * otherwise we end up stuck here with no child processes.
		 */
		alive = reap_dead_kids();
		if (alive == 0)
			return;

		/* Ok, some kids are still alive. 'help' them along with a SIGKILL */
		for_each_child(i) {
			pid_t pid;

			pid = shm->children[i]->pid;
			if (pid == EMPTY_PIDSLOT)
				continue;

			kill(pid, SIGKILL);
		}

		/* wait a second to give kids a chance to exit. */
		sleep(1);

		if (shm_is_corrupt() == TRUE)
			return;
	}

	/* Just to be sure, clear out the pid slots. */
	for_each_child(i) {
		shm->children[i]->pid = EMPTY_PIDSLOT;
	}
}

static bool __check_main(void)
{
	int ret;

	if (shm->mainpid == 0)
		return FALSE;

	ret = kill(shm->mainpid, 0);
	if (ret == -1) {
		/* Are we already exiting ? */
		if (shm->exit_reason != STILL_RUNNING)
			return FALSE;

		/* No. Check what happened. */
		if (errno == ESRCH) {
			output(0, "main pid %u has disappeared.\n", shm->mainpid);
			shm->exit_reason = EXIT_MAIN_DISAPPEARED;
			shm->mainpid = 0;
		} else {
			output(0, "problem checking on pid %u (%d:%s)\n", shm->mainpid, errno, strerror(errno));
		}
		return FALSE;
	}
	return TRUE;
}

static int check_main_alive(void)
{
	int ret;

	/* If we're in the process of exiting, wait, and return without checking. */
	if (shm->exit_reason != STILL_RUNNING) {
		while (shm->mainpid != 0) {
			/* make sure main is still alive, to wait for kids. */
			ret = __check_main();
			if (ret == TRUE) {
				sleep(1);
				kill_all_kids();
			}
		}
		return FALSE;
	}

	ret = __check_main();
	return ret;
}

/* if the first arg was an fd, find out which one it was. */
unsigned int check_if_fd(struct syscallrecord *rec)
{
	struct syscallentry *entry;
	unsigned int fd;
	unsigned int highest;
	unsigned callno;
	bool do32;

	lock(&rec->lock);
	fd = rec->a1;
	callno = rec->nr;
	do32 = rec->do32bit;
	unlock(&rec->lock);

	/* shortcut, if it's out of range, it's not going to be valid. */
	if (fd > 1024)
		return FALSE;

	highest = highest_logfile();
	if (fd < highest)
		return FALSE;

	entry = get_syscall_entry(callno, do32);

	if (entry->arg1type == ARG_FD)
		return TRUE;

	return FALSE;
}

static void stuck_syscall_info(struct childdata *child)
{
	struct syscallrecord *rec;
	unsigned int callno;
	char fdstr[20];

	if (debug == FALSE)
		return;

	rec = &child->syscall;
	callno = rec->nr;

	memset(fdstr, 0, sizeof(fdstr));

	if (check_if_fd(rec) == TRUE)
		sprintf(fdstr, "(fd = %d)", (unsigned int) rec->a1);

	output(0, "child %d (pid %u) Stuck in syscall %d:%s%s%s.\n",
		child->num, child->pid, callno,
		print_syscall_name(callno, rec->do32bit),
		rec->do32bit ? " (32bit)" : "",
		fdstr);
}

/*
 * Check that a child is making forward progress by comparing the timestamps it
 * recorded before making its last syscall.
 * If no progress is being made, send SIGKILLs to it.
 */
static void check_child_progress(struct childdata *child)
{
	struct syscallrecord *rec;
	struct timeval tv;
	time_t diff, old, now;
	pid_t pid;

	pid = child->pid;

	if (pid == EMPTY_PIDSLOT)
		return;

	rec = &child->syscall;

	old = rec->tv.tv_sec;

	if (old == 0)
		return;

	gettimeofday(&tv, NULL);
	now = tv.tv_sec;

	if (old > now)
		diff = old - now;
	else
		diff = now - old;

	/* hopefully the common case. */
	if (diff < 30)
		return;

	/* if we wrapped, just reset it, we'll pick it up next time around. */
	if (diff > 2145) {	/* max adjtime offset. */
		output(1, "child %u wrapped! old=%lu now=%lu\n", child->num, old, now);
		rec->tv.tv_sec = now;
		return;
	}

	/* if we're way off, we're comparing garbage. Reset it. */
	if (diff > 1000) {
		output(0, "huge delta! child %d [%d]: old:%ld now:%ld diff:%d.  Setting to now.\n",
				child->num, pid, old, now, diff);
		rec->tv.tv_sec = now;
		return;
	}

	/* After 30 seconds of no progress, send a kill signal. */
	if (diff == 30) {
		stuck_syscall_info(child);
		debugf("child %d (pid %u) hasn't made progress in 30 seconds! Sending SIGKILL\n",
				child->num, pid);
		goto kill;
	}

	/* if we're still around after 40s, repeatedly send SIGKILLs every second. */
	if (diff >= 40) {
		debugf("sending another SIGKILL to child %d (pid %u). [kill count:%d] [diff:%d]\n",
			child->num, pid, child->kill_count, diff);
		goto kill;
	}

	return;

kill:
	child->kill_count++;
	kill_pid(pid);
}

static void watchdog(void)
{
	static const char watchdogname[17]="trinity-watchdog";
	static unsigned long lastcount = 0;
	bool watchdog_exit = FALSE;
	int ret = 0;

	while (shm->ready == FALSE) {
		sleep(1);
		if (shm->exit_reason != STILL_RUNNING)
			return;
	}

	output(0, "Watchdog is alive. (pid:%d)\n", watchdog_pid);

	prctl(PR_SET_NAME, (unsigned long) &watchdogname);
	(void)signal(SIGSEGV, SIG_DFL);

	while (watchdog_exit == FALSE) {

		unsigned int i;

		if (shm_is_corrupt() == TRUE)
			goto corrupt;

		if (check_main_alive() == FALSE)
			goto main_dead;

		reap_dead_kids();

		check_all_locks();

		if (syscalls_todo && (shm->total_syscalls_done >= syscalls_todo)) {
			output(0, "Reached limit %d. Telling children to exit.\n", syscalls_todo);
			shm->exit_reason = EXIT_REACHED_COUNT;
		}

		// Periodic log syncing. FIXME: This is kinda ugly, and mostly unnecessary.
		if (shm->total_syscalls_done % 1000 == 0)
			synclogs();

		for_each_child(i) {
			struct childdata *child = shm->children[i];
			struct syscallrecord *rec = &child->syscall;

			check_child_progress(child);

			if (rec->op_nr > hiscore)
				hiscore = rec->op_nr;
		}

		if (shm->total_syscalls_done > 1) {
			if (shm->total_syscalls_done - lastcount > 10000) {
				output(0, "%ld iterations. [F:%ld S:%ld HI:%ld]\n",
					shm->total_syscalls_done,
					shm->failures, shm->successes,
					hiscore);
				lastcount = shm->total_syscalls_done;
			}
		}

		/* Only check taint if the mask allows it */
		if (kernel_taint_mask != 0) {
			ret = check_tainted();
			if (((ret & kernel_taint_mask) & (~kernel_taint_initial)) != 0)
				tainted_postmortem(ret);
		}

main_dead:
		/* Are we done ? */
		if (shm->exit_reason != STILL_RUNNING) {
			/* Give children a chance to exit. */
			sleep(1);

			/* Are there still children running ? */
			if (pidmap_empty() == TRUE)
				watchdog_exit = TRUE;
			else {
				output(0, "exit_reason=%d, but %d children still running.\n",
					shm->exit_reason, shm->running_childs);
				kill_all_kids();
			}
		}

		sleep(1);
	}

corrupt:
	kill_all_kids();
}

void init_watchdog(void)
{
	pid_t pid;

	fflush(stdout);
	pid = fork();

	if (pid == 0) {
		watchdog_pid = getpid();
		watchdog();
		output(0, "[%d] Watchdog exiting\n", watchdog_pid);
		_exit(EXIT_SUCCESS);

	} else {
		watchdog_pid = pid;
		output(0, "Started watchdog process, PID is %d\n", watchdog_pid);
	}
}
