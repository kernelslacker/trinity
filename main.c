#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "child.h"
#include "files.h"
#include "locks.h"
#include "log.h"
#include "params.h"
#include "pids.h"
#include "random.h"
#include "shm.h"
#include "signals.h"
#include "syscall.h"
#include "trinity.h"

/* Generate children*/
static void fork_children(void)
{
	while (shm->running_childs < max_children) {
		int pidslot;
		int pid = 0;

		if (shm->spawn_no_more == TRUE)
			return;

		/* a new child means a new seed, or the new child
		 * will do the same syscalls as the one in the pidslot it's replacing.
		 * (special case startup, or we reseed unnecessarily)
		 */
		if (shm->ready == TRUE)
			reseed();

		/* Find a space for it in the pid map */
		pidslot = find_pid_slot(EMPTY_PIDSLOT);
		if (pidslot == PIDSLOT_NOT_FOUND) {
			outputerr("## Pid map was full!\n");
			dump_pid_slots();
			exit(EXIT_FAILURE);
		}

		if (logging == TRUE) {
			int fd;

			fd = fileno(shm->logfiles[pidslot]);
			if (ftruncate(fd, 0) == 0)
				lseek(fd, 0, SEEK_SET);
		}

		(void)alarm(0);
		fflush(stdout);
		pid = fork();

		if (pid == 0) {
			/* Child process. */
			init_child(pidslot);
			child_process(pidslot);
			output(1, "child %d exiting.\n", pidslot);
			_exit(EXIT_SUCCESS);
		} else {
			if (pid == -1) {
				output(0, "couldn't create child! (%s)\n", strerror(errno));
				shm->exit_reason = EXIT_FORK_FAILURE;
				exit(EXIT_FAILURE);
			}
		}

		shm->pids[pidslot] = pid;
		shm->running_childs++;

		debugf("Created child %d in pidslot %d [total:%d/%d]\n",
			shm->pids[pidslot], pidslot,
			shm->running_childs, max_children);

		if (shm->exit_reason != STILL_RUNNING)
			return;

	}
	shm->ready = TRUE;

	debugf("created enough children\n");
}

void reap_child(pid_t childpid)
{
	int i;

	lock(&shm->reaper_lock);

	if (childpid == shm->last_reaped) {
		debugf("already reaped %d!\n", childpid);
		goto out;
	}

	i = find_pid_slot(childpid);
	if (i == PIDSLOT_NOT_FOUND)
		goto out;

	debugf("Removing pid %d from pidmap.\n", childpid);
	shm->pids[i] = EMPTY_PIDSLOT;
	shm->running_childs--;
	shm->tv[i].tv_sec = 0;
	shm->last_reaped = childpid;

out:
	unlock(&shm->reaper_lock);
}

static void handle_child(pid_t childpid, int childstatus)
{
	switch (childpid) {
	case 0:
		//debugf("Nothing changed. children:%d\n", shm->running_childs);
		break;

	case -1:
		if (shm->exit_reason != STILL_RUNNING)
			return;

		if (errno == ECHILD) {
			unsigned int i;
			bool seen = FALSE;

			debugf("All children exited!\n");

			for_each_pidslot(i) {
				if (shm->pids[i] != EMPTY_PIDSLOT) {
					if (pid_alive(shm->pids[i]) == -1) {
						debugf("Removing %d from pidmap\n", shm->pids[i]);
						shm->pids[i] = EMPTY_PIDSLOT;
						shm->running_childs--;
					} else {
						debugf("%d looks still alive! ignoring.\n", shm->pids[i]);
					}
					seen = TRUE;
				}
			}
			if (seen == FALSE)
				shm->running_childs = 0;
			break;
		}
		output(0, "error! (%s)\n", strerror(errno));
		break;

	default:
		debugf("Something happened to pid %d\n", childpid);

		if (WIFEXITED(childstatus)) {

			int slot;

			slot = find_pid_slot(childpid);
			if (slot == PIDSLOT_NOT_FOUND) {
				/* If we reaped it, it wouldn't show up, so check that. */
				if (shm->last_reaped != childpid) {
					outputerr("## Couldn't find pid slot for %d\n", childpid);
					shm->exit_reason = EXIT_LOST_PID_SLOT;
					dump_pid_slots();
				}
			} else {
				debugf("Child %d exited after %ld operations.\n", childpid, shm->child_op_count[slot]);
				reap_child(childpid);
			}
			break;

		} else if (WIFSIGNALED(childstatus)) {

			switch (WTERMSIG(childstatus)) {
			case SIGALRM:
				debugf("got a alarm signal from pid %d\n", childpid);
				break;
			case SIGFPE:
			case SIGSEGV:
			case SIGKILL:
			case SIGPIPE:
			case SIGABRT:
				debugf("got a signal from pid %d (%s)\n", childpid, strsignal(WTERMSIG(childstatus)));
				reap_child(childpid);
				break;
			default:
				debugf("** Child got an unhandled signal (%d)\n", WTERMSIG(childstatus));
				break;
			}
			break;

		} else if (WIFSTOPPED(childstatus)) {

			switch (WSTOPSIG(childstatus)) {
			case SIGALRM:
				debugf("got an alarm signal from pid %d\n", childpid);
				break;
			case SIGSTOP:
				debugf("Sending PTRACE_DETACH (and then KILL)\n");
				ptrace(PTRACE_DETACH, childpid, NULL, NULL);
				kill(childpid, SIGKILL);
				reap_child(childpid);
				break;
			case SIGFPE:
			case SIGSEGV:
			case SIGKILL:
			case SIGPIPE:
			case SIGABRT:
				debugf("Child %d was stopped by %s\n", childpid, strsignal(WTERMSIG(childstatus)));
				reap_child(childpid);
				break;
			default:
				debugf("Child %d was stopped by unhandled signal (%s).\n", childpid, strsignal(WSTOPSIG(childstatus)));
				break;
			}
			break;

		} else if (WIFCONTINUED(childstatus)) {
			break;
		} else {
			output(0, "erk, wtf\n");
		}
	}
}

static void handle_children(void)
{
	unsigned int i;
	int childstatus;
	pid_t pid;

	if (shm->running_childs == 0)
		return;

	/* First, we wait for *any* child to wake us up. */
	pid = waitpid(-1, &childstatus, WUNTRACED | WCONTINUED);

	/* We were awoken, handle it. */
	handle_child(pid, childstatus);

	/* While we're awake, let's see if the other children need attention.
	 * We do this instead of just waitpid(-1) again so that there's no way
	 * for any one child to starve the others of attention.
	 */
	for_each_pidslot(i) {

		pid = shm->pids[i];

		if (pid == EMPTY_PIDSLOT)
			continue;

		if (pid_is_valid(pid) == FALSE)
			return;

		pid = waitpid(pid, &childstatus, WUNTRACED | WCONTINUED | WNOHANG);
		if (pid != 0)
			handle_child(pid, childstatus);
	}
}

static const char *reasons[NUM_EXIT_REASONS] = {
	"Still running.",
	"No more syscalls enabled.",
	"Reached maximum syscall count.",
	"No file descriptors open.",
	"Lost track of a pid slot.",
	"shm corruption - Found a pid out of range.",
	"ctrl-c",
	"kernel became tainted.",
	"SHM was corrupted!",
	"Child reparenting problem",
	"No files in file list.",
	"Main process disappeared.",
	"UID changed.",
	"Something happened during fd init.",
	"fork() failure",
};

static const char * decode_exit(unsigned int reason)
{
	return reasons[reason];
}

void main_loop(void)
{
	while (shm->exit_reason == STILL_RUNNING) {

		if (shm->spawn_no_more == FALSE) {
			if (shm->running_childs < max_children)
				fork_children();

			/* Periodic regenation of fd's etc. */
			if (shm->regenerate >= REGENERATION_POINT)
				regenerate();
		}

		handle_children();
	}

	/* Wait until all children have exited. */
	while (pidmap_empty() == FALSE)
		handle_children();

	outputerr("Bailing main loop. Exit reason: %s\n", decode_exit(shm->exit_reason));
}
