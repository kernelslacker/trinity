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
#include "debug.h"
#include "log.h"
#include "pids.h"
#include "random.h"
#include "shm.h"
#include "syscall.h"
#include "trinity.h"

/* exit() wrapper to clear the pid before exiting, so the
 * watchdog doesn't spin forever on a dead pid.
 */
void exit_main_fail(void)
{
	if (getpid() != shm->mainpid) {
		show_backtrace();
		BUG("wtf, exit_main_fail called from non main pid!\n");
	}

	shm->mainpid = 0;
	exit(EXIT_FAILURE);
}

/* Generate children*/
static void fork_children(void)
{
	while (shm->running_childs < max_children) {
		int childno;
		int pid = 0;

		if (shm->spawn_no_more == TRUE)
			return;

		/* a new child means a new seed, or the new child
		 * will do the same syscalls as the one in the child it's replacing.
		 * (special case startup, or we reseed unnecessarily)
		 */
		if (shm->ready == TRUE)
			reseed();

		/* Find a space for it in the pid map */
		childno = find_childno(EMPTY_PIDSLOT);
		if (childno == CHILD_NOT_FOUND) {
			outputerr("## Pid map was full!\n");
			dump_childnos();
			exit_main_fail();
		}

		fflush(stdout);
		pid = fork();

		if (pid == 0) {
			/* Child process. */

			struct childdata *child = shm->children[childno];

			init_child(child, childno);

			child_process();

			debugf("child %d %d exiting.\n", childno, getpid());
			close_logfile(&this_child->logfile);
			reap_child(child->pid);
			_exit(EXIT_SUCCESS);
		} else {
			if (pid == -1) {
				/* We failed, wait for a child to exit before retrying. */
				if (shm->running_childs > 0)
					return;

				output(0, "couldn't create child! (%s)\n", strerror(errno));
				panic(EXIT_FORK_FAILURE);
				exit_main_fail();
			}
		}

		shm->children[childno]->pid = pid;
		shm->running_childs++;

		debugf("Created child %d (pid:%d) [total:%d/%d]\n",
			childno, pid, shm->running_childs, max_children);

		if (shm->exit_reason != STILL_RUNNING)
			return;

	}
	shm->ready = TRUE;

	debugf("created enough children\n");
}

/*
 * reap_child: Remove all references to a running child.
 *
 * This can get called from three possible places.
 * 1. A child calls this itself just before it exits to clear out
 *    its child struct in the shm.
 * 2. From the watchdog if it finds reference to a pid that no longer exists.
 * 3. From the main pid if it gets a SIGBUS or SIGSTOP from the child.
 *
 * The reaper lock protects against these happening at the same time.
 */
void reap_child(pid_t childpid)
{
	struct childdata *child;
	int i;

	lock(&shm->reaper_lock);

	if (childpid == shm->last_reaped) {
		debugf("already reaped %d!\n", childpid);
		goto out;
	}

	i = find_childno(childpid);
	if (i == CHILD_NOT_FOUND)
		goto out;

	debugf("Removing pid %d from pidmap.\n", childpid);
	child = shm->children[i];
	child->pid = EMPTY_PIDSLOT;
	child->syscall.tv.tv_sec = 0;
	shm->running_childs--;
	shm->last_reaped = childpid;

out:
	unlock(&shm->reaper_lock);
}

static void handle_childsig(int childpid, int childstatus, int stop)
{
	int __sig;

	if (stop == TRUE)
		__sig = WSTOPSIG(childstatus);
	else
		__sig = WTERMSIG(childstatus);

	switch (__sig) {
	case SIGSTOP:
		if (stop != TRUE)
			return;
		debugf("Sending PTRACE_DETACH (and then KILL)\n");
		ptrace(PTRACE_DETACH, childpid, NULL, NULL);
		kill(childpid, SIGKILL);
		reap_child(childpid);
		return;

	case SIGALRM:
		debugf("got a alarm signal from pid %d\n", childpid);
		break;
	case SIGFPE:
	case SIGSEGV:
	case SIGKILL:
	case SIGPIPE:
	case SIGABRT:
	case SIGBUS:
		if (stop == TRUE)
			debugf("Child %d was stopped by %s\n", childpid, strsignal(WSTOPSIG(childstatus)));
		else
			debugf("got a signal from pid %d (%s)\n", childpid, strsignal(WTERMSIG(childstatus)));
		reap_child(childpid);
		return;

	default:
		if (__sig >= SIGRTMIN) {
			debugf("Child %d got RT signal (%d). Ignoring.\n", childpid, __sig);
			return;
		}

		if (stop == TRUE)
			debugf("Child %d was stopped by unhandled signal (%s).\n", childpid, strsignal(WSTOPSIG(childstatus)));
		else
			debugf("** Child got an unhandled signal (%d)\n", WTERMSIG(childstatus));
		return;
	}
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

			for_each_child(i) {
				struct childdata *child;

				child = shm->children[i];

				if (child->pid != EMPTY_PIDSLOT) {
					if (pid_alive(child->pid) == -1) {
						debugf("Removing %d from pidmap\n", child->pid);
						child->pid = EMPTY_PIDSLOT;
						shm->running_childs--;
					} else {
						debugf("%d looks still alive! ignoring.\n", child->pid);
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

			int childno;

			childno = find_childno(childpid);
			if (childno != CHILD_NOT_FOUND) {
				debugf("Child %d exited after %ld operations.\n",
					childpid, shm->children[childno]->syscall.op_nr);
				reap_child(childpid);
			}
			break;

		} else if (WIFSIGNALED(childstatus)) {
			handle_childsig(childpid, childstatus, FALSE);
		} else if (WIFSTOPPED(childstatus)) {
			handle_childsig(childpid, childstatus, TRUE);
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
	for_each_child(i) {

		pid = shm->children[i]->pid;

		if (pid == EMPTY_PIDSLOT)
			continue;

		if (pid_is_valid(pid) == FALSE)	/* If we find something invalid, we just ignore */
			continue;		/* it and leave it to the watchdog to clean up. */

		pid = waitpid(pid, &childstatus, WUNTRACED | WCONTINUED | WNOHANG);
		if (pid != 0)
			handle_child(pid, childstatus);
	}
}

static const char *reasons[NUM_EXIT_REASONS] = {
	"Still running.",
	"No more syscalls enabled.",
	"Completed maximum number of operations.",
	"No file descriptors open.",
	"Lost track of a child.",
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
	"some kind of locking catastrophe",
	"error while opening logfiles",
};

const char * decode_exit(void)
{
	return reasons[shm->exit_reason];
}

void main_loop(void)
{
	while (shm->exit_reason == STILL_RUNNING) {
		if (shm->running_childs < max_children)
			fork_children();

		handle_children();
	}

	/* if the pid map is corrupt, we can't trust that we'll
	 * ever successfully finish pidmap_empty, so skip it */
	if ((shm->exit_reason == EXIT_LOST_CHILD) ||
	    (shm->exit_reason == EXIT_SHM_CORRUPTION))
		goto dont_wait;

	/* Wait until all children have exited. */
	while (pidmap_empty() == FALSE)
		handle_children();

dont_wait:
	output(0, "Bailing main loop because %s.\n", decode_exit());
}

/*
 * Something potentially bad happened. Alert all processes by setting appropriate shm vars.
 * (not always 'bad', reaching max count for eg is one example).
 */
void panic(int reason)
{
	shm->spawn_no_more = TRUE;
	shm->exit_reason = reason;
}
