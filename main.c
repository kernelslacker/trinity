#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

#include "trinity.h"
#include "shm.h"
#include "files.h"
#include "syscall.h"

static void regenerate(void)
{
	shm->regenerating = TRUE;

	sleep(1);	/* give children time to finish with fds. */

	shm->regenerate = 0;

	output(0, "[%d] Regenerating random pages, fd's etc.\n", getpid());

	regenerate_fds();

	destroy_maps();
	setup_maps();

	regenerate_random_page();

	shm->regenerating = FALSE;
}

bool ignore_tainted;

int check_tainted(void)
{
	int fd;
	int ret;
	char buffer[4];

	fd = open("/proc/sys/kernel/tainted", O_RDONLY);
	if (!fd)
		return -1;
	ret = read(fd, buffer, 3);
	close(fd);
	ret = atoi(buffer);

	return ret;
}

#define debugf if (debug == TRUE) printf

static void fork_children(void)
{
	int pidslot;
	static char childname[17];

	/* Generate children*/

	while (shm->running_childs < shm->max_children) {
		int pid = 0;

		/* Find a space for it in the pid map */
		pidslot = find_pid_slot(EMPTY_PIDSLOT);
		if (pidslot == PIDSLOT_NOT_FOUND) {
			printf("[%d] ## Pid map was full!\n", getpid());
			dump_pid_slots();
			exit(EXIT_FAILURE);
		}

		(void)alarm(0);
		fflush(stdout);
		pid = fork();
		if (pid != 0)
			shm->pids[pidslot] = pid;
		else {
			/* Child process. */
			int ret = 0;

			mask_signals_child();

			memset(childname, 0, sizeof(childname));
			sprintf(childname, "trinity-child%d", pidslot);
			prctl(PR_SET_NAME, (unsigned long) &childname);

			/* Wait for parent to set our pidslot */
			while (shm->pids[pidslot] != getpid()) {
				/* Make sure parent is actually alive to wait for us. */
				ret = pid_alive(shm->parentpid);
				if (ret != 0) {
					shm->exit_reason = EXIT_SHM_CORRUPTION;
					printf("[%d] " BUGTXT "parent (%d) went away!\n", getpid(), shm->parentpid);
					sleep(20000);
				}
			}

			set_seed(pidslot);

			ret = child_process();

			output(0, "child %d exitting\n", getpid());

			_exit(ret);
		}
		shm->running_childs++;
		debugf("[%d] Created child %d in pidslot %d [total:%d/%d]\n",
			getpid(), shm->pids[pidslot], pidslot,
			shm->running_childs, shm->max_children);

		if (shm->exit_reason != STILL_RUNNING)
			return;

	}
	debugf("[%d] created enough children\n", getpid());
}

void reap_child(pid_t childpid)
{
	int i;

	while (shm->reaper_lock == LOCKED);

	shm->reaper_lock = LOCKED;

	if (childpid == shm->last_reaped) {
		debugf("[%d] already reaped %d!\n", getpid(), childpid);
		goto out;
	}

	i = find_pid_slot(childpid);
	if (i == PIDSLOT_NOT_FOUND)
		goto out;

	debugf("[%d] Removing pid %d from pidmap.\n", getpid(), childpid);
	shm->pids[i] = EMPTY_PIDSLOT;
	shm->running_childs--;
	shm->tv[i].tv_sec = 0;
	shm->last_reaped = childpid;

out:
	shm->reaper_lock = UNLOCKED;
}

static void handle_child(pid_t childpid, int childstatus)
{
	unsigned int i;
	int slot;

	switch (childpid) {
	case 0:
		//debugf("[%d] Nothing changed. children:%d\n", getpid(), shm->running_childs);
		break;

	case -1:
		if (shm->exit_reason != STILL_RUNNING)
			return;

		if (errno == ECHILD) {
			debugf("[%d] All children exited!\n", getpid());
			for_each_pidslot(i) {
				if (shm->pids[i] != EMPTY_PIDSLOT) {
					if (pid_alive(shm->pids[i]) == -1) {
						debugf("[%d] Removing %d from pidmap\n", getpid(), shm->pids[i]);
						shm->pids[i] = EMPTY_PIDSLOT;
						shm->running_childs--;
					} else {
						debugf("[%d] %d looks still alive! ignoring.\n", getpid(), shm->pids[i]);
					}
				}
			}
			break;
		}
		output(0, "error! (%s)\n", strerror(errno));
		break;

	default:
		debugf("[%d] Something happened to pid %d\n", getpid(), childpid);

		if (WIFEXITED(childstatus)) {

			slot = find_pid_slot(childpid);
			if (slot == PIDSLOT_NOT_FOUND) {
				printf("[%d] ## Couldn't find pid slot for %d\n", getpid(), childpid);
				shm->exit_reason = EXIT_LOST_PID_SLOT;
				dump_pid_slots();
			} else {
				debugf("[%d] Child %d exited after %ld syscalls.\n", getpid(), childpid, shm->child_syscall_count[slot]);
				reap_child(childpid);
			}
			break;

		} else if (WIFSIGNALED(childstatus)) {

			switch (WTERMSIG(childstatus)) {
			case SIGALRM:
				debugf("[%d] got a alarm signal from pid %d\n", getpid(), childpid);
				break;
			case SIGFPE:
			case SIGSEGV:
			case SIGKILL:
			case SIGPIPE:
			case SIGABRT:
				debugf("[%d] got a signal from pid %d (%s)\n", getpid(), childpid, strsignal(WTERMSIG(childstatus)));
				reap_child(childpid);
				break;
			default:
				debugf("[%d] ** Child got an unhandled signal (%d)\n", getpid(), WTERMSIG(childstatus));
				break;
			}
			break;

		} else if (WIFSTOPPED(childstatus)) {

			switch (WSTOPSIG(childstatus)) {
			case SIGALRM:
				debugf("[%d] got an alarm signal from pid %d\n", getpid(), childpid);
				break;
			case SIGSTOP:
				debugf("[%d] Sending PTRACE_DETACH (and then KILL)\n", getpid());
				ptrace(PTRACE_DETACH, childpid, NULL, NULL);
				kill(childpid, SIGKILL);
				reap_child(childpid);
				break;
			case SIGFPE:
			case SIGSEGV:
			case SIGKILL:
			case SIGPIPE:
			case SIGABRT:
				debugf("[%d] Child %d was stopped by %s\n", getpid(), childpid, strsignal(WTERMSIG(childstatus)));
				reap_child(childpid);
				break;
			default:
				debugf("[%d] Child %d was stopped by unhandled signal (%s).\n", getpid(), childpid, strsignal(WSTOPSIG(childstatus)));
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

static const char *reasons[] = {
	"Still running",
	"No more syscalls enabled",
	"Reached maximum syscall count",
	"No file descriptors open",
	"Lost track of a pid slot",
	"shm corruption - Found a pid out of range.",
	"ctrl-c",
	"kernel became tainted",
	"SHM was corrupted!",
	"Child reparenting problem",
};

static const char * decode_exit(unsigned int reason)
{
	return reasons[reason];
}

static void main_loop(void)
{
	while (shm->exit_reason == STILL_RUNNING) {
		if (shm->running_childs < shm->max_children) {
			reseed();
			fork_children();
		}

		if (shm->regenerate >= REGENERATION_POINT)
			regenerate();

		if (shm->need_reseed == TRUE)
			reseed();

		handle_children();
	}
}


void do_main_loop(void)
{
	const char taskname[13]="trinity-main";
	int childstatus;
	pid_t pid;


	/* do an extra fork so that the watchdog and the children don't share a common parent */
	fflush(stdout);
	pid = fork();
	if (pid == 0) {
		setup_main_signals();

		shm->parentpid = getpid();
		output(0, "[%d] Main thread is alive.\n", getpid());
		prctl(PR_SET_NAME, (unsigned long) &taskname);
		set_seed(0);

		setup_fds();

		main_loop();

		/* Wait until all children have exited. */
		while (pidmap_empty() == FALSE)
			handle_children();

		printf("[%d] Bailing main loop. Exit reason: %s\n", getpid(), decode_exit(shm->exit_reason));
		_exit(EXIT_SUCCESS);
	}

	/* wait for main loop process to exit. */
	pid = waitpid(pid, &childstatus, 0);

	shm->parentpid = getpid();
}
