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

static void regenerate()
{
	if (syscallcount >= shm->regenerate)
		return;

	shm->regenerating = TRUE;

	sleep(1);	/* give children time to finish with fds. */

	shm->regenerate = 0;

	output("[%d] Regenerating random pages, fd's etc.\n", getpid());

	regenerate_fds();

	destroy_maps();
	setup_maps();

	regenerate_random_page();

	shm->regenerating = FALSE;
}

unsigned char do_check_tainted;

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

int find_pid_slot(pid_t mypid)
{
	unsigned int i;

	for (i = 0; i < shm->max_children; i++) {
		if (shm->pids[i] == mypid)
			return i;
	}
	return NO_PIDSLOT;
}

static unsigned char pidmap_empty(void)
{
	unsigned int i;

	for (i = 0; i < shm->max_children; i++) {
		if (shm->pids[i] == -1)
			continue;
		if (shm->pids[i] != 0)
			return FALSE;
	}
	return TRUE;
}

void dump_pid_slots(void)
{
	unsigned int i;

	printf("## pids:\n");

	for (i = 0; i < shm->max_children; i++)
		printf("## slot%d: %d\n", i, shm->pids[i]);
}

#define debugf if (debug == TRUE) printf

static void fork_children()
{
	int pidslot;
	static char childname[17];

	/* Generate children*/

	while (shm->running_childs < shm->max_children) {
		int pid = 0;

		/* Find a space for it in the pid map */
		pidslot = find_pid_slot(NO_PIDSLOT);
		if (pidslot == -1) {
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
			int ret = 0;

			memset(childname, 0, sizeof(childname));
			sprintf(childname, "trinity-child%d", pidslot);
			prctl(PR_SET_NAME, (unsigned long) &childname);

			set_seed(pidslot);

			/* Wait for parent to set our pidslot */
			while (shm->pids[pidslot] != getpid());

			ret = child_process();

			output("child %d exitting\n", getpid());

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
	if (i == NO_PIDSLOT)
		goto out;

	debugf("[%d] Removing pid %d from pidmap.\n", getpid(), childpid);
	shm->pids[i] = -1;
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
			for (i = 0; i < shm->max_children; i++) {
				if (shm->pids[i] == 0)
					continue;
				if (shm->pids[i] != -1) {
					debugf("[%d] Removing %d from pidmap\n", getpid(), shm->pids[i]);
					shm->pids[i] = -1;
					shm->running_childs--;
				}
			}
			break;
		}
		output("error! (%s)\n", strerror(errno));
		break;

	default:
		debugf("[%d] Something happened to pid %d\n", getpid(), childpid);

		if (WIFEXITED(childstatus)) {

			slot = find_pid_slot(childpid);
			if (slot == NO_PIDSLOT) {
				printf("[%d] ## Couldn't find pid slot for %d\n", getpid(), childpid);
				shm->exit_reason = EXIT_LOST_PID_SLOT;
				dump_pid_slots();
			} else {
				debugf("[%d] Child %d exited after %d syscalls.\n", getpid(), childpid, shm->total_syscalls[slot]);
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
				;;	// fallthrough
			case SIGFPE:
			case SIGSEGV:
			case SIGKILL:
			case SIGPIPE:
			case SIGABRT:
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
			output("erk, wtf\n");
		}
	}
}

static void handle_children()
{
	unsigned int i;
	int childstatus;
	pid_t pid;

	pid = waitpid(-1, &childstatus, WUNTRACED | WCONTINUED);

	handle_child(pid, childstatus);

	for (i = 0; i < shm->max_children; i++) {

		pid = shm->pids[i];

		if (pid == 0)
			continue;
		if (pid == -1)
			continue;

		pid = waitpid(pid, &childstatus, WUNTRACED | WCONTINUED | WNOHANG);
		if (pid != 0)
			handle_child(pid, childstatus);

		sleep(0.1);	/* Give other children a chance to do something. */
	}
}

static void main_loop()
{
	static const char taskname[13]="trinity-main";

	shm->parentpid = getpid();

	prctl(PR_SET_NAME, (unsigned long) &taskname);

	while (shm->exit_reason == STILL_RUNNING) {
		if (shm->running_childs < shm->max_children)
			fork_children();

		handle_children();

		if (shm->regenerate >= REGENERATION_POINT)
			regenerate();
	}
	while (!(pidmap_empty()))
		handle_children();

	printf("[%d] Bailing main loop. Exit reason: %d\n", getpid(), shm->exit_reason);
	_exit(EXIT_SUCCESS);
}


void do_main_loop()
{
	int childstatus;
	pid_t pid;

	/* do an extra fork so that the watchdog and the children don't share a common parent */
	fflush(stdout);
	pid = fork();
	if (pid == 0)
		main_loop();

	while (pid != -1)
		pid = waitpid(-1, &childstatus, 0);

	shm->parentpid = getpid();
}
