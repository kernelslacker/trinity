#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

#include "trinity.h"
#include "shm.h"
#include "syscall.h"

void syscall_list()
{
	unsigned int i;

	for (i=0; i < max_nr_syscalls; i++)
		 printf("%u: %s\n", i, syscalls[i].entry->name);
}

static void regenerate()
{
	output("[%d] Regenerating random pages, fd's etc.\n", getpid());
	close_files();
	open_files();

	destroy_maps();
	setup_maps();

	shm->regenerate = REGENERATION_POINT - 1;

	regenerate_random_page();
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


#define debugf if (debug == 1) printf

static void fork_children()
{
	unsigned int i;

	/* Generate children*/

	while (shm->running_childs < shm->nr_childs) {
		int pid = 0;

		/* Find a space for it in the pid map */
		for (i = 0; i < shm->nr_childs; i++) {
			if (shm->pids[i] == -1)
				break;
		}
		if (i >= shm->nr_childs) {
			output("pid map full!\n");
			exit(EXIT_FAILURE);
		}
		(void)alarm(0);
		pid = fork();
		if (pid != 0)
			shm->pids[i] = pid;
		else {
			int ret = 0;

			ret = child_process();
			shm->regenerate--;
			output("child %d exitting\n", getpid());

			_exit(ret);
		}
		shm->running_childs++;
		debugf("[%d] Created child %d [total:%d/%d]\n", getpid(), shm->pids[i], shm->running_childs, shm->nr_childs);
	}
	debugf("[%d] created enough children\n\n", getpid());
}

static void reap_child(pid_t childpid)
{
	unsigned int i;

	for (i = 0; i < shm->nr_childs; i++) {
		if (shm->pids[i] == childpid) {
			debugf("[%d] Removing %d from pidmap\n", getpid(), shm->pids[i]);
			shm->pids[i] = -1;
			shm->running_childs--;
			break;
		}
	}
}

static void handle_children()
{
	int childpid, childstatus;
	unsigned int i;

	childpid = waitpid(-1, &childstatus, WUNTRACED | WCONTINUED);

	switch (childpid) {
	case 0:
		debugf("[%d] Nothing changed. children:%d\n", getpid(), shm->running_childs);
		break;

	case -1:
		if (errno == ECHILD) {
			debugf("[%d] All children exited!\n", getpid());
			for (i = 0; i < shm->nr_childs; i++) {
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
			debugf("[%d] Child %d exited\n", getpid(), childpid);
			reap_child(childpid);
			break;

		} else if (WIFSIGNALED(childstatus)) {
			switch (WTERMSIG(childstatus)) {
			case SIGFPE:
			case SIGSEGV:
			case SIGKILL:
			case SIGALRM:
			case SIGPIPE:
			case SIGABRT:
				debugf("[%d] got a signal (%s)\n", getpid(), strsignal(WTERMSIG(childstatus)));
				reap_child(childpid);
				break;
			default:
				debugf("[%d] ** Child got an unhandled signal (%d)\n", getpid(), WTERMSIG(childstatus));
				break;
			}
			break;

		} else if (WIFSTOPPED(childstatus)) {
			debugf("[%d] Child was stopped by %d.", getpid(), WSTOPSIG(childstatus));
			debugf("[%d] Sending PTRACE_CONT (and then KILL)\n", getpid());
			ptrace(PTRACE_CONT, childpid, NULL, NULL);
			kill(childpid, SIGKILL);
			reap_child(childpid);
		} else if (WIFCONTINUED(childstatus)) {
			break;
		} else {
			output("erk, wtf\n");
		}
	}
}

void main_loop()
{
	if (!shm->regenerate)
		regenerate();

	if (do_specific_syscall == 1)
		regenerate_random_page();

	while (1) {
		fork_children();
		handle_children();

		/* Only check taint if it was zero on startup */
		if (do_check_tainted == 0) {
			if (check_tainted() != 0) {
				output("kernel became tainted!\n");
				exit(EXIT_FAILURE);
			}
		}

		if (syscallcount && (shm->execcount >= syscallcount))
			exit(EXIT_SUCCESS);

		if (shm->execcount % 1000 == 0)
			synclogs();
	}
}
