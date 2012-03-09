/*
 * Functions for actually doing the system calls.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

#include "arch.h"
#include "trinity.h"
#include "sanitise.h"

static long mkcall(unsigned int call)
{
	unsigned long olda1, olda2, olda3, olda4, olda5, olda6;
	unsigned long a1, a2, a3, a4, a5, a6;
	int ret = 0;
	char string[512], *sptr=string;

	sigsetjmp(ret_jump, 1);

	sptr += sprintf(sptr, "[%d] %lu: ", getpid(), shm->execcount);

	olda1 = a1 = rand64();
	olda2 = a2 = rand64();
	olda3 = a3 = rand64();
	olda4 = a4 = rand64();
	olda5 = a5 = rand64();
	olda6 = a6 = rand64();

	if (call > max_nr_syscalls)
		sptr += sprintf(sptr, "%u", call);
	else
		sptr += sprintf(sptr, "%s", syscalls[call].entry->name);

	generic_sanitise(call, &a1, &a2, &a3, &a4, &a5, &a6);
	if (syscalls[call].entry->sanitise)
		syscalls[call].entry->sanitise(&a1, &a2, &a3, &a4, &a5, &a6);

#define COLOR_ARG(ARGNUM, NAME, BIT, OLDREG, REG)			\
	if (syscalls[call].entry->num_args >= ARGNUM) {			\
		if (!NAME)						\
			goto args_done;					\
		if (ARGNUM != 1)					\
			sptr += sprintf(sptr, WHITE ", ");		\
		if (NAME)						\
			sptr += sprintf(sptr, "%s=", NAME);		\
									\
		if (OLDREG == REG)					\
			sptr += sprintf(sptr, WHITE);			\
		else							\
			sptr += sprintf(sptr, CYAN);			\
		if (REG > 1024)						\
			sptr += sprintf(sptr, "0x%lx" WHITE, REG);	\
		else							\
			sptr += sprintf(sptr, "%ld" WHITE, REG);	\
									\
		if (REG == (unsigned long)page_zeros)			\
			sptr += sprintf(sptr, "[page_zeros]");		\
		if (REG == (unsigned long)page_rand)			\
			sptr += sprintf(sptr, "[page_rand]");		\
		if (REG == (unsigned long)page_0xff)			\
			sptr += sprintf(sptr, "[page_0xff]");		\
		if (REG == (unsigned long)page_allocs)			\
			sptr += sprintf(sptr, "[page_allocs]");		\
	}

	sptr += sprintf(sptr, WHITE "(");

	COLOR_ARG(1, syscalls[call].entry->arg1name, 1<<5, olda1, a1);
	COLOR_ARG(2, syscalls[call].entry->arg2name, 1<<4, olda2, a2);
	COLOR_ARG(3, syscalls[call].entry->arg3name, 1<<3, olda3, a3);
	COLOR_ARG(4, syscalls[call].entry->arg4name, 1<<2, olda4, a4);
	COLOR_ARG(5, syscalls[call].entry->arg5name, 1<<1, olda5, a5);
	COLOR_ARG(6, syscalls[call].entry->arg6name, 1<<0, olda6, a6);
args_done:
	sptr += sprintf(sptr, WHITE ") ");

	lock_logfile();
	output("%s", string);
	sptr = string;

	/* This sync is here halfway through just in case the syscall crashes. */
	sync_output();

	if (dopause == 1)
		sleep(1);

/* IA64 is retarde^Wspecial. */
#ifdef __ia64__
	call += 1024;
#endif

	ret = syscall(syscalls[call].entry->number, a1, a2, a3, a4, a5, a6);

	if (ret < 0) {
		sptr +=sprintf(sptr, RED "= %d (%s)" WHITE, ret, strerror(errno));
		shm->failures++;
	} else {
		sptr += sprintf(sptr, GREEN "= %d" WHITE, ret);
		shm->successes++;
	}
	sptr += sprintf(sptr, " [T:%ld F:%ld S:%ld]", shm->execcount, shm->failures, shm->successes);
	sptr += sprintf(sptr, "\n");

	output("%s", string);
	sptr = string;
	sync_output();
	unlock_logfile();

	if (quiet) {
		if (shm->execcount % 1000 == 0) {
			sptr = string;
			sptr += sprintf(sptr, "%ld\n", shm->execcount);
			printf("%s", string);
		}
	}

	/* If the syscall doesn't exist don't bother calling it next time. */
	if (ret == -ENOSYS)
		syscalls[call].entry->flags |= AVOID_SYSCALL;

	shm->execcount++;

	return ret;
}

int child_process(void)
{
	int ret = 0;
	unsigned int syscallnr;
	unsigned int left_to_do = syscalls_per_child;

	seed_from_tod();

	while (left_to_do > 0) {

		syscallnr = rand() % max_nr_syscalls;

		if (do_specific_syscall != 0)
			syscallnr = specific_syscall;
		else {

			if (syscalls[syscallnr].entry->num_args == 0)
				goto skip_syscall;

			if (syscalls[syscallnr].entry->flags & AVOID_SYSCALL)
				goto skip_syscall;

			if (syscalls[syscallnr].entry->flags & NI_SYSCALL)
				goto skip_syscall;
		}

		(void)alarm(3);

		ret = mkcall(syscallnr);

		(void)alarm(0);

skip_syscall:
		left_to_do--;
	}

	return ret;
}

static void regenerate()
{
	if (!shm->regenerate) {
		output("Regenerating random pages, fd's etc.\n");
		close_files();
		open_files();

		destroy_maps();
		setup_maps();

		shm->regenerate = REGENERATION_POINT - 1;

		regenerate_random_page();
	}
}

#define debug printf

void reap_child(pid_t childpid)
{
	unsigned int i;

	for (i = 0; i < shm->nr_childs; i++) {
		if (shm->pids[i] == childpid) {
			debug("Removing %d from pidmap\n", shm->pids[i]);
			shm->pids[i] = -1;
			shm->running_childs--;
			break;
		}
	}
}

void do_syscall_from_child()
{
	unsigned int i;
	int childpid, childstatus;

	regenerate();
	if (do_specific_syscall == 1)
		regenerate_random_page();

	while (1) {

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
			debug("Created child %d [total:%d/%d]\n", shm->pids[i], shm->running_childs, shm->nr_childs);
		}
		debug("created enough children\n\n");

		/* deal with child processes */

		childpid = waitpid(-1, &childstatus, WUNTRACED | WCONTINUED);
//		debug("waitpid returned %d status:%x\n", childpid, childstatus);

		switch (childpid) {
		case 0:
			debug("Nothing changed. children:%d\n", shm->running_childs);
			break;

		case -1:
			if (errno == ECHILD) {
				debug("All children exited!\n");
				return;
			}
			output("error! (%s)\n", strerror(errno));
			break;

		default:
			debug("Something happened to pid %d\n", childpid);
			if (WIFEXITED(childstatus)) {
				debug("Child %d exited\n", childpid);
				reap_child(childpid);
				break;

			} else if (WIFSIGNALED(childstatus)) {
				switch (WTERMSIG(childstatus)) {
				case SIGFPE:
				case SIGSEGV:
				case SIGKILL:
				case SIGALRM:
				case SIGPIPE:
					debug("Child got a signal (%d)\n", WTERMSIG(childstatus));
					reap_child(childpid);
					break;
				default:
					debug("** Child got an unhandled signal (%d)\n", WTERMSIG(childstatus));
					break;
				}
				break;

			} else if (WIFSTOPPED(childstatus)) {
				debug("Child was stopped by %d.", WSTOPSIG(childstatus));
				debug("Sending PTRACE_CONT (and then KILL)\n");
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
}
