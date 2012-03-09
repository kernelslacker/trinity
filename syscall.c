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
	mask_signals();

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

		if (ctrlc_hit == 1)
			break;
	}

	return ret;
}

static void regenerate()
{
	if (!shm->regenerate) {
		close_files();
		open_files();

		destroy_maps();
		setup_maps();

		shm->regenerate = REGENERATION_POINT - 1;

		regenerate_random_page();
	}
}

#define debug printf

void do_syscall_from_child()
{
	pid_t pids[64];
	unsigned int i;
	unsigned int nr_childs = min(64, sysconf(_SC_NPROCESSORS_ONLN));
	unsigned int running_childs = 0;
	int childpid, childstatus;

	memset(pids, -1, sizeof(pids));

	regenerate();
	if (do_specific_syscall == 1)
		regenerate_random_page();

	while (1) {

		/* Generate children*/

		while (running_childs < nr_childs) {

			/* Find a space for it in the pid map */
			for (i = 0; i < nr_childs; i++) {
				if (pids[i] == -1)
					break;
			}
			if (i >= nr_childs) {
				output("pid map full!\n");
				exit(EXIT_FAILURE);
			}
			pids[i] = fork();
			if (pids[i] == 0) {
				int ret = 0;

				ret = child_process();
				shm->regenerate--;

				_exit(ret);
			}
			running_childs++;
			debug("Created child %d [total:%d/%d]\n", pids[i], running_childs, nr_childs);
		}

		/* deal with child processes */

		childpid = waitpid(-1, &childstatus, WNOHANG | WUNTRACED | WCONTINUED);

		switch (childpid) {
		case 0:
			debug("Nothing changed. children:%d\n", running_childs);
			/* FIXME: This reaping of dead children shouldn't be necessary.
			    There's a bug somewhere that causes the default switch case
			    never to be taken. */
			for (i = 0; i < nr_childs; i++) {
				if (pids[i] != -1) {
					pid_t pid = waitpid(pids[i], NULL, WNOHANG);
					if (pid == -1) {
						if (errno == ECHILD) {
							debug("pid %d disappeared.", pids[i]);
							debug("Removing from pidmap\n");
							pids[i] = -1;
							running_childs--;
						}
					}
				}
			}
			debug("pids:");
			for (i = 0; i < nr_childs; i++) {
				if (pids[i] != -1)
					debug("%d ", pids[i]);
			}
			debug("\n");
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
				for (i = 0; i < nr_childs; i++) {
					if (pids[i] == childpid) {
						debug("Removing %d from pidmap\n", pids[i]);
						pids[i] = -1;
						running_childs--;
						break;
					}
				}
				break;

			} else if (WIFSIGNALED(childstatus)) {
				debug("Child got a signal (%d)\n", WTERMSIG(childstatus));
				if (WTERMSIG(childstatus) == SIGKILL) {
					for (i = 0; i < nr_childs; i++) {
						if (pids[i] == childpid) {
							debug("Removing %d from pidmap\n", pids[i]);
							pids[i] = -1;
							running_childs--;
							break;
						}
					}
				}
				break;

			} else if (WIFSTOPPED(childstatus)) {
				debug("Child was stopped. Sending CONT\n");
				ptrace(PTRACE_CONT, childpid, NULL, NULL);
			} else {
				output("erk, wtf\n");
			}
		}

		sleep(1);

		if (ctrlc_hit == 1)
			return;
	}
}
