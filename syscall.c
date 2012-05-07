/*
 * Functions for actually doing the system calls.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include "arch.h"
#include "trinity.h"
#include "sanitise.h"

#define __syscall_return(type, res) \
	do { \
	if ((unsigned long)(res) >= (unsigned long)(-125)) { \
		errno = -(res); \
		res = -1; \
	} \
	return (type) (res); \
} while (0)

static long syscall32(int num_args, unsigned int call,
	unsigned long a1, unsigned long a2, unsigned long a3,
	unsigned long a4, unsigned long a5, __unused__ unsigned long a6)
{
#if defined(__i386__) || defined (__x86_64__)
	if (num_args < 6) {
		long __res;
		__asm__ volatile ("int $0x80"
			: "=a" (__res)
			: "0" (call),"b" ((long)(a1)),"c" ((long)(a2)),
			"d" ((long)(a3)), "S" ((long)(a4)),
			"D" ((long)(a5)));
		__syscall_return(long,__res);
		return __res;
	}
/* TODO: 6 arg 32bit x86 syscall goes here.*/
#endif

	// TODO: 32-bit syscall entry for non-x86 archs goes here.
	return 0;
}


static unsigned long do_syscall(unsigned int num_args, int nr, unsigned long a1, unsigned long a2, unsigned long a3,
			unsigned long a4, unsigned long a5, unsigned long a6)
{
	int childpid, childstatus;
	int ret = 0;

	if (extrafork == FALSE) {
		(void)alarm(3);
		if (shm->do32bit == FALSE)
			ret = syscall(nr, a1, a2, a3, a4, a5, a6);
		else
			ret = syscall32(num_args, nr, a1, a2, a3, a4, a5, a6);
		(void)alarm(0);
		return ret;
	}

	/* Do the actual syscall in another child. */
	childpid = fork();
	if (childpid == 0) {
		(void)alarm(3);
		ret = syscall(nr, a1, a2, a3, a4, a5, a6);
		(void)alarm(0);
		_exit(ret);
	}
	childpid = waitpid(childpid, &childstatus, 0);
	switch (childpid) {
	case 0:	output("wtf\n");
		break;

	case -1: output("[%d] Something bad happened to child %d :(\n", getpid(), childpid);
		break;

	default:
		if (WIFEXITED(childstatus)) {
			ret = WEXITSTATUS(childstatus);
			output("[%d] Child %d exited with return code %d\n", getpid(), childpid, ret);
			break;
		}
		if (WIFSIGNALED(childstatus)) {
			output("[%d] Child %d got a signal (%s)\n", getpid(), childpid, strsignal(WTERMSIG(childstatus)));
			ret = -1;
			break;
		}
		if (WIFSTOPPED(childstatus)) {
			output("[%d] Child process %d stopped. killing.\n", getpid(), childpid);
			ptrace(PTRACE_CONT, childpid, NULL, NULL);
			kill(childpid, SIGKILL);
			break;
		}
		break;
	}
	return ret;
}

static long mkcall(unsigned int call)
{
	unsigned long olda1, olda2, olda3, olda4, olda5, olda6;
	unsigned long a1, a2, a3, a4, a5, a6;
	int ret = 0;
	char string[512], *sptr;

	sigsetjmp(ret_jump, 1);

	sptr = string;
	memset(string, 0, sizeof(string));

	sptr += sprintf(sptr, "[%d] ", getpid());
	if (shm->do32bit == TRUE)
		sptr += sprintf(sptr, "[32BIT] ");

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
		if (REG == (((unsigned long)page_zeros) & PAGE_MASK))	\
			sptr += sprintf(sptr, "[page_zeros]");		\
		if (REG == (((unsigned long)page_rand) & PAGE_MASK))	\
			sptr += sprintf(sptr, "[page_rand]");		\
		if (REG == (((unsigned long)page_0xff) & PAGE_MASK))	\
			sptr += sprintf(sptr, "[page_0xff]");		\
		if (REG == (((unsigned long)page_allocs) & PAGE_MASK))	\
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

	output("%s", string);

	if (dopause == 1)
		sleep(1);

/* IA64 is retarde^Wspecial. */
#ifdef __ia64__
	call += 1024;
#endif
	ret = do_syscall(syscalls[call].entry->num_args, syscalls[call].entry->number, a1, a2, a3, a4, a5, a6);

	sptr = string;
	memset(string, 0, sizeof(string));

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

	if (quiet) {
		if (shm->execcount % 1000 == 0) {
			sptr = string;
			sptr += sprintf(sptr, "%ld", shm->execcount);
			printf("%s iterations.\n", string);
		}
	}

	/* If the syscall doesn't exist don't bother calling it next time. */
	if (ret == -ENOSYS)
		syscalls[call].entry->flags |= AVOID_SYSCALL;

	shm->execcount++;

	if (syscalls[call].entry->post)
	    syscalls[call].entry->post(ret);
	return ret;
}

int child_process(void)
{
	cpu_set_t set;
	pid_t pid = getpid();
	int ret = 0;
	unsigned int syscallnr;
	unsigned int cpu;
	unsigned int left_to_do = syscalls_per_child;

	seed_from_tod();

	for (cpu = 0; cpu < shm->nr_childs; cpu++) {
		if (shm->pids[cpu] == pid)
			break;
	}

	if (sched_getaffinity(pid, sizeof(set), &set) == 0) {
		CPU_ZERO(&set);
		CPU_SET(cpu, &set);
		sched_setaffinity(getpid(), sizeof(set), &set);
		output("bound child %d to cpu %d\n", pid, cpu);
	}

	while (left_to_do > 0) {

		if (biarch == TRUE) {
			/*
			 * 10% possibility of a 32bit syscall
			 */
			shm->do32bit = FALSE;
//			if (rand() % 100 < 10)
//				shm->do32bit = TRUE;

			if (shm->do32bit == TRUE) {
				syscalls = syscalls_64bit;
				max_nr_syscalls = max_nr_64bit_syscalls;
			} else {
				syscalls = syscalls_32bit;
				max_nr_syscalls = max_nr_32bit_syscalls;
			}
		}

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

		ret = mkcall(syscallnr);

skip_syscall:
		left_to_do--;
	}

	return ret;
}
