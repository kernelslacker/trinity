/*
 * Functions for actually doing the system calls.
 */

#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include "arch.h"
#include "child.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "pids.h"
#include "log.h"
#include "params.h"
#include "maps.h"
#include "tables.h"
#include "trinity.h"
#include "uid.h"
#include "utils.h"

#define __syscall_return(type, res) \
	do { \
	if ((unsigned long)(res) >= (unsigned long)(-125)) { \
		errno = -(res); \
		res = -1; \
	} \
	return (type) (res); \
} while (0)

#ifdef ARCH_IS_BIARCH
/*
 * This routine does 32 bit syscalls on 64 bit kernel.
 * 32-on-32 will just use syscall() directly from do_syscall() because do32bit flag is biarch only.
 */
long syscall32(unsigned int call,
	unsigned long a1, unsigned long a2, unsigned long a3,
	unsigned long a4, unsigned long a5, unsigned long a6)
{
	long __res = 0;

//FIXME: Move the implementations out to arch header files.

#if defined(__x86_64__)
	__asm__ volatile (
		"pushq %%rbp\n\t"
		"pushq %%r10\n\t"
		"pushq %%r11\n\t"
		"movq %7, %%rbp\n\t"
		"int $0x80\n\t"
		"popq %%r11\n\t"
		"popq %%r10\n\t"
		"popq %%rbp\n\t"
		: "=a" (__res)
		: "0" (call),"b" ((long)(a1)),"c" ((long)(a2)),"d" ((long)(a3)), "S" ((long)(a4)),"D" ((long)(a5)), "g" ((long)(a6))
		: "%rbp" /* mark EBP reg as dirty */
	);
	__syscall_return(long, __res);

#else
	/* non-x86 implementations go here. */
	#error Implement 32-on-64 syscall in syscall.c:syscall32() for this architecture.

#endif
	return __res;
}
#else
#define syscall32(a,b,c,d,e,f,g) 0
#endif /* ARCH_IS_BIARCH */

static unsigned long do_syscall(int childno, int *errno_saved)
{
	int nr = shm->syscall[childno].nr;
	unsigned long a1, a2, a3, a4, a5, a6;
	unsigned long ret = 0;

	a1 = shm->syscall[childno].a1;
	a2 = shm->syscall[childno].a2;
	a3 = shm->syscall[childno].a3;
	a4 = shm->syscall[childno].a4;
	a5 = shm->syscall[childno].a5;
	a6 = shm->syscall[childno].a6;

	shm->total_syscalls_done++;
	shm->child_syscall_count[childno]++;
	(void)gettimeofday(&shm->tv[childno], NULL);

	if (syscalls[nr].entry->flags & NEED_ALARM)
		(void)alarm(1);

	errno = 0;

	if (shm->syscall[childno].do32bit == FALSE)
		ret = syscall(nr, a1, a2, a3, a4, a5, a6);
	else
		ret = syscall32(nr, a1, a2, a3, a4, a5, a6);

	*errno_saved = errno;

	if (syscalls[nr].entry->flags & NEED_ALARM)
		(void)alarm(0);

	return ret;
}

/*
 * Generate arguments, print them out, then call the syscall.
 */
void mkcall(int childno)
{
	struct syscallentry *entry;
	unsigned int call = shm->syscall[childno].nr;
	unsigned long ret = 0;
	int errno_saved;

	entry = syscalls[call].entry;

	shm->regenerate++;

	shm->syscall[childno].a1 = (unsigned long) rand64();
	shm->syscall[childno].a2 = (unsigned long) rand64();
	shm->syscall[childno].a3 = (unsigned long) rand64();
	shm->syscall[childno].a4 = (unsigned long) rand64();
	shm->syscall[childno].a5 = (unsigned long) rand64();
	shm->syscall[childno].a6 = (unsigned long) rand64();

	generic_sanitise(childno);
	if (entry->sanitise)
		entry->sanitise(childno);

	output_syscall_prefix(childno, call);

	/* If we're going to pause, might as well sync pre-syscall */
	if (dopause == TRUE)
		synclogs();

	/* Some architectures (IA64/MIPS) start their Linux syscalls
	 * At non-zero, and have other ABIs below.
	 */
	call += SYSCALL_OFFSET;

	/* This is a special case for things like execve, which would replace our
	 * child process with something unknown to us. We use a 'throwaway' process
	 * to do the execve in, and let it run for a max of a seconds before we kill it */
	if (syscalls[call].entry->flags & EXTRA_FORK) {
		pid_t extrapid;

		extrapid = fork();
		if (extrapid == 0) {
			ret = do_syscall(childno, &errno_saved);
			shm->syscall[childno].retval = ret;
			_exit(EXIT_SUCCESS);
		} else {
			if (pid_alive(extrapid)) {
				sleep(1);
				kill(extrapid, SIGKILL);
			}
		}
	} else {
		/* common-case, do the syscall in this child process. */
		ret = do_syscall(childno, &errno_saved);
		shm->syscall[childno].retval = ret;
	}

	if (IS_ERR(ret))
		shm->failures++;
	else
		shm->successes++;

	output_syscall_postfix(ret, errno_saved, IS_ERR(ret));
	if (dopause == TRUE)
		sleep(1);

	/* If the syscall doesn't exist don't bother calling it next time. */
	if ((ret == -1UL) && (errno_saved == ENOSYS)) {

		/* Futex is awesome, it ENOSYS's depending on arguments. Sigh. */
		if (call == (unsigned int) search_syscall_table(syscalls, max_nr_syscalls, "futex"))
			goto skip_enosys;

		/* Unknown ioctls also ENOSYS. */
		if (call == (unsigned int) search_syscall_table(syscalls, max_nr_syscalls, "ioctl"))
			goto skip_enosys;

		/* sendfile() may ENOSYS depending on args. */
		if (call == (unsigned int) search_syscall_table(syscalls, max_nr_syscalls, "sendfile"))
			goto skip_enosys;

		output(1, "%s (%d) returned ENOSYS, marking as inactive.\n",
			entry->name, call);

		if (biarch == FALSE) {
			deactivate_syscall(call);
		} else {
			if (shm->syscall[childno].do32bit == TRUE)
				deactivate_syscall32(call);
			else
				deactivate_syscall64(call);
		}
	}

skip_enosys:

	if (entry->post)
	    entry->post(childno);

	/* store info for debugging. */
	shm->previous[childno].nr = shm->syscall[childno].nr;
	shm->previous[childno].a1 = shm->syscall[childno].a1;
	shm->previous[childno].a2 = shm->syscall[childno].a2;
	shm->previous[childno].a3 = shm->syscall[childno].a3;
	shm->previous[childno].a4 = shm->syscall[childno].a4;
	shm->previous[childno].a5 = shm->syscall[childno].a5;
	shm->previous[childno].a6 = shm->syscall[childno].a6;
	shm->previous[childno].do32bit = shm->syscall[childno].do32bit;

	check_uid();
}

bool this_syscallname(const char *thisname, int childno)
{
	unsigned int call = shm->syscall[childno].nr;
	struct syscallentry *syscall_entry = syscalls[call].entry;

	return strcmp(thisname, syscall_entry->name);
}
