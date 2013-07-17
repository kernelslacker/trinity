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
#include "trinity.h"

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
#else

// TODO: 32-bit syscall entry for non-x86 archs goes here.
	UNUSED(num_args);
	UNUSED(call);
	UNUSED(a1);
	UNUSED(a2);
	UNUSED(a3);
	UNUSED(a4);
	UNUSED(a5);
	UNUSED(a6);
#endif
	return 0;
}


static unsigned long do_syscall(int childno, int *errno_saved)
{
	int nr = shm->syscallno[childno];
	unsigned int num_args = syscalls[nr].entry->num_args;
	unsigned long a1, a2, a3, a4, a5, a6;
	unsigned long ret = 0;
	int pidslot;

	a1 = shm->a1[childno];
	a2 = shm->a2[childno];
	a3 = shm->a3[childno];
	a4 = shm->a4[childno];
	a5 = shm->a5[childno];
	a6 = shm->a6[childno];

	if (syscalls[nr].entry->flags & NEED_ALARM)
		(void)alarm(1);

	errno = 0;

	if (shm->do32bit[childno] == FALSE)
		ret = syscall(nr, a1, a2, a3, a4, a5, a6);
	else
		ret = syscall32(num_args, nr, a1, a2, a3, a4, a5, a6);

	*errno_saved = errno;

	if (syscalls[nr].entry->flags & NEED_ALARM)
		(void)alarm(0);

	pidslot = find_pid_slot(getpid());
	if (pidslot != PIDSLOT_NOT_FOUND) {
		shm->total_syscalls_done++;
		shm->child_syscall_count[pidslot]++;
		(void)gettimeofday(&shm->tv[pidslot], NULL);
	}

	return ret;
}

/*
 * Generate arguments, print them out, then call the syscall.
 */
long mkcall(int childno)
{
	unsigned long olda1, olda2, olda3, olda4, olda5, olda6;
	unsigned int call = shm->syscallno[childno];
	unsigned int call32, call64;
	unsigned long ret = 0;
	int errno_saved;
	char string[512], *sptr;

	shm->regenerate++;

	sptr = string;

	sptr += sprintf(sptr, "[%d] ", getpid());
	sptr += sprintf(sptr, "[%ld] ", shm->child_syscall_count[childno]);
	if (shm->do32bit[childno] == TRUE)
		sptr += sprintf(sptr, "[32BIT] ");

	olda1 = shm->a1[childno] = (unsigned long)rand64();
	olda2 = shm->a2[childno] = (unsigned long)rand64();
	olda3 = shm->a3[childno] = (unsigned long)rand64();
	olda4 = shm->a4[childno] = (unsigned long)rand64();
	olda5 = shm->a5[childno] = (unsigned long)rand64();
	olda6 = shm->a6[childno] = (unsigned long)rand64();

	if (call > max_nr_syscalls)
		sptr += sprintf(sptr, "%u", call);
	else
		sptr += sprintf(sptr, "%s", syscalls[call].entry->name);

	generic_sanitise(childno);
	if (syscalls[call].entry->sanitise)
		syscalls[call].entry->sanitise(childno);

/*
 * I *really* loathe how this macro has grown. It should be a real function one day.
 */
#define COLOR_ARG(ARGNUM, NAME, BIT, OLDREG, REG, TYPE)			\
	if ((logging == FALSE) && (quiet_level < MAX_LOGLEVEL))		\
		goto args_done;						\
									\
	if (syscalls[call].entry->num_args >= ARGNUM) {			\
		if (!NAME)						\
			goto args_done;					\
		if (ARGNUM != 1) {					\
			CRESET						\
			sptr += sprintf(sptr, ", ");			\
		}							\
		if (NAME)						\
			sptr += sprintf(sptr, "%s=", NAME);		\
									\
		if (OLDREG == REG) {					\
			CRESET						\
		} else {						\
			CYAN						\
		}							\
									\
		switch(TYPE) {						\
		case ARG_PATHNAME:					\
			sptr += sprintf(sptr, "\"%s\"", (char *) REG);	\
			break;						\
		case ARG_PID:						\
		case ARG_FD:						\
			CRESET						\
			sptr += sprintf(sptr, "%ld", REG);		\
			break;						\
		case ARG_MODE_T:					\
			CRESET						\
			sptr += sprintf(sptr, "%o", (mode_t) REG);	\
			break;						\
		case ARG_UNDEFINED:					\
		case ARG_LEN:						\
		case ARG_ADDRESS:					\
		case ARG_NON_NULL_ADDRESS:				\
		case ARG_RANGE:						\
		case ARG_OP:						\
		case ARG_LIST:						\
		case ARG_RANDPAGE:					\
		case ARG_CPU:						\
		case ARG_RANDOM_LONG:					\
		case ARG_IOVEC:						\
		case ARG_IOVECLEN:					\
		case ARG_SOCKADDR:					\
		case ARG_SOCKADDRLEN:					\
		default:						\
			if (REG > 8 * 1024)				\
				sptr += sprintf(sptr, "0x%lx", REG);	\
			else						\
				sptr += sprintf(sptr, "%ld", REG);	\
			CRESET						\
			break;						\
		}							\
		if (REG == (((unsigned long)page_zeros) & PAGE_MASK))	\
			sptr += sprintf(sptr, "[page_zeros]");		\
		if (REG == (((unsigned long)page_rand) & PAGE_MASK))	\
			sptr += sprintf(sptr, "[page_rand]");		\
		if (REG == (((unsigned long)page_0xff) & PAGE_MASK))	\
			sptr += sprintf(sptr, "[page_0xff]");		\
		if (REG == (((unsigned long)page_allocs) & PAGE_MASK))	\
			sptr += sprintf(sptr, "[page_allocs]");		\
	}

	CRESET
	sptr += sprintf(sptr, "(");

	COLOR_ARG(1, syscalls[call].entry->arg1name, 1<<5, olda1, shm->a1[childno], syscalls[call].entry->arg1type);
	COLOR_ARG(2, syscalls[call].entry->arg2name, 1<<4, olda2, shm->a2[childno], syscalls[call].entry->arg2type);
	COLOR_ARG(3, syscalls[call].entry->arg3name, 1<<3, olda3, shm->a3[childno], syscalls[call].entry->arg3type);
	COLOR_ARG(4, syscalls[call].entry->arg4name, 1<<2, olda4, shm->a4[childno], syscalls[call].entry->arg4type);
	COLOR_ARG(5, syscalls[call].entry->arg5name, 1<<1, olda5, shm->a5[childno], syscalls[call].entry->arg5type);
	COLOR_ARG(6, syscalls[call].entry->arg6name, 1<<0, olda6, shm->a6[childno], syscalls[call].entry->arg6type);
args_done:
	CRESET
	sptr += sprintf(sptr, ") ");
	*sptr = '\0';

	output(2, "%s", string);

	/* If we're going to pause, might as well sync pre-syscall */
	if (dopause == TRUE)
		synclogs();

	if (((unsigned long)shm->a1 == (unsigned long) shm) ||
	    ((unsigned long)shm->a2 == (unsigned long) shm) ||
	    ((unsigned long)shm->a3 == (unsigned long) shm) ||
	    ((unsigned long)shm->a4 == (unsigned long) shm) ||
	    ((unsigned long)shm->a5 == (unsigned long) shm) ||
	    ((unsigned long)shm->a6 == (unsigned long) shm)) {
		BUG("Address of shm ended up in a register!\n");
	}


	/* Some architectures (IA64/MIPS) start their Linux syscalls
	 * At non-zero, and have other ABIs below.
	 */
	call += SYSCALL_OFFSET;

	ret = do_syscall(childno, &errno_saved);

	sptr = string;

	if (IS_ERR(ret)) {
		RED
		sptr += sprintf(sptr, "= %ld (%s)", ret, strerror(errno_saved));
		CRESET
		shm->failures++;
	} else {
		GREEN
		if ((unsigned long)ret > 10000)
			sptr += sprintf(sptr, "= 0x%lx", ret);
		else
			sptr += sprintf(sptr, "= %ld", ret);
		CRESET
		shm->successes++;
	}

	*sptr = '\0';

	output(2, "%s\n", string);

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

		output(1, "%s (%d) returned ENOSYS, marking as inactive.\n", syscalls[call].entry->name, call);

		if (biarch == FALSE) {
			syscalls[call].entry->flags &= ~ACTIVE;
		} else {
			call32 = search_syscall_table(syscalls_32bit, max_nr_32bit_syscalls, syscalls[call].entry->name);
			syscalls_32bit[call32].entry->flags &= ~ACTIVE;
			call64 = search_syscall_table(syscalls_64bit, max_nr_64bit_syscalls, syscalls[call].entry->name);
			syscalls_64bit[call64].entry->flags &= ~ACTIVE;
			output(1, "Disabled syscalls 32bit:%d 64bit:%d\n", call32, call64);
		}
	}

skip_enosys:

	if (syscalls[call].entry->post)
	    syscalls[call].entry->post(ret);

	/* store info for debugging. */
	shm->previous_syscallno[childno] = shm->syscallno[childno];
	shm->previous_a1[childno] = shm->a1[childno];
	shm->previous_a2[childno] = shm->a2[childno];
	shm->previous_a3[childno] = shm->a3[childno];
	shm->previous_a4[childno] = shm->a4[childno];
	shm->previous_a5[childno] = shm->a5[childno];
	shm->previous_a6[childno] = shm->a6[childno];

	return ret;
}
