/*
 * Functions for actually doing the system calls.
 */

#include <errno.h>
#include <string.h>
#include <sys/syscall.h>

#include "arch.h"
#include "child.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "log.h"
#include "tables.h"
#include "uid.h"
#include "utils.h"

#ifdef ARCH_IS_BIARCH
/*
 * This routine does 32 bit syscalls on 64 bit kernel.
 * 32-on-32 will just use syscall() directly from do_syscall() because do32bit flag is biarch only.
 */
static long syscall32(unsigned int call,
	unsigned long a1, unsigned long a2, unsigned long a3,
	unsigned long a4, unsigned long a5, unsigned long a6)
{
	long __res = 0;

#if defined(DO_32_SYSCALL)
	DO_32_SYSCALL
	__syscall_return(long, __res);
#else
	#error Implement 32-on-64 syscall macro for this architecture.
#endif
	return __res;
}
#else
#define syscall32(a,b,c,d,e,f,g) 0
#endif /* ARCH_IS_BIARCH */

static void __do_syscall(struct syscallrecord *rec)
{
	int nr, call;
	unsigned long ret = 0;
	bool needalarm;

	nr = rec->nr;

	/* Some architectures (IA64/MIPS) start their Linux syscalls
	 * At non-zero, and have other ABIs below.
	 */
	call = nr + SYSCALL_OFFSET;

	needalarm = syscalls[nr].entry->flags & NEED_ALARM;
	if (needalarm)
		(void)alarm(1);

	errno = 0;

	if (rec->do32bit == FALSE)
		ret = syscall(call, rec->a1, rec->a2, rec->a3, rec->a4, rec->a5, rec->a6);
	else
		ret = syscall32(call, rec->a1, rec->a2, rec->a3, rec->a4, rec->a5, rec->a6);

	/* We returned! */
	shm->total_syscalls_done++;

	lock(&rec->lock);
	(void)gettimeofday(&rec->tv, NULL);

	rec->op_nr++;
	rec->errno_post = errno;
	rec->retval = ret;
	rec->state = AFTER;
	unlock(&rec->lock);

	if (needalarm)
		(void)alarm(0);
}

void do_syscall(struct syscallrecord *rec)
{
	/* This is a special case for things like execve, which would replace our
	 * child process with something unknown to us. We use a 'throwaway' process
	 * to do the execve in, and let it run for a max of a seconds before we kill it */
#if 0
	if (syscalls[call].entry->flags & EXTRA_FORK) {
		pid_t extrapid;

		extrapid = fork();
		if (extrapid == 0) {
			__do_syscall();
			/* We should never get here. */
			rec->state = GOING_AWAY;
			_exit(EXIT_SUCCESS);
		} else {
			if (pid_alive(extrapid)) {
				sleep(1);
				kill(extrapid, SIGKILL);
			}
			generic_free_arg();
			return;
		}
	}

	/* common-case, do the syscall in this child process. */
#endif

	rec->state = BEFORE;
	__do_syscall(rec);

	if (IS_ERR(rec->retval))
		shm->failures++;
	else
		shm->successes++;
}

void handle_syscall_ret(struct syscallrecord *rec)
{
	struct syscallentry *entry;
	struct syscallrecord *previous;
	unsigned int call;

	/*
	 * If the syscall doesn't exist don't bother calling it next time.
	 * Some syscalls return ENOSYS depending on their arguments, we mark
	 * those as IGNORE_ENOSYS and keep calling them.
	 */
	call = rec->nr;
	entry = syscalls[call].entry;

	if ((rec->retval == -1UL) && (rec->errno_post == ENOSYS) && !(entry->flags & IGNORE_ENOSYS)) {
		lock(&shm->syscalltable_lock);

		/* check another thread didn't already do this. */
		if (entry->active_number == 0)
			goto already_done;

		output(1, "%s (%d%s) returned ENOSYS, marking as inactive.\n",
			entry->name,
			call + SYSCALL_OFFSET,
			rec->do32bit == TRUE ? ":[32BIT]" : "");

		deactivate_syscall(call, rec->do32bit);
already_done:
		unlock(&shm->syscalltable_lock);
	}

	if (entry->post)
	    entry->post(rec);

	/* store info for debugging. */
	previous = &this_child->previous;
	previous->nr = rec->nr;
	previous->a1 = rec->a1;
	previous->a2 = rec->a2;
	previous->a3 = rec->a3;
	previous->a4 = rec->a4;
	previous->a5 = rec->a5;
	previous->a6 = rec->a6;
	previous->do32bit = rec->do32bit;
	previous->state = DONE;

	check_uid();

	generic_free_arg(rec);
}
