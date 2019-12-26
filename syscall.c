/*
 * Functions for actually doing the system calls.
 */

#include <errno.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "arch.h"
#include "child.h"
#include "ftrace.h"
#include "params.h"
#include "pids.h"
#include "random.h"
#include "results.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"
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
	/* If we have CONFIG_IA32_EMULATION unset, we will segfault.
	 * Detect this case, and force 64-bit only.
	 */
	if (shm->syscalls32_succeeded == FALSE) {
		if (shm->syscalls32_attempted >= (max_children * 2)) {
			unsigned int i;

			lock(&shm->syscalltable_lock);

			/* check another thread didn't already do this. */
			if (shm->nr_active_32bit_syscalls == 0)
				goto already_done;

			output(0, "Tried %d 32-bit syscalls unsuccessfully. Disabling all 32-bit syscalls.\n",
					shm->syscalls32_attempted);

			for (i = 0; i < max_nr_32bit_syscalls; i++) {
				struct syscallentry *entry = syscalls[i].entry;

				if (entry->active_number != 0)
					deactivate_syscall(i, TRUE);
			}
already_done:
			unlock(&shm->syscalltable_lock);
		}

		shm->syscalls32_attempted++;
	}

	DO_32_SYSCALL

	if ((unsigned long)(__res) >= (unsigned long)(-133)) {
		errno = -(__res);
		__res = -1;
	}

	shm->syscalls32_succeeded = TRUE;

#else
	#error Implement 32-on-64 syscall macro for this architecture.
#endif
	return __res;
}
#else
#define syscall32(a,b,c,d,e,f,g) 0
#endif /* ARCH_IS_BIARCH */

static void __do_syscall(struct syscallrecord *rec, enum syscallstate state)
{
	unsigned long ret = 0;

	errno = 0;

	shm->stats.op_count++;

	if (dry_run == FALSE) {
		int nr, call;
		bool needalarm;

		nr = rec->nr;
		/* Some architectures (IA64/MIPS) start their Linux syscalls
		 * At non-zero, and have other ABIs below.
		 */
		call = nr + SYSCALL_OFFSET;
		needalarm = syscalls[nr].entry->flags & NEED_ALARM;
		if (needalarm)
			(void)alarm(1);

		lock(&rec->lock);
		rec->state = state;
		unlock(&rec->lock);

		if (rec->do32bit == FALSE) {
			ret = syscall(call, rec->a1, rec->a2, rec->a3, rec->a4, rec->a5, rec->a6);
		} else {
			ret = syscall32(call, rec->a1, rec->a2, rec->a3, rec->a4, rec->a5, rec->a6);
		}

		/* If we became tainted, get out as fast as we can. */
		if (is_tainted() == TRUE) {
			stop_ftrace();
			panic(EXIT_KERNEL_TAINTED);
			_exit(EXIT_FAILURE);
		}

		if (needalarm)
			(void)alarm(0);
	}

	lock(&rec->lock);
	rec->errno_post = errno;
	rec->retval = ret;
	rec->state = AFTER;
	unlock(&rec->lock);
}

/* This is a special case for things like execve, which would replace our
 * child process with something unknown to us. We use a 'throwaway' process
 * to do the execve in, and let it run for a max of a second before we kill it
 */
static void do_extrafork(struct syscallrecord *rec)
{
	pid_t pid = 0;
	pid_t extrapid;

	extrapid = fork();
	if (extrapid == 0) {
		/* grand-child */
		char childname[]="trinity-subchild";
		prctl(PR_SET_NAME, (unsigned long) &childname);

		__do_syscall(rec, GOING_AWAY);
		/* if this was for eg. an successful execve, we should never get here.
		 * if it failed though... */
		_exit(EXIT_SUCCESS);
	}

	/* misc failure. */
	if (extrapid == -1) {
		//debugf("Couldn't fork grandchild: %s\n", strerror(errno));
		return;
	}

	/* small pause to let grandchild do some work. */
	if (pid_alive(extrapid) == TRUE)
		usleep(100);

	/* We take the rec lock here even though we don't obviously use it.
	 * The reason, is that the grandchild is using it. */
	lock(&rec->lock);
	while (pid == 0) {
		int childstatus;

		pid = waitpid(extrapid, &childstatus, WUNTRACED | WCONTINUED | WNOHANG);
		if (pid_alive(extrapid) == TRUE)
			kill(extrapid, SIGKILL);
		usleep(1000);
	}
	unlock(&rec->lock);
}


void do_syscall(struct syscallrecord *rec)
{
	struct syscallentry *entry;
	unsigned int call;

	call = rec->nr;
	entry = syscalls[call].entry;

	if (entry->flags & EXTRA_FORK)
		do_extrafork(rec);
	else
		 /* common-case, do the syscall in this child process. */
		__do_syscall(rec, BEFORE);

	/* timestamp again for when we returned */
	clock_gettime(CLOCK_MONOTONIC, &rec->tp);
}

/*
 * If the syscall doesn't exist don't bother calling it next time.
 * Some syscalls return ENOSYS depending on their arguments, we mark
 * those as IGNORE_ENOSYS and keep calling them.
 */
static void deactivate_enosys(struct syscallrecord *rec, struct syscallentry *entry, unsigned int call)
{
	/* some syscalls return ENOSYS instead of EINVAL etc (futex for eg) */
	if (entry->flags & IGNORE_ENOSYS)
		return;

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

static void generic_post(const enum argtype type, unsigned long reg)
{
	void *ptr = (void *) reg;

	if ((type == ARG_PATHNAME) && (ptr != NULL))
		free(ptr);
}

void handle_syscall_ret(struct syscallrecord *rec)
{
	struct syscallentry *entry;
	unsigned int call;

	call = rec->nr;
	entry = syscalls[call].entry;

	if (rec->retval == -1UL) {
		int err = rec->errno_post;

		/* only check syscalls that completed. */
		//FIXME: how else would we get here?
		if (rec->state == AFTER) {
			if (err == ENOSYS)
				deactivate_enosys(rec, entry, call);

			entry->failures++;
			if (err < NR_ERRNOS) {
				entry->errnos[err]++;
			} else {
				// "These should never be seen by user programs."
				// But trinity isn't a 'normal' user program, we're doing
				// stuff that libc hides from apps.
				if (err < 512 || err > 530)
					printf("errno out of range after doing %s: %d:%s\n",
						entry->name,
						err, strerror(err));
			}
			shm->stats.failures++;
		}
	} else {
		handle_success(rec);	// Believe me folks, you'll never get bored with winning
		entry->successes++;
		shm->stats.successes++;
	}
	entry->attempted++;

	generic_post(entry->arg1type, rec->a1);
	generic_post(entry->arg2type, rec->a2);
	generic_post(entry->arg3type, rec->a3);
	generic_post(entry->arg4type, rec->a4);
	generic_post(entry->arg5type, rec->a5);
	generic_post(entry->arg6type, rec->a6);

	if (entry->post)
	    entry->post(rec);

	check_uid();

	generic_free_arg(rec);
}
