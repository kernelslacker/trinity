/*
 * Call a single random syscall with random args.
 */

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "arch.h"	// biarch
#include "child.h"
#include "debug.h"
#include "locks.h"
#include "log.h"
#include "pids.h"
#include "random.h"
#include "shm.h"
#include "signals.h"
#include "sanitise.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"

/*
 * This function decides if we're going to be doing a 32bit or 64bit syscall.
 * There are various factors involved here, from whether we're on a 32-bit only arch
 * to 'we asked to do a 32bit only syscall' and more.. Hairy.
 */

static int *active_syscalls;

static bool choose_syscall_table(void)
{
	bool do32 = FALSE;

	if (biarch == FALSE) {
		active_syscalls = shm->active_syscalls;
	} else {

		/* First, check that we have syscalls enabled in either table. */
		if (validate_syscall_table_64() == FALSE) {
			use_64bit = FALSE;
			/* If no 64bit syscalls enabled, force 32bit. */
			do32 = TRUE;
		}

		if (validate_syscall_table_32() == FALSE)
			use_32bit = FALSE;

		/* If both tables enabled, pick randomly. */
		if ((use_64bit == TRUE) && (use_32bit == TRUE)) {
			/* 10% possibility of a 32bit syscall */
			if (ONE_IN(10))
				do32 = TRUE;
		}

		if (do32 == FALSE) {
			syscalls = syscalls_64bit;
			active_syscalls = shm->active_syscalls64;
			max_nr_syscalls = max_nr_64bit_syscalls;
		} else {
			syscalls = syscalls_32bit;
			active_syscalls = shm->active_syscalls32;
			max_nr_syscalls = max_nr_32bit_syscalls;
		}
	}
	return do32;
}

static void fail_sanity(void)
{
	struct childdata *child = this_child();

	dump_childnos();
	dump_childdata(child);
	panic(EXIT_SHM_CORRUPTION);
}

static void check_sanity(struct syscallrecord *rec, struct syscallrecord *stash)
{
	unsigned int len;

	len = strlen(stash->prebuffer);
	if (len != strlen(rec->prebuffer)) {
		output(0, "Sanity check failed: prebuffer length changed from %d to %d after syscall:%s(%lx, %lx, %lx).\n",
			len, strlen(rec->prebuffer),
			print_syscall_name(stash->nr, stash->do32bit),
			stash->a1, stash->a2, stash->a3);
		fail_sanity();
	}
}

static bool set_syscall_nr(struct syscallrecord *rec)
{
	unsigned int syscallnr;
	bool do32;

retry:
	if (no_syscalls_enabled() == TRUE) {
		output(0, "[%d] No more syscalls enabled. Exiting\n", getpid());
		shm->exit_reason = EXIT_NO_SYSCALLS_ENABLED;
		return FAIL;
	}

	/* Ok, we're doing another syscall, let's pick one. */
	do32 = choose_syscall_table();
	syscallnr = rnd() % max_nr_syscalls;

	/* If we got a syscallnr which is not active repeat the attempt,
	 * since another child has switched that syscall off already.*/
	if (active_syscalls[syscallnr] == 0)
		goto retry;

	syscallnr = active_syscalls[syscallnr] - 1;

	if (validate_specific_syscall_silent(syscalls, syscallnr) == FALSE) {
		deactivate_syscall(syscallnr, do32);
		goto retry;
	}

	/* critical section for shm updates. */
	lock(&rec->lock);
	rec->do32bit = do32;
	rec->nr = syscallnr;
	unlock(&rec->lock);

	if (syscalls_todo) {
		if (shm->stats.op_count >= syscalls_todo) {
			shm->exit_reason = EXIT_REACHED_COUNT;
			return FAIL;
		}
	}

	return TRUE;
}

/*
static bool do_syscall_in_child(struct syscallrecord *rec, struct childdata *child)
{
	pid_t pid;

	pid = fork();
	if (pid == 0) {
		// child
		do_syscall(rec);
		_exit(EXIT_SUCCESS);
	} else if (pid > 0) {
		// parent
		int childret = 0;
		int childstatus;

		// wait for child to exit, or kill it.
		while (childret == 0) {

			clock_gettime(CLOCK_MONOTONIC, &child->tp);

			if (pid_alive(pid) == TRUE) {
				kill_pid(pid);
				childret = waitpid(pid, &childstatus, WUNTRACED | WCONTINUED | WNOHANG);
				if (childret == 0)
					usleep(10000);
			}
		}
		// and do the same work in the parent.
		do_syscall(rec);
		return TRUE;
	} else {
		// fork failed
		return FALSE;
	}
}
*/

bool random_syscall(struct childdata *child)
{
	struct syscallrecord *rec, *stash;
	int ret = FALSE;

	rec = &child->syscall;

	if (set_syscall_nr(rec) == FAIL)
		return FAIL;

	/* Generate arguments, print them out */

	generate_syscall_args(rec);

	output_syscall_prefix(rec);

	/* we stash a copy of this stuff in case something stomps the rec struct */
	stash = zmalloc(sizeof(struct syscallrecord));
	memcpy(stash, rec, sizeof(struct syscallrecord));

/*
	if (ONE_IN(100)) {
		if (do_syscall_in_child(rec, child) == FALSE)
			goto fail;
	} else
*/
	do_syscall(rec);

	check_sanity(rec, stash);

	output_syscall_postfix(rec);

	handle_syscall_ret(rec);

	ret = TRUE;
//fail:
	free(stash);

	return ret;
}
