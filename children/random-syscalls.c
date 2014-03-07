/*
 * Call random syscalls with random args.
 */

#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "arch.h"	// biarch
#include "child.h"
#include "syscall.h"
#include "locks.h"
#include "log.h"
#include "random.h"
#include "shm.h"
#include "signals.h"
#include <string.h>
#include "pids.h"
#include "tables.h"

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
		do32 = TRUE;
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
			if (rand() % 100 < 10)
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

static unsigned int handle_sigreturn(int childno)
{
	static unsigned int count = 0;
	static unsigned int last = -1;

	output(2, "<timed out>\n");	/* Flush out the previous syscall output. */

	/* Check if we're making any progress at all. */
	if (shm->child_syscall_count[childno] == last) {
		count++;
		//output(1, "no progress for %d tries.\n", count);
	} else {
		count = 0;
		last = shm->child_syscall_count[childno];
	}
	if (count == 3) {
		output(1, "no progress for 3 tries, exiting child.\n");
		return 0;
	}

	if (shm->kill_count[childno] > 0) {
		output(1, "[%d] Missed a kill signal, exiting\n", getpid());
		return 0;
	}

	if (sigwas != SIGALRM)
		output(1, "[%d] Back from signal handler! (sig was %s)\n", getpid(), strsignal(sigwas));

	return 1;
}

int child_random_syscalls(int childno)
{
	int ret;
	unsigned int syscallnr;
	bool do32;

	ret = sigsetjmp(ret_jump, 1);
	if (ret != 0) {
		if (handle_sigreturn(childno) == 0)
			return 0;
		ret = 0;
	}

	while (shm->exit_reason == STILL_RUNNING) {

		check_parent_pid();

		while (shm->regenerating == TRUE)
			sleep(1);

		/* If the parent reseeded, we should reflect the latest seed too. */
		if (shm->seed != shm->seeds[childno])
			set_seed(childno);

		do32 = choose_syscall_table();

		if (no_syscalls_enabled() == TRUE) {
			output(0, "[%d] No more syscalls enabled. Exiting\n", getpid());
			shm->exit_reason = EXIT_NO_SYSCALLS_ENABLED;
			goto out;
		}

		if (shm->exit_reason != STILL_RUNNING)
			goto out;

		syscallnr = rand() % max_nr_syscalls;
		/* If we got a syscallnr which is not active repeat the attempt, since another child has switched that syscall off already.*/
		if (active_syscalls[syscallnr] == 0)
			continue;

		syscallnr = active_syscalls[syscallnr] - 1;

		if (validate_specific_syscall_silent(syscalls, syscallnr) == FALSE) {
			if (biarch == FALSE) {
				deactivate_syscall(syscallnr);
			} else {
				if (do32 == TRUE)
					deactivate_syscall32(syscallnr);
				else
					deactivate_syscall64(syscallnr);
			}
			continue;
		}

		lock(&shm->syscall_lock);
		shm->do32bit[childno] = do32;
		shm->syscallno[childno] = syscallnr;
		unlock(&shm->syscall_lock);

		if (syscalls_todo) {
			if (shm->total_syscalls_done >= syscalls_todo) {
				output(0, "Reached maximum syscall count (todo = %d, done = %d), exiting...\n",
					syscalls_todo, shm->total_syscalls_done);
				shm->exit_reason = EXIT_REACHED_COUNT;
			}
		}

		ret = mkcall(childno);
	}
out:
	return ret;
}
