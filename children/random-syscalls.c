/*
 * Call a single random syscall with random args.
 */

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "arch.h"	// biarch
#include "child.h"
#include "syscall.h"
#include "locks.h"
#include "log.h"
#include "random.h"
#include "shm.h"
#include "signals.h"
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

bool child_random_syscalls(int childno)
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
	syscallnr = rand() % max_nr_syscalls;

	/* If we got a syscallnr which is not active repeat the attempt,
	 * since another child has switched that syscall off already.*/
	if (active_syscalls[syscallnr] == 0)
		goto retry;

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
		goto retry;
	}

	/* critical section for shm updates. */
	lock(&shm->syscall_lock);
	shm->syscall[childno].do32bit = do32;
	shm->syscall[childno].nr = syscallnr;
	unlock(&shm->syscall_lock);

	if (syscalls_todo) {
		if (shm->total_syscalls_done >= syscalls_todo)
			shm->exit_reason = EXIT_REACHED_COUNT;
	}

	/* Do the actual syscall. */
	return mkcall(childno);
}
