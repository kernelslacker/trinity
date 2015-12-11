/*
 * Call a single random syscall with random args.
 */

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
	dump_childnos();
	dump_childdata(this_child);
	panic(EXIT_PID_OUT_OF_RANGE);
}

static void check_sanity(struct syscallrecord *rec, struct syscallrecord *stash)
{
	unsigned int len;

	if (stash->tv.tv_sec != 0) {
		// FIXME: Should factor in loadavg here, as with enough pids, a child can exceed 60s
		//  without getting scheduled.
		if (rec->tv.tv_sec - stash->tv.tv_sec > 60) {
			output(0, "Sanity check failed. Something stomped on rec->tv after syscall:%s(%lx, %lx, %lx)  was:%lx now:%lx.\n",
				print_syscall_name(stash->nr, stash->do32bit),
				stash->a1, stash->a2, stash->a3, stash->tv.tv_sec, rec->tv.tv_sec);
			fail_sanity();
		}
	}

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
	syscallnr = rand() % max_nr_syscalls;

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
		if (shm->stats.total_syscalls_done >= syscalls_todo)
			shm->exit_reason = EXIT_REACHED_COUNT;
		return FAIL;
	}

	return TRUE;
}

bool child_random_syscalls(void)
{
	struct syscallrecord *rec, *stash;

	rec = &this_child->syscall;

	if (set_syscall_nr(rec) == FAIL)
		return FAIL;

	/* Generate arguments, print them out */

	generate_syscall_args(rec);

	output_syscall_prefix(rec);

	/* we stash a copy of this stuff in case something stomps the rec struct */
	stash = zmalloc(sizeof(struct syscallrecord));
	memcpy(stash, rec, sizeof(struct syscallrecord));

	do_syscall(rec);

	check_sanity(rec, stash);

	output_syscall_postfix(rec);

	handle_syscall_ret(rec);

	free(stash);

	return TRUE;
}
