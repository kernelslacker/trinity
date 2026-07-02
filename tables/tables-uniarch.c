/*
 * Functions for handling the system call tables.
 * These functions are only used by architectures that have either 32 or 64 bit syscalls, but not both.
 */


#include <stdlib.h>
#include <string.h>
#include "arch.h"
#include "syscall.h"
#include "params.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "tables.h"

const struct syscalltable *syscalls;

unsigned int max_nr_syscalls;

void activate_syscall(unsigned int calln)
{
	activate_syscall_in_table(calln, &shm->nr_active_syscalls, syscalls,
				  shm->active_syscalls, false,
				  shm->active_cheap, &shm->nr_active_cheap,
				  shm->active_expensive, &shm->nr_active_exp);
}

void deactivate_syscall_uniarch(unsigned int calln)
{
	deactivate_syscall_in_table(calln, &shm->nr_active_syscalls, syscalls,
				    shm->active_syscalls, false,
				    shm->active_cheap, &shm->nr_active_cheap,
				    shm->active_expensive, &shm->nr_active_exp);
}

void toggle_syscall_n(int calln, bool state, const char *arg, const char *arg_name)
{
	struct syscallentry *entry;

	if (calln == -1) {
		outputerr("No idea what syscall (%s) is.\n", arg);
		exit(EXIT_FAILURE);
	}

	validate_specific_syscall(syscalls, calln);

	entry = syscalls[calln].entry;

	if (state == true) {
		entry->flags |= ACTIVE;
		/* `-c <syscall>` lands here from parse_args, before
		 * create_shm() has mapped the active table activate_
		 * syscall() writes into.  Defer the shm write to
		 * activate_flagged_syscalls() in munge_tables(); later
		 * callers (-r / -g) run post-create_shm and activate
		 * inline. */
		if (shm != NULL)
			activate_syscall(calln);
	} else {
		/* EXPLICITLY_EXCLUDED is the persistent record of "-x named this".
		 * It must survive deactivate_disabled_syscalls() (which only clears
		 * ACTIVE|TO_BE_DEACTIVATED) so syscall_nr_is_excluded() can honor
		 * -x at raw syscall sites under any targeting selector. */
		entry->flags |= TO_BE_DEACTIVATED | EXPLICITLY_EXCLUDED;
	}

	output(0, "Marking syscall %s (%d) as to be %sabled.\n",
		arg_name, calln,
		state ? "en" : "dis");
}


void enable_random_syscalls_uniarch(void)
{
	unsigned int call;
	struct syscallentry *entry;
	unsigned int retries = 0;

retry:
	if (retries++ > max_nr_syscalls * 2) {
		outputerr("enable_random_syscalls: no eligible syscall found after %u attempts\n",
			  retries - 1);
		return;
	}

	call = rnd_modulo_u32(max_nr_syscalls);
	entry = syscalls[call].entry;

	if (validate_specific_syscall_silent(syscalls, call) == false)
		goto retry;

	/* if we've set this to be disabled, don't enable it! */
	if (entry->flags & TO_BE_DEACTIVATED)
		goto retry;

	toggle_syscall_n(call, true, entry->name, entry->name);
}


int setup_syscall_group_uniarch(unsigned int group)
{
	unsigned int i;

	for_each_syscall(i) {
		struct syscallentry *entry = syscalls[i].entry;
		if (entry == NULL)
			continue;

		if (entry->group == group ||
		    group_parent[entry->group] == group) {
			entry->flags |= ACTIVE;
			activate_syscall(i);
		}
	}

	if (shm->nr_active_syscalls == 0) {
		outputstd("No syscalls found in group\n");
		return false;
	} else {
		outputstd("Found %d syscalls in group\n", shm->nr_active_syscalls);
	}

	return true;
}

/* Walk the syscall table and stamp any entry whose ACTIVE flag was
 * set before shm existed (today: `-c <syscall>` in parse_args) into
 * the shm-backed active table.  activate_syscall_in_table() short-
 * circuits on entry->active_number != 0, so this is idempotent for
 * entries that mark_all_syscalls_active_uniarch() or enable_random_
 * syscalls_uniarch() already activated. */
void activate_flagged_syscalls_uniarch(void)
{
	struct syscallentry *entry;
	unsigned int i;

	for_each_syscall(i) {
		entry = syscalls[i].entry;
		if (entry == NULL)
			continue;
		if ((entry->flags & ACTIVE) && entry->active_number == 0)
			activate_syscall(i);
	}
}

void mark_all_syscalls_active_uniarch(void)
{
	unsigned int i;

	for_each_syscall(i) {
		struct syscallentry *entry = syscalls[i].entry;
		if (entry == NULL)
			continue;

		entry->flags |= ACTIVE;
		activate_syscall(i);
	}
}

void init_syscalls_uniarch(void)
{
	unsigned int i;

	for_each_syscall(i) {
		struct syscallentry *entry = syscalls[i].entry;
		if (entry == NULL)
			continue;

		if (entry->flags & ACTIVE)
			if (entry->init)
				entry->init();
	}
}

void deactivate_disabled_syscalls_uniarch(void)
{
	unsigned int i;

	for_each_syscall(i) {
		struct syscallentry *entry = syscalls[i].entry;

		if (entry == NULL)
			continue;

		if (entry->flags & TO_BE_DEACTIVATED) {
			entry->flags &= ~(ACTIVE|TO_BE_DEACTIVATED);
			deactivate_syscall_uniarch(i);
			output(0, "Marked syscall %s (%d) as deactivated.\n",
				entry->name, entry->number);
		}
	}
}

void dump_syscall_tables_uniarch(void)
{
	unsigned int i;

	for_each_syscall(i) {
		struct syscallentry *entry = syscalls[i].entry;

		if (entry == NULL)
			continue;
		if (entry->flags & AVOID_SYSCALL)
			continue;
		/* Skip placeholder names that contain whitespace
		 * (e.g. "ni_syscall (generic)"); they don't round-trip
		 * through `trinity -c <name>`. */
		if (strchr(entry->name, ' ') != NULL)
			continue;

		outputstd("%s\n", entry->name);
	}
}

void display_enabled_syscalls_uniarch(void)
{
	unsigned int i;

	for_each_syscall(i) {
		struct syscallentry *entry = syscalls[i].entry;

		if (entry == NULL)
			continue;

		if (entry->flags & ACTIVE)
			output(0, "syscall %d:%s enabled.\n", i, entry->name);
	}
}
