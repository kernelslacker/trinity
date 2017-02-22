/*
 * Functions for handling the system call tables.
 * These functions are only used by architectures that have either 32 or 64 bit syscalls, but not both.
 */

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include "arch.h"
#include "syscall.h"
#include "params.h"
#include "random.h"
#include "shm.h"
#include "tables.h"

const struct syscalltable *syscalls;

unsigned int max_nr_syscalls;

void activate_syscall(unsigned int calln)
{
	activate_syscall_in_table(calln, &shm->nr_active_syscalls, syscalls, shm->active_syscalls);
}

void deactivate_syscall_uniarch(unsigned int calln)
{
	deactivate_syscall_in_table(calln, &shm->nr_active_syscalls, syscalls, shm->active_syscalls);
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

	if (state == TRUE) {
		entry->flags |= ACTIVE;
		activate_syscall(calln);
	} else {
		entry->flags |= TO_BE_DEACTIVATED;
	}

	output(0, "Marking syscall %s (%d) as to be %sabled.\n",
		arg_name, calln,
		state ? "en" : "dis");
}


void enable_random_syscalls_uniarch(void)
{
	unsigned int call;
	struct syscallentry *entry;

retry:
	call = rnd() % max_nr_syscalls;
	entry = syscalls[call].entry;

	if (validate_specific_syscall_silent(syscalls, call) == FALSE)
		goto retry;

	/* if we've set this to be disabled, don't enable it! */
	if (entry->flags & TO_BE_DEACTIVATED)
		goto retry;

	toggle_syscall_n(call, TRUE, entry->name, entry->name);
}


int setup_syscall_group_uniarch(unsigned int group)
{
	unsigned int i;

	for_each_syscall(i) {
		if (syscalls[i].entry->group == group)
			activate_syscall(i);
	}

	if (shm->nr_active_syscalls == 0) {
		outputstd("No syscalls found in group\n");
		return FALSE;
	} else {
		outputstd("Found %d syscalls in group\n", shm->nr_active_syscalls);
	}

	return TRUE;
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

	outputstd("syscalls: %d\n", max_nr_syscalls);

	for_each_syscall(i) {
		struct syscallentry *entry = syscalls[i].entry;

		if (entry == NULL)
			continue;

		outputstd("entrypoint %d %s : ", entry->number, entry->name);
		show_state(entry->flags & ACTIVE);
		if (entry->flags & AVOID_SYSCALL)
			outputstd(" AVOID");
		outputstd("\n");
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
