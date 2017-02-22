/*
 * Functions for handling the system call tables.
 * These functions are only used on architectures that have both 32 and 64 bit syscalls.
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

#define NOTFOUND (unsigned int)-1

const struct syscalltable *syscalls_32bit;
const struct syscalltable *syscalls_64bit;

unsigned int max_nr_32bit_syscalls;
unsigned int max_nr_64bit_syscalls;

bool use_32bit = FALSE;
bool use_64bit = FALSE;

void activate_syscall32(unsigned int calln)
{
	activate_syscall_in_table(calln, &shm->nr_active_32bit_syscalls, syscalls_32bit, shm->active_syscalls32);
}

void activate_syscall64(unsigned int calln)
{
	activate_syscall_in_table(calln, &shm->nr_active_64bit_syscalls, syscalls_64bit, shm->active_syscalls64);
}

void deactivate_syscall32(unsigned int calln)
{
	deactivate_syscall_in_table(calln, &shm->nr_active_32bit_syscalls, syscalls_32bit, shm->active_syscalls32);
}

void deactivate_syscall64(unsigned int calln)
{
	deactivate_syscall_in_table(calln, &shm->nr_active_64bit_syscalls, syscalls_64bit, shm->active_syscalls64);
}


int validate_syscall_table_64(void)
{
	if (shm->nr_active_64bit_syscalls == 0)
		use_64bit = FALSE;
	else
		use_64bit = TRUE;

	return use_64bit;
}

int validate_syscall_table_32(void)
{
	if (shm->nr_active_32bit_syscalls == 0)
		use_32bit = FALSE;
	else
		use_32bit = TRUE;

	return use_32bit;
}

static void toggle_syscall_biarch_n(int calln, const struct syscalltable *table,
				    bool onlyflag, bool doflag, bool state,
				    void (*activate)(unsigned int),
				    int arch_bits, const char *arg_name)
{
	if (calln != -1) {
		struct syscallentry *entry = table[calln].entry;

		validate_specific_syscall(table, calln);

		if ((state == TRUE) && onlyflag && doflag) {
			entry->flags |= ACTIVE;
			(*activate)(calln);
		} else {
			entry->flags |= TO_BE_DEACTIVATED;
		}
	}

	if ((arch_bits != 0) && (calln != -1))
		output(0, "Marking %d-bit syscall %s (%d) as to be %sabled.\n",
			arch_bits, arg_name, calln,
			state ? "en" : "dis");
}

void toggle_syscall_biarch(const char *arg, bool state)
{
	int specific_syscall32 = 0;
	int specific_syscall64 = 0;
	char *arg_name = NULL;
	bool only_32bit = TRUE;
	bool only_64bit = TRUE;

	check_user_specified_arch(arg, &arg_name, &only_64bit, &only_32bit);

	/* If we found a 64bit syscall, validate it. */
	specific_syscall64 = search_syscall_table(syscalls_64bit, max_nr_64bit_syscalls, arg_name);
	toggle_syscall_biarch_n(specific_syscall64, syscalls_64bit, only_64bit, do_64_arch, state, &activate_syscall64, 0, arg_name);

	/* Search for and validate 32bit */
	specific_syscall32 = search_syscall_table(syscalls_32bit, max_nr_32bit_syscalls, arg_name);
	toggle_syscall_biarch_n(specific_syscall32, syscalls_32bit, only_32bit, do_32_arch, state, &activate_syscall32, 0, arg_name);


	if ((!only_32bit) && (!only_64bit)) {
		outputerr("No idea what architecture for syscall (%s) is.\n", arg);
		exit(EXIT_FAILURE);
	}

	if ((specific_syscall64 == -1) && (specific_syscall32 == -1)) {
		outputerr("No idea what syscall (%s) is.\n", arg);
		exit(EXIT_FAILURE);
	}

	if ((specific_syscall64 != -1) && (specific_syscall32 != -1)) {
		output(0, "Marking syscall %s (64bit:%d 32bit:%d) as to be %sabled.\n",
			arg_name, specific_syscall64, specific_syscall32,
			state ? "en" : "dis");
		goto out;
	}

	if (specific_syscall64 != -1) {
		output(0, "Marking 64-bit syscall %s (%d) as to be %sabled.\n",
			arg, specific_syscall64,
			state ? "en" : "dis");
		goto out;
	}

	if  (specific_syscall32 != -1) {
		output(0, "Marking 32-bit syscall %s (%d) as to be %sabled.\n",
			arg, specific_syscall32,
			state ? "en" : "dis");
	}
out:
	clear_check_user_specified_arch(arg, &arg_name);
	return;

}

void enable_random_syscalls_biarch(void)
{
	unsigned int call32 = NOTFOUND, call64 = NOTFOUND;

retry:

	//Search for 64 bit version
	if (do_64_arch) {
		struct syscallentry *entry = NULL;

		call64 = rnd() % max_nr_64bit_syscalls;

		if (validate_specific_syscall_silent(syscalls_64bit, call64) == FALSE)
			goto retry;

		entry = syscalls_64bit[call64].entry;

		if (entry->flags & TO_BE_DEACTIVATED) {
			call64 = NOTFOUND;
			goto try32bit;
		}

		if (entry->active_number != 0) {
			call64 = NOTFOUND;
			goto try32bit;
		}

		// If we got so far, then activate it.
		toggle_syscall_biarch_n(call64, syscalls_64bit, TRUE, do_64_arch, TRUE,
					&activate_syscall64, 64, entry->name);
	}

try32bit:
	//Search for 32 bit version
	if (do_32_arch) {
		struct syscallentry *entry = NULL;

		/* If we enabled a 64bit syscall above, enable its 32-bit counter-part too */
		if (do_64_arch) {
			if (call64 == NOTFOUND) {
				goto just32;
			} else {
				call32 = search_syscall_table(syscalls_32bit, max_nr_32bit_syscalls, syscalls_64bit[call64].entry->name);
				if (call32 == NOTFOUND)
					return;	// syscall is 64-bit only.
			}
		} else {
just32:
			call32 = rnd() % max_nr_32bit_syscalls;
		}

		if (validate_specific_syscall_silent(syscalls_32bit, call32) == FALSE)
			return;

		entry = syscalls_32bit[call32].entry;

		if ((entry->flags & TO_BE_DEACTIVATED) || (entry->active_number != 0))
			return;

		//If we got so far, then active it.
		toggle_syscall_biarch_n(call32, syscalls_32bit, TRUE, do_32_arch, TRUE,
					&activate_syscall32, 32, entry->name);
	}
}

int setup_syscall_group_biarch(unsigned int group)
{
	unsigned int i;

	for_each_32bit_syscall(i) {
		struct syscallentry *entry = syscalls_32bit[i].entry;
		if (entry == NULL)
			continue;

		if (entry->group == group)
			toggle_syscall(entry->name, TRUE);
	}

	if (shm->nr_active_32bit_syscalls == 0)
		outputstd("No 32-bit syscalls in group\n");
	else
		outputstd("Found %d 32-bit syscalls in group\n", shm->nr_active_32bit_syscalls);

	/* now the 64 bit table*/
	for_each_64bit_syscall(i) {
		struct syscallentry *entry = syscalls_64bit[i].entry;
		if (entry == NULL)
		continue;

		if (entry->group == group)
			toggle_syscall(entry->name, TRUE);
	}

	if (shm->nr_active_64bit_syscalls == 0) {
		outputstd("No 64-bit syscalls in group\n");
		return FALSE;
	} else {
		outputstd("Found %d 64-bit syscalls in group\n", shm->nr_active_64bit_syscalls);
	}

	return TRUE;
}

void mark_all_syscalls_active_biarch(void)
{
	unsigned int i;

	if (do_32_arch) {
		for_each_32bit_syscall(i) {
			struct syscallentry *entry = syscalls_32bit[i].entry;
			if (entry == NULL)
				continue;
			entry->flags |= ACTIVE;
			activate_syscall32(i);
		}
	}

	if (do_64_arch) {
		for_each_64bit_syscall(i) {
			struct syscallentry *entry = syscalls_64bit[i].entry;
			if (entry == NULL)
				continue;
			entry->flags |= ACTIVE;
			activate_syscall64(i);
		}
	}
}

void init_syscalls_biarch(void)
{
	struct syscallentry *entry;
	unsigned int i;

	for_each_64bit_syscall(i) {
		entry = syscalls_64bit[i].entry;
		if (entry == NULL)
			continue;

		if (entry->flags & ACTIVE)
			if (entry->init)
				entry->init();
	}

	for_each_32bit_syscall(i) {
		entry = syscalls_32bit[i].entry;
		if (entry == NULL)
			continue;

		if (entry->flags & ACTIVE)
			if (entry->init)
				entry->init();
	}
}

void deactivate_disabled_syscalls_biarch(void)
{
	struct syscallentry *entry;
	unsigned int i;

	for_each_64bit_syscall(i) {
		entry = syscalls_64bit[i].entry;
		if (entry == NULL)
			continue;

		if (entry->flags & TO_BE_DEACTIVATED) {
			entry->flags &= ~(ACTIVE|TO_BE_DEACTIVATED);
			deactivate_syscall64(i);
			output(0, "Marked 64-bit syscall %s (%d) as deactivated.\n",
				entry->name, entry->number);
		}
	}

	for_each_32bit_syscall(i) {
		entry = syscalls_32bit[i].entry;
		if (entry == NULL)
			continue;

		if (entry->flags & TO_BE_DEACTIVATED) {
			entry->flags &= ~(ACTIVE|TO_BE_DEACTIVATED);
			deactivate_syscall32(i);
			output(0, "Marked 32-bit syscall %s (%d) as deactivated.\n",
				entry->name, entry->number);
		}
	}
}

void dump_syscall_tables_biarch(void)
{
	struct syscallentry *entry;
	unsigned int i;

	outputstd("syscalls: %d [32-bit]\n", max_nr_32bit_syscalls);
	outputstd("syscalls: %d [64-bit]\n", max_nr_64bit_syscalls);

	for_each_32bit_syscall(i) {
		entry = syscalls_32bit[i].entry;
		if (entry == NULL)
			continue;

		outputstd("entrypoint %d %s : [32-bit] ",
			entry->number, entry->name);
		show_state(entry->flags & ACTIVE);

		if (entry->flags & AVOID_SYSCALL)
			outputstd(" AVOID");

		outputstd("\n");
	}

	for_each_64bit_syscall(i) {
		entry = syscalls_64bit[i].entry;
		if (entry == NULL)
			continue;

		outputstd("entrypoint %d %s : [64-bit] ",
			entry->number, entry->name);
		show_state(entry->flags & ACTIVE);

		if (entry->flags & AVOID_SYSCALL)
			outputstd(" AVOID");

		outputstd("\n");
	}
}

void display_enabled_syscalls_biarch(void)
{
	struct syscallentry *entry;
	unsigned int i;

	for_each_64bit_syscall(i) {
		entry = syscalls_64bit[i].entry;
		if (entry == NULL)
			continue;

		if (entry->flags & ACTIVE)
			output(0, "64-bit syscall %d:%s enabled.\n", i, entry->name);
	}

	for_each_32bit_syscall(i) {
		entry = syscalls_32bit[i].entry;
		if (entry == NULL)
			continue;

		if (entry->flags & ACTIVE)
			output(0, "32-bit syscall %d:%s enabled.\n", i, entry->name);
	}
}
