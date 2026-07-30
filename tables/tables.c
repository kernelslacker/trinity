/*
 * Functions for handling the system call tables.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "arch.h"
#include "params.h"
#include "shm.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"	// MAX_LOGLEVEL
#include "utils.h"	// ARRAY_SIZE

unsigned long syscalls_todo = 0;

bool biarch = false;

void init_syscalls(void)
{
	if (biarch == true)
		init_syscalls_biarch();
	else
		init_syscalls_uniarch();
}

void mark_all_syscalls_active(void)
{
	outputstd("Marking all syscalls as enabled.\n");

	if (biarch == true)
		mark_all_syscalls_active_biarch();
	else
		mark_all_syscalls_active_uniarch();
}

void toggle_syscall(const char *arg, bool state)
{
	int specific_syscall = 0;
	char * arg_name = NULL;

	if (biarch == true) {
		toggle_syscall_biarch(arg, state);
		return;
	}

	/* non-biarch case. */
	check_user_specified_arch(arg, &arg_name, NULL, NULL); //We do not care about arch here, just to get rid of arg flags.

	specific_syscall = search_syscall_table(syscalls, max_nr_syscalls, arg_name);
	if (specific_syscall == -1) {
		outputerr("No idea what syscall (%s) is.\n", arg);
		goto out;
	}

	toggle_syscall_n(specific_syscall, state, arg, arg_name);

out:
	clear_check_user_specified_arch(arg, &arg_name);
}

void deactivate_disabled_syscalls(void)
{
	output(0, "Disabling syscalls marked as disabled by command line options\n");

	if (biarch == true)
		deactivate_disabled_syscalls_biarch();
	else
		deactivate_disabled_syscalls_uniarch();
}

void dump_syscall_tables(void)
{
	if (biarch == true)
		dump_syscall_tables_biarch();
	else
		dump_syscall_tables_uniarch();
}

/*
 * Subgroup inheritance for `-g <group>`: a syscall is selected under
 * group G if its .group is G, OR if its .group's parent is G.  The
 * lookup is selection-only -- xattr syscalls keep .group = GROUP_XATTR
 * so per-group stats/bias keep attributing to the leaf group.  Only
 * GROUP_XATTR currently has a parent (GROUP_VFS); every other slot
 * defaults to GROUP_NONE.
 */
const unsigned int group_parent[NR_GROUPS] = {
	[GROUP_XATTR]     = GROUP_VFS,
	[GROUP_VFS_PATH]  = GROUP_VFS,
	[GROUP_VFS_STAT]  = GROUP_VFS,
	[GROUP_VFS_MOUNT] = GROUP_VFS,
	[GROUP_VFS_SYNC]  = GROUP_VFS,
	[GROUP_VFS_IO]    = GROUP_VFS,
	[GROUP_CRED]      = GROUP_PROCESS,
	[GROUP_NS]        = GROUP_PROCESS,
};

int setup_syscall_group(unsigned int group)
{
	if (biarch == true)
		return setup_syscall_group_biarch(group);
	else
		return setup_syscall_group_uniarch(group);
}

void display_enabled_syscalls(void)
{
	if (biarch == true)
		display_enabled_syscalls_biarch();
	else
		display_enabled_syscalls_uniarch();
}

static void enable_random_syscalls(void)
{
	unsigned int i;

	if (random_selection_num == 0) {
		outputerr("-r 0 syscalls ? what?\n");
		exit(EXIT_FAILURE);
	}

	if (biarch == true) {
		if ((random_selection_num > max_nr_64bit_syscalls) && do_64_arch) {
			outputerr("-r val %d out of range (1-%d)\n", random_selection_num, max_nr_64bit_syscalls);
			exit(EXIT_FAILURE);
		}
	} else {
		if (random_selection_num > max_nr_syscalls) {
			outputerr("-r val %d out of range (1-%d)\n", random_selection_num, max_nr_syscalls);
			exit(EXIT_FAILURE);
		}
	}

	outputerr("Enabling %d random syscalls\n", random_selection_num);

	for (i = 0; i < random_selection_num; i++) {
		if (biarch == true)
			enable_random_syscalls_biarch();
		else
			enable_random_syscalls_uniarch();
	}
}

/* Pick up syscalls flagged ACTIVE before create_shm() ran (the
 * `-c <syscall>` handler in parse_args) and stamp them into the
 * shm-backed active table.  Idempotent: activate_syscall_in_table()
 * skips entries with syscall_rt(entry)->active_number != 0. */
static void activate_flagged_syscalls(void)
{
	if (biarch == true)
		activate_flagged_syscalls_biarch();
	else
		activate_flagged_syscalls_uniarch();
}

/* By default, all syscall entries will be disabled.
 * If we didn't pass -c, -x, -r, or -g then mark all syscalls active.
 */
static void decide_if_active(void)
{
	if (do_specific_syscall == true)
		return;
	if (do_exclude_syscall == true)
		return;
	if (random_selection == true)
		return;
	if (desired_group != GROUP_NONE)
		return;

	mark_all_syscalls_active();
}

/* This is run *after* we've parsed params */
int munge_tables(void)
{
	decide_if_active();

	activate_flagged_syscalls();

	if (desired_group != GROUP_NONE) {
		unsigned int ret;

		ret = setup_syscall_group(desired_group);
		if (ret == false)
			return false;
	}

	if (random_selection == true)
		enable_random_syscalls();

	/* If we saw a '-x', set all syscalls to enabled, then selectively disable.
	 * Unless:
	 * - we've started enabling them already (with -r)
	 * - or if we specified a group -g
	 * - we've also specified syscalls with -c
	 */
	if (do_exclude_syscall == true) {
		if ((random_selection == false) && (desired_group == GROUP_NONE) && (do_specific_syscall == false))
			mark_all_syscalls_active();
		deactivate_disabled_syscalls();
	}

	sanity_check_tables();

	count_syscalls_enabled();

	if (verbosity >= MAX_LOGLEVEL)
		display_enabled_syscalls();

	if (validate_syscall_tables() == false) {
		outputstd("No syscalls were enabled!\n");
		outputstd("Use 32bit:%d 64bit:%d\n", use_32bit, use_64bit);
		return false;
	}

	return true;
}
