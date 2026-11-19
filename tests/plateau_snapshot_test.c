/*
 * Self-check for plateau_snapshot_capture() (strategy/
 * strategy-plateau.c).  The single-group-dominant hypothesis reads the
 * per-group split of productive calls, so the walk behind it must cover
 * both tables of a biarch build and credit each syscall's own ABI's
 * counters to its own group: one number names different syscalls in
 * the two tables.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "arch.h"		/* biarch, ARCH_IS_BIARCH */
#include "debug.h"		/* BUG */
#include "kcov.h"
#include "picker-context.h"	/* PICKER_CTX_INIT */
#include "strategy.h"
#include "syscall.h"
#include "tables.h"

#define NR	3

static struct syscallentry native_entry = { .name = "native", .group = GROUP_VFS };
static struct syscallentry compat_entry = { .name = "compat", .group = GROUP_NET };
static const struct syscalltable native_table[NR + 1] = {
	[NR] = { .entry = &native_entry },
};
static const struct syscalltable compat_table[NR + 1] = {
	[NR] = { .entry = &compat_entry },
};

void plateau_snapshot_self_check(void);
void plateau_snapshot_self_check(void)
{
	struct plateau_window_snapshot snap;

#ifndef ARCH_IS_BIARCH
	/* A uniarch build has the one table. */
	return;
#endif
	kcov_shm = calloc(1, sizeof(*kcov_shm));
	if (kcov_shm == NULL)
		BUG("plateau snapshot: calloc failed");
	kcov_shm->per_syscall.per_syscall_edges[NR][PICKER_CTX_INIT][0] = 5;
	kcov_shm->per_syscall.per_syscall_edges[NR][PICKER_CTX_INIT][1] = 7;
	biarch = true;
	syscalls_64bit = native_table;
	syscalls_32bit = compat_table;
	max_nr_64bit_syscalls = NR + 1;
	max_nr_32bit_syscalls = NR + 1;

	plateau_snapshot_capture(&snap);
	if (snap.group_edges[GROUP_VFS] != 5 || snap.group_edges[GROUP_NET] != 7) {
		fprintf(stderr, "\n    plateau snapshot: vfs %lu, net %lu (want 5 and 7)",
			snap.group_edges[GROUP_VFS], snap.group_edges[GROUP_NET]);
		BUG("plateau snapshot: a table's productive calls missed their group");
	}

	/* Back to the empty uniarch tables fake_parent.c provides. */
	biarch = false;
	syscalls_64bit = NULL;
	syscalls_32bit = NULL;
	max_nr_64bit_syscalls = 0;
	max_nr_32bit_syscalls = 0;
	free(kcov_shm);
	kcov_shm = NULL;
}
