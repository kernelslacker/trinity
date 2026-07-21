/*
 * Per-syscall JSON array for --stats-json.  One entry per syscall
 * that has been attempted at least once; consumers can walk the
 * array without extra filtering.
 */

#include <stdbool.h>
#include <stdio.h>
#include "kcov.h"
#include "stats/json/internal.h"
#include "syscall.h"
#include "tables.h"

/* Emit one syscall entry. Returns true if anything was printed. Caller is
 * responsible for emitting a leading comma between successive entries. */
static bool json_emit_syscall(const struct syscalltable *table, unsigned int i)
{
	struct syscallentry *entry;
	unsigned long extrafork_calls = 0;
	unsigned long kcov_calls = 0;
	unsigned int j;
	unsigned int nr;
	bool first_errno = true;

	entry = table[i].entry;
	if (entry == NULL || entry->attempted == 0)
		return false;

	nr = entry->number;
	if (kcov_shm != NULL && nr < MAX_NR_SYSCALL) {
		extrafork_calls = __atomic_load_n(
			&kcov_shm->per_syscall.per_syscall_extrafork_calls[nr],
			__ATOMIC_RELAXED);
		kcov_calls = per_syscall_calls_total(nr);
	}

	putchar('{');
	fputs("\"name\":", stdout);
	json_emit_string(entry->name);
	/* kcov_calls / attempted_calls are named explicitly to disambiguate
	 * the two per-syscall denominators the stats consumers routinely
	 * conflate: kcov_calls is per_syscall_calls[nr] (KCOV-bracketed
	 * count kcov_collect() bumps -- the natural numerator match for
	 * per_syscall_edges and cold-skip / picker productivity ratios),
	 * while attempted_calls is entry->attempted (every dispatched
	 * invocation regardless of whether the kcov bracket ran, so it
	 * also counts EXTRA_FORK / validator-rejected / dry-run paths).
	 *
	 * extrafork_calls: dispatches routed through do_extrafork()
	 * (execve / execveat / vfork).  Non-zero here means the syscall
	 * runs in a throwaway grandchild outside the parent kcov bracket,
	 * so a zero-yield edges / kcov_calls ratio for this slot is by
	 * design, not evidence the syscall is dead. */
	printf(",\"attempted_calls\":%u,\"kcov_calls\":%lu,\"successes\":%u,\"failures\":%u,\"extrafork_calls\":%lu,\"errnos\":{",
		entry->attempted, kcov_calls, entry->successes,
		entry->failures, extrafork_calls);
	for (j = 0; j <= NR_ERRNOS; j++) {
		if (entry->errnos[j] == 0)
			continue;
		if (!first_errno)
			putchar(',');
		printf("\"%u\":%u", j, entry->errnos[j]);
		first_errno = false;
	}
	fputs("}}", stdout);
	return true;
}

void json_emit_syscalls_array(void)
{
	unsigned int i;
	bool first = true;

	fputs("\"syscalls\":[", stdout);
	if (biarch == true) {
		for_each_32bit_syscall(i) {
			if (syscalls_32bit[i].entry == NULL ||
			    syscalls_32bit[i].entry->attempted == 0)
				continue;
			if (!first)
				putchar(',');
			json_emit_syscall(syscalls_32bit, i);
			first = false;
		}
		for_each_64bit_syscall(i) {
			if (syscalls_64bit[i].entry == NULL ||
			    syscalls_64bit[i].entry->attempted == 0)
				continue;
			if (!first)
				putchar(',');
			json_emit_syscall(syscalls_64bit, i);
			first = false;
		}
	} else {
		for_each_syscall(i) {
			if (syscalls[i].entry == NULL ||
			    syscalls[i].entry->attempted == 0)
				continue;
			if (!first)
				putchar(',');
			json_emit_syscall(syscalls, i);
			first = false;
		}
	}
	putchar(']');
}
