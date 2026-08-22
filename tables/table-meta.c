/*
 * Syscall table metadata query, sanity-check, and inspection helpers.
 *
 * Carved out of tables/tables.c: this file owns the read-only accessors
 * (search_syscall_table, get_syscall_entry, print_syscall_name,
 * this_syscallname, syscall_nr_is_excluded), the per-entry sanity-check
 * pass run at init (sanity_check_tables and its helpers), the enabled/
 * disabled counters (count_syscalls_enabled, no_syscalls_enabled,
 * validate_syscall_tables), the -c/-x arg-name parser
 * (check_user_specified_arch / clear_check_user_specified_arch), and
 * the inspection printers (print_disabled_syscalls,
 * show_unannotated_args).
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "params.h"
#include "shm.h"
#include "syscall.h"
#include "syscall-gate.h"
#include "tables.h"
#include "uid.h"
#include "utils.h"

int search_syscall_table(const struct syscalltable *table, unsigned int nr_syscalls, const char *arg)
{
	unsigned int i;

	/* search by name */
	for (i = 0; i < nr_syscalls; i++) {
		if (table[i].entry == NULL)
			continue;

		if (strcmp(arg, table[i].entry->name) == 0) {
			//debugf("Found %s at %u\n", table[i].entry->name, i);
			return i;
		}
	}

	return -1;
}

void validate_specific_syscall(const struct syscalltable *table, int call)
{
	struct syscallentry *entry;

	if (call == -1)
		return;

	entry = table[call].entry;
	if (entry == NULL)
		return;

	if (entry->flags & AVOID_SYSCALL)
		output(0, "%s is marked as AVOID. Skipping\n", entry->name);

	if (entry->flags & NI_SYSCALL)
		output(0, "%s is NI_SYSCALL. Skipping\n", entry->name);

	if ((entry->flags & NEEDS_ROOT) && orig_uid != 0)
		output(0, "%s needs root. Skipping\n", entry->name);
}

int validate_specific_syscall_silent(const struct syscalltable *table, int call)
{
	struct syscallentry *entry;

	if (call == -1)
		return false;

	entry = table[call].entry;
	if (entry == NULL)
		return false;

	if (entry->flags & AVOID_SYSCALL)
		return false;

	if (entry->flags & NI_SYSCALL)
		return false;

	if ((entry->flags & NEEDS_ROOT) && orig_uid != 0)
		return false;

	return true;
}

void count_syscalls_enabled(void)
{
	if (biarch == true) {
		char str32[40];
		char str64[40];
		unsigned int nr;

		memset(str32, 0, sizeof(str32));
		memset(str64, 0, sizeof(str64));

		/* first the 32bit syscalls */
		if (shm->nr_active_32bit_syscalls != 0) {
			char *p = str32;
			char *end = str32 + sizeof(str32);
			int n;

			n = snprintf(p, end - p, "%u enabled", shm->nr_active_32bit_syscalls);
			if (n > 0 && n < end - p)
				p += n;

			nr = max_nr_32bit_syscalls - shm->nr_active_32bit_syscalls;
			if (nr != 0)
				snprintf(p, end - p, ", %u disabled", nr);
		} else {
			snprintf(str32, sizeof(str32), "all disabled.");
		}

		/* now the 64bit syscalls. */
		if (shm->nr_active_64bit_syscalls != 0) {
			char *p = str64;
			char *end = str64 + sizeof(str64);
			int n;

			n = snprintf(p, end - p, "%u enabled", shm->nr_active_64bit_syscalls);
			if (n > 0 && n < end - p)
				p += n;

			nr = max_nr_64bit_syscalls - shm->nr_active_64bit_syscalls;
			if (nr != 0)
				snprintf(p, end - p, ", %u disabled", nr);
		} else {
			snprintf(str64, sizeof(str64), "all disabled");
		}

		output(0, "32-bit syscalls: %s.  64-bit syscalls: %s.\n",
			str32, str64);

	} else {
		output(0, "Enabled %d syscalls. Disabled %d syscalls.\n",
			shm->nr_active_syscalls, max_nr_syscalls - shm->nr_active_syscalls);
	}
}

bool no_syscalls_enabled(void)
{
	unsigned int total;

	if (biarch == true)
		total = shm->nr_active_32bit_syscalls + shm->nr_active_64bit_syscalls;
	else
		total = shm->nr_active_syscalls;

	if (total == 0)
		return true;
	else
		return false;
}

/* Make sure there's at least one syscall enabled. */
int validate_syscall_tables(void)
{
	if (biarch == true) {
		unsigned int ret;

		ret = validate_syscall_table_32();
		ret |= validate_syscall_table_64();
		return ret;
	}

	/* non-biarch case*/
	if (shm->nr_active_syscalls == 0)
		return false;
	else
		return true;
}

static void check_syscall(struct syscallentry *entry)
{
	/* check that we have a name set. */
#define CHECK(NUMARGS, ARGNUM, ARGIDX)				\
	if (entry == NULL)					\
		return;						\
	if (entry->num_args > 0) {				\
		if (entry->num_args > NUMARGS) {		\
			if (entry->argname[ARGIDX] == NULL)  {	\
				outputerr("arg %d of %s has no name\n", ARGNUM, entry->name);      \
				exit(EXIT_FAILURE);		\
			}					\
		}						\
	}							\

	CHECK(0, 1, 0);
	CHECK(1, 2, 1);
	CHECK(2, 3, 2);
	CHECK(3, 4, 3);
	CHECK(4, 5, 4);
	CHECK(5, 6, 5);
}

static void check_no_slots_past_num_args(struct syscallentry *entry)
{
	unsigned int j;

	if (entry == NULL)
		return;

	for (j = entry->num_args; j < ARRAY_SIZE(entry->argtype); j++) {
		if (entry->argtype[j] != ARG_UNDEFINED) {
			outputerr("%s: argtype slot %u is set (%d) but num_args=%u; slots past num_args must be zero\n",
				  entry->name, j, entry->argtype[j], entry->num_args);
			exit(EXIT_FAILURE);
		}
	}
}

static void sanity_check(const struct syscalltable *table, unsigned int nr)
{
	unsigned int i;

	for (i = 0; i < nr; i++) {
		check_syscall(table[i].entry);
		check_no_slots_past_num_args(table[i].entry);
	}
}

void sanity_check_tables(void)
{
	if (biarch == true) {
		sanity_check(syscalls_32bit, max_nr_32bit_syscalls);
		sanity_check(syscalls_64bit, max_nr_64bit_syscalls);
		return;
	}

	/* non-biarch case*/
	sanity_check(syscalls, max_nr_syscalls);
}

void check_user_specified_arch(const char *arg, char **arg_name, bool *only_64bit, bool *only_32bit)
{
	//Check if the arch is specified
	const char *arg_arch = strstr(arg,",");

	if (arg_arch  != NULL) {
		unsigned long size = 0;

		size = (unsigned long)arg_arch - (unsigned long)arg;
		*arg_name = malloc(size + 1);
		if (*arg_name == NULL)
			exit(EXIT_FAILURE);
		(*arg_name)[size] = 0;
		memcpy(*arg_name, arg, size);

		//identify architecture
		if ((only_64bit != NULL) && (only_32bit != NULL)) {
			if ((strcmp(arg_arch + 1, "64") == 0)) {
				*only_64bit = true;
				*only_32bit = false;
			} else if ((strcmp(arg_arch + 1,"32") == 0)) {
				*only_64bit = false;
				*only_32bit = true;
			} else {
				outputerr("Unknown bit width (%s). Choose 32, or 64.\n", arg);
				exit(EXIT_FAILURE);
			}
		}
	} else {
		*arg_name = (char*)arg;//castaway const.
	}
}

void clear_check_user_specified_arch(const char *arg, char **arg_name)
{
	//Release memory only if we have allocated it
	if (((char *)arg) != *arg_name) {
		free(*arg_name);
		*arg_name = NULL;
	}
}

static void print_disabled_in_table(const struct syscalltable *table,
				    unsigned int nr, const char *label)
{
	struct syscallentry *entry;
	unsigned int i, count = 0;

	for (i = 0; i < nr; i++) {
		entry = table[i].entry;
		if (entry == NULL)
			continue;

		if (!(entry->flags & (AVOID_SYSCALL | NEED_ALARM)))
			continue;

		outputstd("%s %u %s :", label, entry->number, entry->name);
		if (entry->flags & AVOID_SYSCALL)
			outputstd(" AVOID_SYSCALL");
		if (entry->flags & NEED_ALARM)
			outputstd(" NEED_ALARM");
		outputstd("\n");
		count++;
	}

	outputstd("%s: %u disabled syscall%s\n",
		label, count, count == 1 ? "" : "s");
}

void print_disabled_syscalls(void)
{
	if (biarch == true) {
		print_disabled_in_table(syscalls_32bit, max_nr_32bit_syscalls,
					"[32-bit]");
		print_disabled_in_table(syscalls_64bit, max_nr_64bit_syscalls,
					"[64-bit]");
	} else {
		print_disabled_in_table(syscalls, max_nr_syscalls, "syscall");
	}
}

static void show_unannotated_biarch(void)
{
	struct syscallentry *entry;
	unsigned int i, j;
	unsigned int count = 0;

	for_each_32bit_syscall(i) {
		entry = syscalls_32bit[i].entry;
		if (entry == NULL)
			continue;

		count = 0;

		for (j = 0; j < entry->num_args; j++) {
			if (entry->argtype[j] == ARG_UNDEFINED)
				count++;
		}
		if (count != 0)
			output(0, "%s has %u unannotated arguments\n", entry->name, count);
	}

	output(0, "\n");

	for_each_64bit_syscall(i) {
		entry = syscalls_64bit[i].entry;
		if (entry == NULL)
			continue;

		count = 0;

		for (j = 0; j < entry->num_args; j++) {
			if (search_syscall_table(syscalls_32bit, max_nr_32bit_syscalls, entry->name) == -1) {
				if (entry->argtype[j] == ARG_UNDEFINED)
					count++;
			}
		}
		if (count != 0)
			output(0, "%s has %u unannotated arguments\n", entry->name, count);
	}
}

void show_unannotated_args(void)
{
	if (biarch == true)
		show_unannotated_biarch();
}

const char * print_syscall_name(unsigned int callno, bool is32bit)
{
	const struct syscalltable *table;
	unsigned int max;

	if (biarch == false) {
		max = max_nr_syscalls;
		table = syscalls;
	} else {
		if (is32bit == false) {
			max = max_nr_64bit_syscalls;
			table = syscalls_64bit;
		} else {
			max = max_nr_32bit_syscalls;
			table = syscalls_32bit;
		}
	}

	if (callno >= max) {
		outputstd("Bogus syscall number in %s (%u)\n", __func__, callno);
		return "invalid-syscall";
	}

	if (table[callno].entry == NULL)
		return "unknown";

	return table[callno].entry->name;
}

/*
 * Honor -x <syscall> at raw syscall(__NR_X, ...) sites in childops /
 * fds that bypass the syscall-table picker entirely.  Returns true if
 * `nr` names a syscall the user named in -x at parse time: the
 * EXPLICITLY_EXCLUDED flag is stamped on the entry by toggle_syscall_n()
 * / toggle_syscall_biarch_n() alongside TO_BE_DEACTIVATED, and survives
 * the ACTIVE|TO_BE_DEACTIVATED clear that deactivate_disabled_syscalls()
 * performs in munge_tables() -- so the flag is the authoritative,
 * targeting-mode-independent record of "this syscall is excluded".
 *
 * Returns false in every other case, including the common ones:
 *   - do_exclude_syscall is false (one load + branch, no table touch),
 *   - nr is negative or out of range for the host arch table,
 *   - the table slot is NULL (gaps for arch-specific syscalls),
 *   - the entry was not named in -x (flag not set).
 *
 * Targeting selectors (-c / -r / -g) no longer change the answer.  The
 * previous implementation inferred exclusion from (flags & ACTIVE) == 0
 * and had to short-circuit to false under any targeting selector to
 * avoid misreporting unrelated syscalls (a non-targeted entry is
 * inactive because it was never enabled, not because it was -x'd) --
 * but that workaround also silently dropped the legitimate -x exclusion
 * when targeting was active (targeting/exclusion bug: e.g. `-c foo -x bar` left
 * bar reachable from raw-syscall sites).  Reading the explicit bit
 * fixes both directions at once.
 *
 * Biarch: trinity itself runs as the host's native (64bit) binary; a
 * raw syscall(__NR_X) from a childop / fd-provider invokes the 64bit
 * syscall regardless of which table -c <name> resolved against, so
 * consult the 64bit table only.  -x toggles the 32bit and 64bit slots
 * in lockstep (toggle_syscall_biarch in tables-biarch.c) so an entry
 * flagged in one table is flagged in the other.
 *
 * Callers should treat a true return as "skip this syscall"; the
 * trinity_raw_syscall() wrapper in include/syscall-gate.h sets
 * errno = ENOSYS and returns -1, which existing childops already
 * handle gracefully (kernels legitimately ENOSYS unsupported calls).
 */
bool syscall_nr_is_excluded(int nr)
{
	struct syscallentry *entry;

	if (do_exclude_syscall == false)
		return false;
	if (nr < 0)
		return false;

#ifdef ARCH_IS_BIARCH
	if ((unsigned int)nr >= max_nr_64bit_syscalls)
		return false;
	entry = syscalls_64bit[nr].entry;
#else
	if ((unsigned int)nr >= max_nr_syscalls)
		return false;
	entry = syscalls[nr].entry;
#endif

	if (entry == NULL)
		return false;

	return (entry->flags & EXPLICITLY_EXCLUDED) != 0;
}

/*
 * return a ptr to a syscall table entry, allowing calling code to be
 * ignorant about things like biarch.
 *
 * Takes the actual syscall number from the syscallrecord struct as an arg.
 */
struct syscallentry * get_syscall_entry(unsigned int callno, bool do32 __attribute__((unused)))
{
#ifndef ARCH_IS_BIARCH
	if (callno >= max_nr_syscalls)
		return NULL;
	return syscalls[callno].entry;
#else
	if (do32 == true) {
		if (callno >= max_nr_32bit_syscalls)
			return NULL;
		return syscalls_32bit[callno].entry;
	}

	if (callno >= max_nr_64bit_syscalls)
		return NULL;
	return syscalls_64bit[callno].entry;
#endif
}

/*
 * Check the name of the syscall we're in the ->sanitise of.
 * This is useful for syscalls where we have a common ->sanitise
 * for multiple syscallentry's. (mmap/mmap2, sync_file_range/sync_file_range2)
 *
 * Reads the resolved entry pointer that dispatch_step() stamps on the rec
 * before invoking do_syscall(); this elides the per-call
 * get_syscall_entry(nr, do32bit) table lookup + biarch branch the original
 * shape paid for on every callsite (mmap/mmap2 fires this twice per call).
 * All current callers run inside .sanitise / .post hooks, both of which
 * fire after dispatch_step has set rec->entry, so the NULL guard only
 * matters for any future caller that fires before dispatch.
 */
bool this_syscallname(const char *thisname)
{
	struct syscallentry *e = this_child()->syscall.entry;

	if (e == NULL)
		return false;

	return strcmp(thisname, e->name) == 0;
}
