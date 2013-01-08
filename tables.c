/*
 * Functions for handling the system call tables.
 */

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include "arch.h"
#include "arch-syscalls.h"
#include "syscall.h"
#include "trinity.h"

const struct syscalltable *syscalls;
const struct syscalltable *syscalls_32bit;
const struct syscalltable *syscalls_64bit;

unsigned long syscalls_todo = 0;

unsigned int max_nr_syscalls;
unsigned int max_nr_32bit_syscalls;
unsigned int max_nr_64bit_syscalls;

bool use_32bit = FALSE;
bool use_64bit = FALSE;
bool biarch = FALSE;

int search_syscall_table(const struct syscalltable *table, unsigned int nr_syscalls, const char *arg)
{
	unsigned int i;

	/* search by name */
	for (i = 0; i < nr_syscalls; i++) {
		if (strcmp(arg, table[i].entry->name) == 0) {
			//printf("Found %s at %u\n", table[i].entry->name, i);
			return i;
		}
	}

	return -1;
}

int validate_specific_syscall(const struct syscalltable *table, int call)
{
	if (call != -1) {
		if (table[call].entry->flags & AVOID_SYSCALL) {
			printf("%s is marked as AVOID. Skipping\n", table[call].entry->name);
			return FALSE;
		}

		if (table[call].entry->flags & NI_SYSCALL) {
			printf("%s is NI_SYSCALL. Skipping\n", table[call].entry->name);
			return FALSE;
		}
		if (table[call].entry->num_args == 0) {
			printf("%s has no arguments. Skipping\n", table[call].entry->name);
			return FALSE;
		}
	}
	return TRUE;
}

bool no_syscalls_enabled(void)
{
	unsigned int i;

	if (biarch == TRUE) {
		for_each_64bit_syscall(i) {
			if (syscalls_64bit[i].entry->flags & ACTIVE)
				return FALSE;
		}
		for_each_32bit_syscall(i) {
			if (syscalls_32bit[i].entry->flags & ACTIVE)
				return FALSE;
		}
		return TRUE;;
	}

	/* non-biarch */
	for_each_syscall(i) {
		if (syscalls[i].entry->flags & ACTIVE)
			return FALSE;
	}
	return TRUE;
}

int validate_syscall_table_64(void)
{
	unsigned int i;

	for_each_64bit_syscall(i) {
		if (syscalls_64bit[i].entry->flags & ACTIVE) {
			use_64bit = TRUE;
			break;
		}
	}
	return use_64bit;
}

int validate_syscall_table_32(void)
{
	unsigned int i;

	for_each_32bit_syscall(i) {
		if (syscalls_32bit[i].entry->flags & ACTIVE) {
			use_32bit = TRUE;
			break;
		}
	}
	return use_32bit;
}

/* Make sure there's at least one syscall enabled. */
int validate_syscall_tables(void)
{
	unsigned int i, ret;

	if (biarch == TRUE) {
		ret = validate_syscall_table_32();
		ret |= validate_syscall_table_64();
		return ret;
	}

	/* non-biarch case*/
	for_each_syscall(i) {
		if (syscalls[i].entry->flags & ACTIVE)
			return TRUE;
	}
	return FALSE;
}

static void check_syscall(struct syscall *entry)
{
	/* check that we have a name set. */
#define CHECK(NUMARGS, ARGNUM, ARGTYPE, ARGNAME)		\
	if (entry->num_args > 0) {				\
		if (entry->num_args > NUMARGS) {		\
			if (entry->ARGNAME == NULL)  {		\
				printf("arg %d of %s has no name\n", ARGNUM, entry->name);      \
				exit(EXIT_FAILURE);		\
			}					\
		}						\
	}							\

	CHECK(0, 1, arg1type, arg1name);
	CHECK(1, 2, arg2type, arg2name);
	CHECK(2, 3, arg3type, arg3name);
	CHECK(3, 4, arg4type, arg4name);
	CHECK(4, 5, arg5type, arg5name);
	CHECK(5, 6, arg6type, arg6name);

	/* check if we have a type. */
	/* note: not enabled by default, because we haven't annotated everything yet. */
#undef CHECK
#define CHECK(NUMARGS, ARGNUM, ARGTYPE, ARGNAME)		\
	if (entry->num_args > 0) {				\
		if (entry->num_args > NUMARGS) {		\
			if (entry->ARGTYPE == ARG_UNDEFINED) {	\
				printf("%s has an undefined argument type for arg1 (%s)!\n", entry->name, entry->ARGNAME);	\
			}					\
		}						\
	}							\

/*	CHECK(0, 1, arg1type, arg1name);
	CHECK(1, 2, arg2type, arg2name);
	CHECK(2, 3, arg3type, arg3name);
	CHECK(3, 4, arg4type, arg4name);
	CHECK(4, 5, arg5type, arg5name);
	CHECK(5, 6, arg6type, arg6name);
*/
}

static void sanity_check(const struct syscalltable *table, unsigned int nr)
{
	unsigned int i;

	for (i = 0; i < nr; i++)
		check_syscall(table[i].entry);
}

void sanity_check_tables(void)
{
	if (biarch == TRUE) {
		sanity_check(syscalls_32bit, max_nr_32bit_syscalls);
		sanity_check(syscalls_64bit, max_nr_64bit_syscalls);
		return;
	}

	/* non-biarch case*/
	sanity_check(syscalls, max_nr_syscalls);
}

void mark_all_syscalls_active(void)
{
	unsigned int i;

	if (biarch == TRUE) {
		for_each_32bit_syscall(i)
			syscalls_32bit[i].entry->flags |= ACTIVE;
		for_each_64bit_syscall(i)
			syscalls_64bit[i].entry->flags |= ACTIVE;
	} else {
		for_each_syscall(i)
			syscalls[i].entry->flags |= ACTIVE;
	}
}

static void toggle_syscall_biarch(char *arg, unsigned char state)
{
	int specific_syscall32 = 0;
	int specific_syscall64 = 0;
	int ret;

	specific_syscall64 = search_syscall_table(syscalls_64bit, max_nr_64bit_syscalls, arg);

	/* If we found a 64bit syscall, validate it. */
	if (specific_syscall64 != -1) {
		ret = validate_specific_syscall(syscalls_64bit, specific_syscall64);
		if (ret == FALSE)
			exit(EXIT_FAILURE);
		if (state == TRUE) {
			printf("[%d] Marking 64-bit syscall %d (%s) as enabled\n", getpid(), specific_syscall64, arg);
			syscalls_64bit[specific_syscall64].entry->flags |= ACTIVE;
		} else {
			printf("[%d] Marking 64-bit syscall %d (%s) as disabled\n", getpid(), specific_syscall64, arg);
			syscalls_64bit[specific_syscall64].entry->flags &= ~ACTIVE;
		}
	}

	/* Search for and validate 32bit */
	specific_syscall32 = search_syscall_table(syscalls_32bit, max_nr_32bit_syscalls, arg);
	if (specific_syscall32 != -1) {
		ret = validate_specific_syscall(syscalls_32bit, specific_syscall32);
		if (ret == FALSE)
			exit(EXIT_FAILURE);
		if (state == TRUE) {
			printf("[%d] Marking 32-bit syscall %d (%s) as enabled\n", getpid(), specific_syscall32, arg);
			syscalls_32bit[specific_syscall32].entry->flags |= ACTIVE;
		} else {
			printf("[%d] Marking 32-bit syscall %d (%s) as disabled\n", getpid(), specific_syscall32, arg);
			syscalls_32bit[specific_syscall32].entry->flags &= ~ACTIVE;
		}
	}

	if ((specific_syscall64 == -1) && (specific_syscall32 == -1)) {
		printf("No idea what syscall (%s) is.\n", arg);
		exit(EXIT_FAILURE);
	}
}

void toggle_syscall(char *arg, unsigned char state)
{
	int specific_syscall = 0;
	int ret;

	if (biarch == TRUE) {
		toggle_syscall_biarch(arg, state);
		return;
	}

	/* non-biarch case. */
	specific_syscall = search_syscall_table(syscalls, max_nr_syscalls, arg);
	if (specific_syscall != -1) {
		ret = validate_specific_syscall(syscalls, specific_syscall);
		if (ret == FALSE)
			exit(EXIT_FAILURE);
		if (state == TRUE) {
			printf("[%d] Marking syscall %d (%s) as enabled\n", getpid(), specific_syscall, arg);
			syscalls[specific_syscall].entry->flags |= ACTIVE;
		} else {
			printf("[%d] Marking syscall %d (%s) as disabled\n", getpid(), specific_syscall, arg);
			syscalls[specific_syscall].entry->flags &= ~ACTIVE;
		}
	}

	if (specific_syscall == -1) {
		printf("No idea what syscall (%s) is.\n", arg);
		exit(EXIT_FAILURE);
	}
}

static void show_state(unsigned int state)
{
	if (state)
		printf("Enabled");
	else
		printf("Disabled");
}

void dump_syscall_tables(void)
{
	unsigned int i;

	if (biarch == TRUE) {
		printf("32-bit syscalls: %d\n", max_nr_32bit_syscalls);
		printf("64-bit syscalls: %d\n", max_nr_64bit_syscalls);

		for_each_32bit_syscall(i) {
			printf("32-bit entrypoint %d %s : ", syscalls_32bit[i].entry->number, syscalls_32bit[i].entry->name);
			show_state(syscalls_32bit[i].entry->flags & ACTIVE);
			if (syscalls_32bit[i].entry->flags & AVOID_SYSCALL)
				printf(" AVOID");
			printf("\n");
		}
		for_each_64bit_syscall(i) {
			printf("64-bit entrypoint %d %s : ", syscalls_64bit[i].entry->number, syscalls_64bit[i].entry->name);
			show_state(syscalls_64bit[i].entry->flags & ACTIVE);
			if (syscalls_64bit[i].entry->flags & AVOID_SYSCALL)
				printf(" AVOID");
			printf("\n");
		}
	} else {
		printf("syscalls: %d\n", max_nr_syscalls);
		for_each_syscall(i) {
			printf("%s : ", syscalls[i].entry->name);
			show_state(syscalls[i].entry->flags & ACTIVE);
			if (syscalls[i].entry->flags & AVOID_SYSCALL)
				printf(" AVOID");
			printf("\n");
		}
	}
}

/*
 * This changes the pointers in the table 'from' to be copies in
 * shared mmaps across all children.  We do this so that a child can
 * modify the flags field (adding AVOID for eg) and have other processes see the change.
 */
static struct syscalltable * copy_syscall_table(struct syscalltable *from, unsigned int nr)
{
	unsigned int n;
	struct syscall *copy;

	/* FIXME: Use fewer shared maps.
	 * It's pretty sad that we use a whole page just for a copy of that struct when we
	 * could fit dozens of them in a page.  This would cut down our /proc/$$/maps a *lot*
	 */
	for (n = 0; n < nr; n++) {
		copy = alloc_shared(sizeof(struct syscall));
		if (copy == NULL)
			exit(EXIT_FAILURE);
		memcpy(copy, from[n].entry, sizeof(struct syscall));
		copy->number = n;
		from[n].entry = copy;
	}
	return from;
}

void setup_syscall_tables(void)
{
#if defined(__x86_64__)
	syscalls_64bit = copy_syscall_table(syscalls_x86_64, ARRAY_SIZE(syscalls_x86_64));
	syscalls_32bit = copy_syscall_table(syscalls_i386, ARRAY_SIZE(syscalls_i386));

	max_nr_64bit_syscalls = ARRAY_SIZE(syscalls_x86_64);
	max_nr_32bit_syscalls = ARRAY_SIZE(syscalls_i386);
	biarch = TRUE;
#elif defined(__i386__)
	syscalls = copy_syscall_table(syscalls_i386, ARRAY_SIZE(syscalls_i386));
	max_nr_syscalls = ARRAY_SIZE(syscalls_i386);
#elif defined(__powerpc__)
	syscalls = copy_syscall_table(syscalls_ppc, ARRAY_SIZE(syscalls_ppc));
	max_nr_syscalls = ARRAY_SIZE(syscalls_ppc);
#elif defined(__ia64__)
	syscalls = copy_syscall_table(syscalls_ia64, ARRAY_SIZE(syscalls_ia64));
	max_nr_syscalls = ARRAY_SIZE(syscalls_ia64);
#elif defined(__sparc__)
	syscalls = copy_syscall_table(syscalls_sparc, ARRAY_SIZE(syscalls_sparc));
	max_nr_syscalls = ARRAY_SIZE(syscalls_sparc);
#elif defined(__arm__)
	syscalls = copy_syscall_table(syscalls_arm, ARRAY_SIZE(syscalls_arm));
	max_nr_syscalls = ARRAY_SIZE(syscalls_arm);
#elif defined(__mips__)
	syscalls = copy_syscall_table(syscalls_mips, ARRAY_SIZE(syscalls_mips));
	max_nr_syscalls = ARRAY_SIZE(syscalls_mips);
#elif defined(__sh__)
	syscalls = copy_syscall_table(syscalls_sh, ARRAY_SIZE(syscalls_sh));
	max_nr_syscalls = ARRAY_SIZE(syscalls_sh);
#else
#error Unknown architecture.
#endif

}


int setup_syscall_group(unsigned int group)
{
	struct syscalltable *newsyscalls;
	struct syscalltable *newsyscalls32;
	struct syscalltable *newsyscalls64;

	unsigned int i;
	int count = 0, j = 0;

	if (biarch == TRUE) {
		for_each_32bit_syscall(i) {
			if (syscalls_32bit[i].entry->group == group)
				count++;
		}

		newsyscalls32 = malloc(count * sizeof(struct syscalltable));
		if (newsyscalls32 == NULL)
			return FALSE;

		for_each_32bit_syscall(i) {
			if (syscalls_32bit[i].entry->group == group)
				newsyscalls32[j++].entry = syscalls_32bit[i].entry;
		}

		max_nr_32bit_syscalls = count;
		syscalls_32bit = newsyscalls32;

		printf("Found %d 32-bit syscalls in group\n", max_nr_32bit_syscalls);

		/* now the 64 bit table*/
		count = 0, j = 0;

		for_each_64bit_syscall(i) {
			if (syscalls_64bit[i].entry->group == group)
				count++;
		}

		newsyscalls64 = malloc(count * sizeof(struct syscalltable));
		if (newsyscalls64 == NULL)
			return FALSE;

		for_each_64bit_syscall(i) {
			if (syscalls_64bit[i].entry->group == group)
				newsyscalls64[j++].entry = syscalls_64bit[i].entry;
		}

		max_nr_64bit_syscalls = count;
		syscalls_64bit = newsyscalls64;
		printf("Found %d 64-bit syscalls in group\n", max_nr_32bit_syscalls);

	} else {
		/* non-biarch case. */

		for_each_syscall(i) {
			if (syscalls[i].entry->group == group)
				count++;
		}

		newsyscalls = malloc(count * sizeof(struct syscalltable));
		if (newsyscalls == NULL)
			exit(EXIT_FAILURE);

		for_each_syscall(i) {
			if (syscalls[i].entry->group == group)
				newsyscalls[j++].entry = syscalls[i].entry;
		}

		max_nr_syscalls = count;
		syscalls = newsyscalls;

		printf("Found %d syscalls in group\n", max_nr_syscalls);
	}

	return TRUE;
}

const char * print_syscall_name(unsigned int callno, bool bitsize)
{
	const struct syscalltable *table;

	if (bitsize == FALSE)
		table = syscalls_64bit;
	else
		table = syscalls_32bit;

	return table[callno].entry->name;
}
