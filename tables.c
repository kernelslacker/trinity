/*
 * Functions for handling the system call tables.
 */

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include "trinity.h"	// ARRAY_SIZE, alloc_shared
#include "arch.h"
#include "arch-syscalls.h"
#include "syscall.h"
#include "params.h"
#include "log.h"

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

static void validate_specific_syscall(const struct syscalltable *table, int call)
{
	if (call == -1)
		return;

	if (table[call].entry->flags & AVOID_SYSCALL)
		printf("%s is marked as AVOID. Skipping\n", table[call].entry->name);

	if (table[call].entry->flags & NI_SYSCALL)
		printf("%s is NI_SYSCALL. Skipping\n", table[call].entry->name);
}

int validate_specific_syscall_silent(const struct syscalltable *table, int call)
{
	if (call == -1)
		return FALSE;

	if (table[call].entry->flags & AVOID_SYSCALL)
		return FALSE;

	if (table[call].entry->flags & NI_SYSCALL)
		return FALSE;

	return TRUE;
}

void count_syscalls_enabled(void)
{
	unsigned int i;
	unsigned int ecount_32 = 0, ecount_64 = 0;
	unsigned int dcount_32 = 0, dcount_64 = 0;

	if (biarch == TRUE) {
		for_each_64bit_syscall(i) {
			if (syscalls_64bit[i].entry->flags & ACTIVE)
				ecount_64++;
			else
				dcount_64++;
		}

		for_each_32bit_syscall(i) {
			if (syscalls_32bit[i].entry->flags & ACTIVE)
				ecount_32++;
			else
				dcount_32++;
		}
		printf("[%d] 32-bit syscalls: %d enabled, %d disabled.  "
			"64-bit syscalls: %d enabled, %d disabled.\n",
			getpid(), ecount_32, dcount_32, ecount_64, dcount_64);

	} else {

		/* non-biarch */
		for_each_syscall(i) {
			if (syscalls[i].entry->flags & ACTIVE)
				ecount_32++;
			else
				dcount_32++;
		}
		printf("[%d] Enabled %d syscalls. Disabled %d syscalls.\n", getpid(), ecount_32, dcount_32);
	}
}

void init_syscalls(void)
{
	unsigned int i;

	if (biarch == TRUE) {
		for_each_64bit_syscall(i) {
			if (syscalls_64bit[i].entry->flags & ACTIVE)
				if (syscalls_64bit[i].entry->init)
					syscalls_64bit[i].entry->init();
		}

		for_each_32bit_syscall(i) {
			if (syscalls_32bit[i].entry->flags & ACTIVE)
				if (syscalls_32bit[i].entry->init)
					syscalls_32bit[i].entry->init();
		}

	} else {

		/* non-biarch */
		for_each_syscall(i) {
			if (syscalls[i].entry->flags & ACTIVE)
				if (syscalls[i].entry->init)
					syscalls[i].entry->init();
		}
	}
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
		return TRUE;
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

	printf("Marking all syscalls as enabled.\n");
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

static void toggle_syscall_biarch(const char *arg, unsigned char state)
{
	int specific_syscall32 = 0;
	int specific_syscall64 = 0;

	specific_syscall64 = search_syscall_table(syscalls_64bit, max_nr_64bit_syscalls, arg);

	/* If we found a 64bit syscall, validate it. */
	if (specific_syscall64 != -1) {
		validate_specific_syscall(syscalls_64bit, specific_syscall64);

		if (state == TRUE)
			syscalls_64bit[specific_syscall64].entry->flags |= ACTIVE;
		else
			syscalls_64bit[specific_syscall64].entry->flags |= TO_BE_DEACTIVATED;
	}

	/* Search for and validate 32bit */
	specific_syscall32 = search_syscall_table(syscalls_32bit, max_nr_32bit_syscalls, arg);
	if (specific_syscall32 != -1) {
		validate_specific_syscall(syscalls_32bit, specific_syscall32);

		if (state == TRUE)
			syscalls_32bit[specific_syscall32].entry->flags |= ACTIVE;
		else
			syscalls_32bit[specific_syscall32].entry->flags |= TO_BE_DEACTIVATED;
	}

	if ((specific_syscall64 == -1) && (specific_syscall32 == -1)) {
		printf("No idea what syscall (%s) is.\n", arg);
		exit(EXIT_FAILURE);
	}

	/* biarch? */
	if ((specific_syscall64 != -1) && (specific_syscall32 != -1)) {
		printf("[%d] Marking syscall %s (64bit:%d 32bit:%d) as to be %sabled.\n",
			getpid(), arg, specific_syscall64, specific_syscall32,
			state ? "en" : "dis");
		return;
	}

	if (specific_syscall64 != -1) {
		printf("[%d] Marking 64-bit syscall %s (%d) as to be %sabled.\n",
			getpid(), arg, specific_syscall64,
			state ? "en" : "dis");
		return;
	}

	if  (specific_syscall32 != -1) {
		printf("[%d] Marking 32-bit syscall %s (%d) as to be %sabled.\n",
			getpid(), arg, specific_syscall32,
			state ? "en" : "dis");
		return;
	}
}

void toggle_syscall(const char *arg, unsigned char state)
{
	int specific_syscall = 0;

	if (biarch == TRUE) {
		toggle_syscall_biarch(arg, state);
		return;
	}

	/* non-biarch case. */
	specific_syscall = search_syscall_table(syscalls, max_nr_syscalls, arg);
	if (specific_syscall == -1) {
		printf("No idea what syscall (%s) is.\n", arg);
		exit(EXIT_FAILURE);
	}

	validate_specific_syscall(syscalls, specific_syscall);

	if (state == TRUE)
		syscalls[specific_syscall].entry->flags |= ACTIVE;
	else
		syscalls[specific_syscall].entry->flags |= TO_BE_DEACTIVATED;

	printf("[%d] Marking syscall %s (%d) as to be %sabled.\n",
		getpid(), arg, specific_syscall,
		state ? "en" : "dis");
}

void deactivate_disabled_syscalls(void)
{
	unsigned int i;

	printf("Disabling syscalls marked as disabled by command line options\n");

	if (biarch == TRUE) {
		for_each_64bit_syscall(i) {
			if (syscalls_64bit[i].entry->flags & TO_BE_DEACTIVATED) {
				syscalls_64bit[i].entry->flags &= ~(ACTIVE|TO_BE_DEACTIVATED);
				printf("[%d] Marked 64-bit syscall %s (%d) as deactivated.\n",
					getpid(), syscalls_64bit[i].entry->name, syscalls_64bit[i].entry->number);
			}
		}
		for_each_32bit_syscall(i) {
			if (syscalls_32bit[i].entry->flags & TO_BE_DEACTIVATED) {
				syscalls_32bit[i].entry->flags &= ~(ACTIVE|TO_BE_DEACTIVATED);
				printf("[%d] Marked 32-bit syscall %s (%d) as deactivated.\n",
					getpid(), syscalls_32bit[i].entry->name, syscalls_32bit[i].entry->number);
			}
		}

	} else {
		for_each_syscall(i) {
			if (syscalls[i].entry->flags & TO_BE_DEACTIVATED) {
				syscalls[i].entry->flags &= ~(ACTIVE|TO_BE_DEACTIVATED);
				printf("[%d] Marked syscall %s (%d) as deactivated.\n",
					getpid(), syscalls[i].entry->name, syscalls[i].entry->number);
			}
		}
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
			printf("%d %s : ", syscalls[i].entry->number, syscalls[i].entry->name);
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

void select_syscall_tables(void)
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
#elif defined(__s390x__)
	syscalls = copy_syscall_table(syscalls_s390x, ARRAY_SIZE(syscalls_s390x));
	max_nr_syscalls = ARRAY_SIZE(syscalls_s390x);
#elif defined(__s390__)
	syscalls = copy_syscall_table(syscalls_s390, ARRAY_SIZE(syscalls_s390));
	max_nr_syscalls = ARRAY_SIZE(syscalls_s390);
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

		if (count == 0) {
			printf("No 32-bit syscalls in group\n");
			goto try_64bit;
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

try_64bit:
		/* now the 64 bit table*/
		count = 0, j = 0;

		for_each_64bit_syscall(i) {
			if (syscalls_64bit[i].entry->group == group)
				count++;
		}

		if (count == 0) {
			printf("No 64-bit syscalls in group\n");
			return FALSE;
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

		if (count == 0) {
			printf("No syscalls found in group\n");
			return FALSE;
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

const char * print_syscall_name(unsigned int callno, bool is32bit)
{
	const struct syscalltable *table;
	unsigned int max;

	if (biarch == FALSE) {
		max = max_nr_syscalls;
		table = syscalls;
	} else {
		if (is32bit == FALSE) {
			max = max_nr_64bit_syscalls;
			table = syscalls_64bit;
		} else {
			max = max_nr_32bit_syscalls;
			table = syscalls_32bit;
		}
	}

	if (callno >= max) {
		printf("Bogus syscall number in %s (%u)\n", __func__, callno);
		return "invalid-syscall";
	}

	return table[callno].entry->name;
}

// FIXME: in the biarch=TRUE case, we ignore 32bit for now
static const char * lookup_name(unsigned int num)
{
	if (biarch == TRUE) {
		return syscalls_64bit[num].entry->name;
	}

	return syscalls[num].entry->name;
}

void display_enabled_syscalls(void)
{
	unsigned int i;

	if (biarch == TRUE) {
		for_each_64bit_syscall(i) {
			if (syscalls_64bit[i].entry->flags & ACTIVE)
				printf("[%d] 64-bit syscall %d:%s enabled.\n", getpid(), i, syscalls_64bit[i].entry->name);
		}

		for_each_32bit_syscall(i) {
			if (syscalls_32bit[i].entry->flags & ACTIVE)
				printf("[%d] 32-bit syscall %d:%s enabled.\n", getpid(), i, syscalls_32bit[i].entry->name);
		}

	} else {
		/* non-biarch */
		for_each_syscall(i) {
			if (syscalls[i].entry->flags & ACTIVE)
				printf("[%d] syscall %d:%s enabled.\n", getpid(), i, syscalls[i].entry->name);
		}
	}
}

/* If we want just network sockets, don't bother with VM/VFS syscalls */
static bool is_syscall_net_related(const struct syscalltable *table, unsigned int num)
{
	unsigned int i;

	if (no_files == FALSE)
		return TRUE;

	if (table[num].entry->group == GROUP_VM)
		return FALSE;
	if (table[num].entry->group == GROUP_VFS)
		return FALSE;

	for (i = 0; i < table[num].entry->num_args; i++) {
		switch (i) {
		case 0:	if (table[num].entry->arg1type == ARG_PATHNAME)
				return FALSE;
			break;
		case 1:	if (table[num].entry->arg2type == ARG_PATHNAME)
				return FALSE;
			break;
		case 2:	if (table[num].entry->arg3type == ARG_PATHNAME)
				return FALSE;
			break;
		case 3:	if (table[num].entry->arg4type == ARG_PATHNAME)
				return FALSE;
			break;
		case 4:	if (table[num].entry->arg5type == ARG_PATHNAME)
				return FALSE;
			break;
		case 5:	if (table[num].entry->arg6type == ARG_PATHNAME)
				return FALSE;
			break;
		default:
			BUG("impossible!\n");
		}
	}

	return TRUE;
}

void disable_non_net_syscalls(void)
{
	const char *syscallname;
	unsigned int i;

	printf("Disabling non networking related syscalls\n");

	if (biarch == TRUE) {
		for_each_64bit_syscall(i) {
			if (validate_specific_syscall_silent(syscalls_64bit, i) == FALSE)
				continue;

			if (syscalls_64bit[i].entry->flags & ACTIVE) {
				if (is_syscall_net_related(syscalls_64bit, i) == FALSE) {
					syscallname = lookup_name(i);
					toggle_syscall_biarch(syscallname, FALSE);
				}
			}
		}

		for_each_32bit_syscall(i) {
			if (validate_specific_syscall_silent(syscalls_32bit, i) == FALSE)
				continue;

			if (syscalls_32bit[i].entry->flags & ACTIVE) {
				if (is_syscall_net_related(syscalls_32bit, i) == FALSE) {
					syscallname = syscalls_32bit[i].entry->name;
					toggle_syscall_biarch(syscallname, FALSE);
				}
			}
		}

	} else {
		/* non-biarch */
		for_each_syscall(i) {
			if (validate_specific_syscall_silent(syscalls, i) == FALSE)
				continue;

			if (syscalls[i].entry->flags & ACTIVE) {
				if (is_syscall_net_related(syscalls, i) == FALSE) {
					syscallname = lookup_name(i);
					toggle_syscall(syscallname, FALSE);
				}
			}
		}

	}

	deactivate_disabled_syscalls();
}


void enable_random_syscalls(void)
{
	unsigned int i;
	const char *syscallname;
	unsigned int call, call32, call64;

	if (random_selection_num == 0) {
		printf("-r 0 syscalls ? what?\n");
		exit(EXIT_FAILURE);
	}

	if (biarch == TRUE) {
		if (random_selection_num > max_nr_64bit_syscalls) {
			printf("-r val %d out of range (1-%d)\n", random_selection_num, max_nr_64bit_syscalls);
			exit(EXIT_FAILURE);
		}
	} else {
		if (random_selection_num > max_nr_syscalls) {
			printf("-r val %d out of range (1-%d)\n", random_selection_num, max_nr_syscalls);
			exit(EXIT_FAILURE);
		}
	}

	printf("Enabling %d random syscalls\n", random_selection_num);

	for (i = 0; i < random_selection_num; i++) {

retry:
		if (biarch == TRUE) {
			call64 = rand() % max_nr_64bit_syscalls;
			syscallname = lookup_name(call64);
			call32 = search_syscall_table(syscalls_32bit, max_nr_32bit_syscalls, syscallname);

			if (validate_specific_syscall_silent(syscalls_64bit, call64) == FALSE)
				goto retry;
			if (validate_specific_syscall_silent(syscalls_32bit, call32) == FALSE)
				goto retry;

			if (no_files == TRUE) {
				if (is_syscall_net_related(syscalls_64bit, call64) == FALSE)
					goto retry;
				if (is_syscall_net_related(syscalls_32bit, call32) == FALSE)
					goto retry;
			}

			if (syscalls_64bit[call64].entry->flags & TO_BE_DEACTIVATED)
				goto retry;
			if (syscalls_32bit[call32].entry->flags & TO_BE_DEACTIVATED)
				goto retry;

		} else {
			call = rand() % max_nr_syscalls;

			if (validate_specific_syscall_silent(syscalls, call) == FALSE)
				goto retry;

			if (no_files == TRUE)
				if (is_syscall_net_related(syscalls_32bit, call) == FALSE)
					goto retry;

			/* if we've set this to be disabled, don't enable it! */
			if (syscalls[call].entry->flags & TO_BE_DEACTIVATED)
				goto retry;

			syscallname = lookup_name(call);
		}

		toggle_syscall(syscallname, TRUE);
	}
}
