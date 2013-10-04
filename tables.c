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
#include "shm.h"

#define NOTFOUND (unsigned int)-1

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

static void activate_syscall_in_table(unsigned int calln, unsigned int *nr_active, const struct syscalltable *table, int *active_syscall)
{
	struct syscall *call_ptr;

	call_ptr = table[calln].entry;

	//Check if the call is activated already, and activate it only if needed
	if (call_ptr->active_number == 0) {
		//Sanity check
		if ((*nr_active + 1) > MAX_NR_SYSCALL) {
			output(0, "[tables] MAX_NR_SYSCALL needs to be increased. More syscalls than active table can fit.\n");
			exit(EXIT_FAILURE);
		}

		//save the call no
		active_syscall[*nr_active] = calln + 1;
		(*nr_active) += 1;
		call_ptr->active_number = *nr_active;
	}
}

void activate_syscall32(unsigned int calln)
{
	activate_syscall_in_table(calln, &shm->nr_active_32bit_syscalls, syscalls_32bit, shm->active_syscalls32);
}

void activate_syscall64(unsigned int calln)
{
	activate_syscall_in_table(calln, &shm->nr_active_64bit_syscalls, syscalls_64bit, shm->active_syscalls64);
}

void activate_syscall(unsigned int calln)
{
	activate_syscall_in_table(calln, &shm->nr_active_syscalls, syscalls, shm->active_syscalls);
}

static void deactivate_syscall_in_table(unsigned int calln, unsigned int *nr_active, const struct syscalltable *table, int *active_syscall)
{
	struct syscall *call_ptr;
	unsigned int i;

	call_ptr = table[calln].entry;
	//Check if the call is activated already, and deactivate it only if needed
	if ((call_ptr->active_number != 0) && (*nr_active > 0)) {
		for (i = call_ptr->active_number - 1; i < *nr_active - 1; i++) {
			active_syscall[i] = active_syscall[i + 1];
			table[active_syscall[i] - 1].entry->active_number = i + 1;
		}
		//The last step is to erase the last item.
		active_syscall[*nr_active - 1] = 0;
		(*nr_active) -= 1;
		call_ptr->active_number = 0;
	}
}

void deactivate_syscall32(unsigned int calln)
{
	deactivate_syscall_in_table(calln, &shm->nr_active_32bit_syscalls, syscalls_32bit, shm->active_syscalls32);
}

void deactivate_syscall64(unsigned int calln)
{
	deactivate_syscall_in_table(calln, &shm->nr_active_64bit_syscalls, syscalls_64bit, shm->active_syscalls64);
}

void deactivate_syscall(unsigned int calln)
{
	deactivate_syscall_in_table(calln, &shm->nr_active_syscalls, syscalls, shm->active_syscalls);
}

void count_syscalls_enabled(void)
{
	if (biarch == TRUE) {
		printf("[init] 32-bit syscalls: %d enabled, %d disabled.  "
			"64-bit syscalls: %d enabled, %d disabled.\n",
			shm->nr_active_32bit_syscalls, max_nr_32bit_syscalls - shm->nr_active_32bit_syscalls,
			shm->nr_active_64bit_syscalls, max_nr_64bit_syscalls - shm->nr_active_64bit_syscalls);
	} else {
		printf("Enabled %d syscalls. Disabled %d syscalls.\n",
			shm->nr_active_syscalls, max_nr_syscalls - shm->nr_active_syscalls);
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
	if (biarch == TRUE) {
		if ((shm->nr_active_32bit_syscalls == 0) && (shm->nr_active_64bit_syscalls == 0))
			return TRUE;
		else
			return FALSE;
	}

	/* non-biarch */
	if (shm->nr_active_syscalls == 0)
		return TRUE;
	else
		return FALSE;
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

/* Make sure there's at least one syscall enabled. */
int validate_syscall_tables(void)
{
	unsigned int ret;

	if (biarch == TRUE) {
		ret = validate_syscall_table_32();
		ret |= validate_syscall_table_64();
		return ret;
	}

	/* non-biarch case*/
	if (shm->nr_active_syscalls == 0)
		return FALSE;
	else
		return TRUE;
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
		if (do_32_arch)
			for_each_32bit_syscall(i) {
				syscalls_32bit[i].entry->flags |= ACTIVE;
				activate_syscall32(i);
			}
		if (do_64_arch)
			for_each_64bit_syscall(i) {
				syscalls_64bit[i].entry->flags |= ACTIVE;
				activate_syscall64(i);
			}
	} else {
		for_each_syscall(i) {
			syscalls[i].entry->flags |= ACTIVE;
			activate_syscall(i);
		}
	}
}

static void check_user_specified_arch(const char *arg, char **arg_name, bool *only_64bit, bool *only_32bit)
{
	//Check if the arch is specified
	char *arg_arch = strstr(arg,",");
	unsigned long size = 0;

	if (arg_arch  != NULL) {
		size = (unsigned long)arg_arch - (unsigned long)arg;
		*arg_name = malloc(size + 1);
		if (*arg_name == NULL)
			exit(EXIT_FAILURE);
		(*arg_name)[size] = 0;
		memcpy(*arg_name, arg, size);

		//identify architecture
		if ((only_64bit != NULL) && (only_32bit != NULL)) {
			if ((strcmp(arg_arch + 1, "64") == 0)) {
				*only_64bit = TRUE;
				*only_32bit = FALSE;
			} else if ((strcmp(arg_arch + 1,"32") == 0)) {
				*only_64bit = FALSE;
				*only_32bit = TRUE;
			} else {
				printf("Unknown bit width (%s). Choose 32, or 64.\n", arg);
				exit(EXIT_FAILURE);
			}
		}
	} else {
		*arg_name = (char*)arg;//castaway const.
	}


}

static void clear_check_user_specified_arch(const char *arg, char **arg_name)
{
	//Release memory only if we have allocated it
	if (((char *)arg) != *arg_name) {
		free(*arg_name);
		*arg_name = NULL;
	}
}

static void toggle_syscall_biarch_n(int calln, const struct syscalltable *table, bool onlyflag, bool doflag, bool state, void (*activate)(unsigned int), int arch_bits, const char *arg_name)
{
	if (calln != -1) {
		validate_specific_syscall(table, calln);

		if ((state == TRUE) && onlyflag && doflag) {
			table[calln].entry->flags |= ACTIVE;
			(*activate)(calln);
		} else {
			table[calln].entry->flags |= TO_BE_DEACTIVATED;
		}
	}

	if ((arch_bits != 0) && (calln != -1))
		printf("Marking %d-bit syscall %s (%d) as to be %sabled.\n",
			arch_bits, arg_name, calln,
			state ? "en" : "dis");
}

static void toggle_syscall_biarch(const char *arg, bool state)
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
		printf("No idea what architecture for syscall (%s) is.\n", arg);
		exit(EXIT_FAILURE);
	}

	if ((specific_syscall64 == -1) && (specific_syscall32 == -1)) {
		printf("No idea what syscall (%s) is.\n", arg);
		exit(EXIT_FAILURE);
	}

	if ((specific_syscall64 != -1) && (specific_syscall32 != -1)) {
		printf("Marking syscall %s (64bit:%d 32bit:%d) as to be %sabled.\n",
			arg_name, specific_syscall64, specific_syscall32,
			state ? "en" : "dis");
		clear_check_user_specified_arch(arg, &arg_name);
		return;
	}

	if (specific_syscall64 != -1) {
		printf("Marking 64-bit syscall %s (%d) as to be %sabled.\n",
			arg, specific_syscall64,
			state ? "en" : "dis");
		clear_check_user_specified_arch(arg, &arg_name);
		return;
	}

	if  (specific_syscall32 != -1) {
		printf("Marking 32-bit syscall %s (%d) as to be %sabled.\n",
			arg, specific_syscall32,
			state ? "en" : "dis");
		clear_check_user_specified_arch(arg, &arg_name);
		return;
	}

}

static void toggle_syscall_n(int calln, bool state, const char *arg, const char *arg_name)
{
	if (calln == -1) {
		printf("No idea what syscall (%s) is.\n", arg);
		exit(EXIT_FAILURE);
	}

	validate_specific_syscall(syscalls, calln);

	if (state == TRUE) {
		syscalls[calln].entry->flags |= ACTIVE;
		activate_syscall(calln);
	} else {
		syscalls[calln].entry->flags |= TO_BE_DEACTIVATED;
	}

	printf("Marking syscall %s (%d) as to be %sabled.\n",
		arg_name, calln,
		state ? "en" : "dis");
}

void toggle_syscall(const char *arg, bool state)
{
	int specific_syscall = 0;
	char * arg_name = NULL;

	if (biarch == TRUE) {
		toggle_syscall_biarch(arg, state);
		return;
	}

	/* non-biarch case. */
	check_user_specified_arch(arg, &arg_name, NULL, NULL); //We do not care about arch here, just to get rid of arg flags.
	specific_syscall = search_syscall_table(syscalls, max_nr_syscalls, arg_name);
	toggle_syscall_n(specific_syscall, state, arg, arg_name);
	clear_check_user_specified_arch(arg, &arg_name);
}

void deactivate_disabled_syscalls(void)
{
	unsigned int i;

	printf("Disabling syscalls marked as disabled by command line options\n");

	if (biarch == TRUE) {
		for_each_64bit_syscall(i) {
			if (syscalls_64bit[i].entry->flags & TO_BE_DEACTIVATED) {
				syscalls_64bit[i].entry->flags &= ~(ACTIVE|TO_BE_DEACTIVATED);
				deactivate_syscall64(i);
				printf("Marked 64-bit syscall %s (%d) as deactivated.\n",
					syscalls_64bit[i].entry->name, syscalls_64bit[i].entry->number);
			}
		}
		for_each_32bit_syscall(i) {
			if (syscalls_32bit[i].entry->flags & TO_BE_DEACTIVATED) {
				syscalls_32bit[i].entry->flags &= ~(ACTIVE|TO_BE_DEACTIVATED);
				deactivate_syscall32(i);
				printf("Marked 32-bit syscall %s (%d) as deactivated.\n",
					syscalls_32bit[i].entry->name, syscalls_32bit[i].entry->number);
			}
		}

	} else {
		for_each_syscall(i) {
			if (syscalls[i].entry->flags & TO_BE_DEACTIVATED) {
				syscalls[i].entry->flags &= ~(ACTIVE|TO_BE_DEACTIVATED);
				deactivate_syscall(i);
				printf("Marked syscall %s (%d) as deactivated.\n",
					syscalls[i].entry->name, syscalls[i].entry->number);
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

	copy = alloc_shared(nr * sizeof(struct syscall));
	if (copy == NULL)
		exit(EXIT_FAILURE);

	for (n = 0; n < nr; n++) {
		memcpy(copy + n , from[n].entry, sizeof(struct syscall));
		copy[n].number = n;
		copy[n].active_number = 0;
		from[n].entry = &copy[n];
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
#elif defined(__aarch64__)
	syscalls = copy_syscall_table(syscalls_aarch64, ARRAY_SIZE(syscalls_aarch64));
	max_nr_syscalls = ARRAY_SIZE(syscalls_aarch64);
#else
#error Unknown architecture.
#endif

}

int setup_syscall_group(unsigned int group)
{
	unsigned int i;

	if (biarch == TRUE) {
		for_each_32bit_syscall(i) {
			if (syscalls_32bit[i].entry->group == group)
				activate_syscall32(i);
		}

		if (shm->nr_active_32bit_syscalls == 0) {
			printf("No 32-bit syscalls in group\n");
		} else {
			printf("Found %d 32-bit syscalls in group\n", shm->nr_active_32bit_syscalls);
		}

		/* now the 64 bit table*/
		for_each_64bit_syscall(i) {
			if (syscalls_64bit[i].entry->group == group)
				activate_syscall64(i);
		}

		if (shm->nr_active_64bit_syscalls == 0) {
			printf("No 64-bit syscalls in group\n");
			return FALSE;
		} else {
			printf("Found %d 64-bit syscalls in group\n", shm->nr_active_64bit_syscalls);
		}

	} else {
		/* non-biarch case. */
		for_each_syscall(i) {
			if (syscalls[i].entry->group == group)
				activate_syscall(i);
		}

		if (shm->nr_active_syscalls == 0) {
			printf("No syscalls found in group\n");
			return FALSE;
		} else {
			printf("Found %d syscalls in group\n", shm->nr_active_syscalls);
		}
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

void display_enabled_syscalls(void)
{
	unsigned int i;

	if (biarch == TRUE) {
		for_each_64bit_syscall(i) {
			if (syscalls_64bit[i].entry->flags & ACTIVE)
				printf("64-bit syscall %d:%s enabled.\n", i, syscalls_64bit[i].entry->name);
		}

		for_each_32bit_syscall(i) {
			if (syscalls_32bit[i].entry->flags & ACTIVE)
				printf("32-bit syscall %d:%s enabled.\n", i, syscalls_32bit[i].entry->name);
		}

	} else {
		/* non-biarch */
		for_each_syscall(i) {
			if (syscalls[i].entry->flags & ACTIVE)
				printf("syscall %d:%s enabled.\n", i, syscalls[i].entry->name);
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
	unsigned int i;

	printf("Disabling non networking related syscalls\n");

	if (biarch == TRUE) {
		for_each_64bit_syscall(i) {
			if (validate_specific_syscall_silent(syscalls_64bit, i) == FALSE)
				continue;

			if (syscalls_64bit[i].entry->flags & ACTIVE) {
				if (is_syscall_net_related(syscalls_64bit, i) == FALSE) {
					toggle_syscall_biarch_n(i, syscalls_64bit, FALSE, do_64_arch, FALSE,
								&activate_syscall64, 64, syscalls_64bit[i].entry->name);
				}
			}
		}

		for_each_32bit_syscall(i) {
			if (validate_specific_syscall_silent(syscalls_32bit, i) == FALSE)
				continue;

			if (syscalls_32bit[i].entry->flags & ACTIVE) {
				if (is_syscall_net_related(syscalls_32bit, i) == FALSE) {
					toggle_syscall_biarch_n(i, syscalls_32bit, FALSE, do_32_arch, FALSE,
								&activate_syscall32, 32, syscalls_32bit[i].entry->name);
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
					toggle_syscall_n(i, FALSE, syscalls[i].entry->name, syscalls[i].entry->name);
				}
			}
		}

	}

	deactivate_disabled_syscalls();
}


void enable_random_syscalls(void)
{
	unsigned int i;
	unsigned int call, call32, call64;

	if (random_selection_num == 0) {
		printf("-r 0 syscalls ? what?\n");
		exit(EXIT_FAILURE);
	}

	if (biarch == TRUE) {
		if ((random_selection_num > max_nr_64bit_syscalls) && do_64_arch) {
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
			call64 = NOTFOUND;
			call32 = NOTFOUND;

			//Search for 64 bit version
			if (do_64_arch) {
				call64 = rand() % max_nr_64bit_syscalls;
				if (validate_specific_syscall_silent(syscalls_64bit, call64) == FALSE)
					goto retry;

				if (no_files == TRUE)
					if (is_syscall_net_related(syscalls_64bit, call64) == FALSE)
						goto retry;

				if ((syscalls_64bit[call64].entry->flags & TO_BE_DEACTIVATED) || (syscalls_64bit[call64].entry->active_number != 0))
					goto try32bit;

				//If we got so far, then active it.
				toggle_syscall_biarch_n(call64, syscalls_64bit, TRUE, do_64_arch, TRUE,
							&activate_syscall64, 64, syscalls_64bit[call64].entry->name);
			}
try32bit:
			//Search for 32 bit version
			if (do_32_arch) {

				if (do_64_arch) {
					call32 = search_syscall_table(syscalls_32bit, max_nr_32bit_syscalls, syscalls_64bit[call64].entry->name);
					if (syscalls_64bit[call64].entry->flags & TO_BE_DEACTIVATED)
						call64 = NOTFOUND; //mark as not found in order not to increment i.
				} else {
					call32 = rand() % max_nr_32bit_syscalls;
				}

				if (validate_specific_syscall_silent(syscalls_32bit, call32) == FALSE) {
					if (call64 == NOTFOUND)
						goto retry;
					else
						continue;
				}

				if (no_files == TRUE)
					if (is_syscall_net_related(syscalls_32bit, call32) == FALSE) {
						if (call64 == NOTFOUND)
							goto retry;
						else
							continue;
					}

				if ((syscalls_32bit[call32].entry->flags & TO_BE_DEACTIVATED) || (syscalls_32bit[call32].entry->active_number != 0)) {
					if (call64 == NOTFOUND)
						goto retry;
					else
						continue;
				}

				//If we got so far, then active it.
				toggle_syscall_biarch_n(call32, syscalls_32bit, TRUE, do_32_arch, TRUE,
							&activate_syscall32, 32, syscalls_32bit[call32].entry->name);
			}

		} else {
			/* non-biarch case */

			call = rand() % max_nr_syscalls;

			if (validate_specific_syscall_silent(syscalls, call) == FALSE)
				goto retry;

			if (no_files == TRUE)
				if (is_syscall_net_related(syscalls, call) == FALSE)
					goto retry;

			/* if we've set this to be disabled, don't enable it! */
			if (syscalls[call].entry->flags & TO_BE_DEACTIVATED)
				goto retry;

			toggle_syscall_n(call, FALSE, syscalls[call].entry->name, syscalls[call].entry->name);
		}
	}
}
