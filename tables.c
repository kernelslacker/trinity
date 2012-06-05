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

struct syscalltable *syscalls;
struct syscalltable *syscalls_32bit;
struct syscalltable *syscalls_64bit;

unsigned long long syscallcount = 0;

unsigned int max_nr_syscalls;
unsigned int max_nr_32bit_syscalls;
unsigned int max_nr_64bit_syscalls;


int search_syscall_table(struct syscalltable *table, unsigned int nr_syscalls, char *arg)
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

int validate_specific_syscall(struct syscalltable *table, int call)
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

void mark_all_syscalls_active(void)
{
	unsigned int i;

	if (biarch == TRUE) {
		for (i = 0; i < max_nr_32bit_syscalls; i++)
			syscalls_32bit[i].entry->flags |= ACTIVE;
		for (i = 0; i < max_nr_64bit_syscalls; i++)
			syscalls_64bit[i].entry->flags |= ACTIVE;
	} else {
		for (i = 0; i < max_nr_syscalls; i++)
			syscalls[i].entry->flags |= ACTIVE;
	}
}

void toggle_syscall(char *arg, unsigned char state)
{
	int specific_syscall32 = 0;
	int specific_syscall64 = 0;
	int ret;

	if (biarch == TRUE)
		specific_syscall64 = search_syscall_table(syscalls_64bit, max_nr_64bit_syscalls, arg);
	else
		specific_syscall64 = -1;

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

void dump_syscall_tables(void)
{
	unsigned int i;

	if (biarch == TRUE) {
		for (i = 0; i < max_nr_32bit_syscalls; i++) {
			printf("32bit %s : ", syscalls_32bit[i].entry->name);
			if (syscalls_32bit[i].entry->flags & ACTIVE)
				printf("Enabled\n");
			else
				printf("Disabled\n");
		}
		for (i = 0; i < max_nr_64bit_syscalls; i++) {
			printf("64bit %s : ", syscalls_64bit[i].entry->name);
			if (syscalls_64bit[i].entry->flags & ACTIVE)
				printf("Enabled\n");
			else
				printf("Disabled\n");
		}
	} else {
		for (i = 0; i < max_nr_syscalls; i++) {
			printf("%s : ", syscalls[i].entry->name);
			if (syscalls[i].entry->flags & ACTIVE)
				printf("Enabled\n");
			else
				printf("Disabled\n");
		}
	}
}

void setup_syscall_tables(void)
{
	unsigned int i;

#if defined(__x86_64__)
	syscalls_64bit = syscalls_x86_64;
	syscalls_32bit = syscalls_i386;
	max_nr_64bit_syscalls = NR_X86_64_SYSCALLS;
	max_nr_32bit_syscalls = NR_I386_SYSCALLS;
	biarch = TRUE;
#elif defined(__i386__)
	syscalls = syscalls_i386;
	max_nr_syscalls = NR_I386_SYSCALLS;
#elif defined(__powerpc__)
	syscalls = syscalls_ppc;
#elif defined(__ia64__)
	syscalls = syscalls_ia64;
#elif defined(__sparc__)
	syscalls = syscalls_sparc;
#else
	syscalls = syscalls_i386;
#endif

	if (biarch == TRUE) {
		for (i = 0; i < max_nr_32bit_syscalls; i++)
			syscalls_32bit[i].entry->number = i;

		for (i = 0; i < max_nr_64bit_syscalls; i++)
			syscalls_64bit[i].entry->number = i;
	} else {
		for (i = 0; i < max_nr_syscalls; i++)
			syscalls[i].entry->number = i;
	}
}


int setup_syscall_group(unsigned int group)
{
	struct syscalltable *newsyscalls;
	struct syscalltable *newsyscalls32;
	struct syscalltable *newsyscalls64;

	unsigned int i;
	int count = 0, j = 0;

	if (biarch == TRUE) {
		for (i = 0; i < max_nr_32bit_syscalls; i++) {
			if (syscalls_32bit[i].entry->group == group)
				count++;
		}

		newsyscalls32 = malloc(count * sizeof(struct syscalltable));
		if (newsyscalls32 == NULL)
			return FALSE;

		for (i = 0; i < max_nr_32bit_syscalls; i++) {
			if (syscalls_32bit[i].entry->group == group)
				newsyscalls32[j++].entry = syscalls_32bit[i].entry;
		}

		max_nr_32bit_syscalls = count;
		syscalls_32bit = newsyscalls32;

		printf("Found %d 32 bit syscalls in group\n", max_nr_32bit_syscalls);

		/* now the 64 bit table*/
		count = 0, j = 0;

		for (i = 0; i < max_nr_64bit_syscalls; i++) {
			if (syscalls_64bit[i].entry->group == group)
				count++;
		}

		newsyscalls64 = malloc(count * sizeof(struct syscalltable));
		if (newsyscalls64 == NULL)
			return FALSE;

		for (i = 0; i < max_nr_64bit_syscalls; i++) {
			if (syscalls_64bit[i].entry->group == group)
				newsyscalls64[j++].entry = syscalls_64bit[i].entry;
		}

		max_nr_64bit_syscalls = count;
		syscalls_64bit = newsyscalls64;
		printf("Found %d 64 bit syscalls in group\n", max_nr_32bit_syscalls);

	} else {
		for (i = 0; i < max_nr_syscalls; i++) {
			if (syscalls[i].entry->group == group)
				count++;
		}

		newsyscalls = malloc(count * sizeof(struct syscalltable));
		if (newsyscalls == NULL)
			exit(EXIT_FAILURE);

		for (i = 0; i < max_nr_syscalls; i++) {
			if (syscalls[i].entry->group == group)
				newsyscalls[j++].entry = syscalls[i].entry;
		}

		max_nr_syscalls = count;
		syscalls = newsyscalls;

		printf("Found %d syscalls in group\n", max_nr_syscalls);
	}

	return TRUE;
}
