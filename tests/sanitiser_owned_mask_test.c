/*
 * Self-check for the users of syscallentry.sanitiser_owned_mask:
 * generic_sanitise() must zero an owned slot without generating it,
 * arg_meta_init() must label it ARG_OWNER_SANITISER, and
 * sanity_check_tables() must refuse a mask with no .sanitise behind it
 * or with a bit at or past num_args.
 */

#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "arch.h"		/* biarch */
#include "args-internal.h"	/* fill_arg */
#include "debug.h"		/* BUG */
#include "sanitise.h"		/* generic_sanitise */
#include "syscall.h"		/* arg_meta_init */
#include "tables.h"		/* syscalls, max_nr_syscalls, sanity_check_tables */
#include "utils.h"		/* waitpid_eintr */

/* Bit (argnum - 1) is set for each slot generic_sanitise() generated. */
static unsigned int filled;

unsigned long fill_arg(struct syscallentry *entry, struct syscallrecord *rec,
		       unsigned int argnum)
{
	(void)entry; (void)rec;
	filled |= 1u << (argnum - 1);
	return 0x1000 + argnum;
}

/* One owned slot per pass, so a slip in any single slot shows up.  The
 * slots start out holding a previous call's value, which must not
 * survive in the owned slot either. */
static void owned_slot_not_generated(void)
{
	static struct syscallrecord rec;
	unsigned long *const slot[6] = {
		&rec.a1, &rec.a2, &rec.a3, &rec.a4, &rec.a5, &rec.a6,
	};
	unsigned int i, k;

	for (k = 0; k < 6; k++) {
		struct syscallentry entry = {
			.num_args = 6,
			.sanitiser_owned_mask = (uint8_t)(1u << k),
		};

		for (i = 0; i < 6; i++)
			*slot[i] = 0xdead;
		filled = 0;

		generic_sanitise(&entry, &rec);

		if (filled != (0x3fu & ~(1u << k)))
			BUG("generic_sanitise: generated a sanitiser-owned slot");
		for (i = 0; i < 6; i++) {
			unsigned long want = (i == k) ? 0 : 0x1000 + i + 1;

			if (*slot[i] != want)
				BUG("generic_sanitise: wrong value left in a slot");
		}
	}
}

static void owned_slot_labelled(void)
{
	static struct syscallrecord rec;
	struct syscallentry entry = {
		.num_args = 2,
		.argtype = { ARG_STRUCT_PTR_IN, ARG_STRUCT_PTR_IN },
		.sanitiser_owned_mask = (1u << 1),
	};

	arg_meta_init(&entry, &rec);

	if (rec.arg_meta[1].owner != ARG_OWNER_SANITISER)
		BUG("arg_meta_init: a sanitiser-owned slot is not labelled as such");
	if (rec.arg_meta[0].owner != ARG_OWNER_GENERIC)
		BUG("arg_meta_init: an unowned struct slot lost its generic owner");
}

static void fake_sanitise(struct syscallrecord *rec)
{
	(void)rec;
}

/* sanity_check_tables() exits on a bad entry, so run it over a one-entry
 * table in a child and return the child's exit status.  The child's
 * stderr goes to /dev/null: the refusals are expected. */
static int table_check_status(unsigned int num_args, uint8_t mask,
			      bool has_sanitise)
{
	struct syscallentry entry = {
		.name = "owned_mask_probe",
		.num_args = num_args,
		.argname = { "a1", "a2", "a3", "a4", "a5", "a6" },
		.sanitise = has_sanitise ? fake_sanitise : NULL,
		.sanitiser_owned_mask = mask,
	};
	struct syscalltable table = { .entry = &entry };
	int status, devnull;
	pid_t pid;

	pid = fork();
	if (pid < 0)
		BUG("sanity_check_tables: fork failed");
	if (pid == 0) {
		devnull = open("/dev/null", O_WRONLY);
		if (devnull >= 0)
			dup2(devnull, STDERR_FILENO);
		biarch = false;
		syscalls = &table;
		max_nr_syscalls = 1;
		sanity_check_tables();
		_exit(0);
	}
	if (waitpid_eintr(pid, &status, 0) != pid || !WIFEXITED(status))
		BUG("sanity_check_tables: the check child did not exit");
	return WEXITSTATUS(status);
}

static void bad_mask_refused(void)
{
	if (table_check_status(2, 1u << 1, true) != 0)
		BUG("sanity_check_tables: refused a mask on the last real slot");
	if (table_check_status(2, 1u << 2, true) != EXIT_FAILURE)
		BUG("sanity_check_tables: accepted a mask bit at num_args");
	if (table_check_status(2, 1u << 7, true) != EXIT_FAILURE)
		BUG("sanity_check_tables: accepted a mask bit past every slot");
	if (table_check_status(2, 1u << 1, false) != EXIT_FAILURE)
		BUG("sanity_check_tables: accepted a mask with no .sanitise");
}

void sanitiser_owned_mask_self_check(void);
void sanitiser_owned_mask_self_check(void)
{
	owned_slot_not_generated();
	owned_slot_labelled();
	bad_mask_refused();
}
