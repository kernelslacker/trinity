/*
 * Self-check for the users of syscallentry.sanitiser_owned_mask:
 * generic_sanitise() must zero an owned slot without generating it,
 * arg_meta_init() must label it ARG_OWNER_SANITISER, and
 * sanity_check_tables() must refuse a mask with no .sanitise behind it
 * or with a bit at or past num_args.  The real entries that set the mask
 * must own what their sanitisers write on every path.  And the sanitiser
 * generate_syscall_args() runs must find its own entry on the record.
 */

#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "arch.h"		/* biarch */
#include "blob_corpus.h"	/* blob_corpus_clear_pending */
#include "cmp_hints.h"		/* cmp_hints_feedback_reset_stash */
#include "debug.h"		/* BUG */
#include "objects.h"		/* enum obj_scope, struct objhead */
#include "sanitise.h"		/* generic_sanitise, generate_syscall_args */
#include "syscall.h"		/* arg_meta_init */
#include "syscalls/syscalls.h"	/* syscall_prctl, syscall_keyctl, ... */
#include "tables.h"		/* syscalls, max_nr_syscalls, sanity_check_tables */
#include "utils.h"		/* waitpid_eintr */
#include "utils-macros.h"	/* ARRAY_SIZE */

extern struct objhead *(*fake_get_objhead)(enum obj_scope scope,
					   enum objecttype type);	/* fake_objects.c */

/* Bit (argnum - 1) is set for each slot generic_sanitise() generated. */
static unsigned int filled;

unsigned long __wrap_fill_arg(struct syscallentry *entry,
			      struct syscallrecord *rec, unsigned int argnum);
unsigned long __wrap_fill_arg(struct syscallentry *entry,
			      struct syscallrecord *rec, unsigned int argnum)
{
	(void)entry; (void)rec;
	filled |= 1u << (argnum - 1);
	return 0x1000 + argnum;
}

/* generate_syscall_args() reaches these. */
void blob_corpus_clear_pending(void)
{
}

void cmp_hints_feedback_reset_stash(void)
{
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

static const struct syscallentry *entry_seen;

static void note_entry(struct syscallrecord *rec)
{
	entry_seen = rec->entry;
}

/* A sanitiser shared by two entries tells them apart by the entry on the
 * record, which still holds the previous call's until
 * generate_syscall_args() puts this one's there. */
static void sanitiser_sees_its_entry(void)
{
	static struct syscallrecord rec;
	struct syscallentry entry = {
		.name = "entry_probe",
		.sanitise = note_entry,
	};
	struct syscallentry previous = { .name = "previous_call" };
	struct syscalltable table = { .entry = &entry };

	syscalls = syscalls_32bit = syscalls_64bit = &table;
	max_nr_syscalls = max_nr_32bit_syscalls = max_nr_64bit_syscalls = 1;

	rec.entry = &previous;
	generate_syscall_args(&rec);

	/* Back to the empty tables fake_parent.c provides. */
	syscalls = syscalls_32bit = syscalls_64bit = NULL;
	max_nr_syscalls = max_nr_32bit_syscalls = max_nr_64bit_syscalls = 0;

	if (entry_seen != &entry)
		BUG("generate_syscall_args: the sanitiser read another call's entry");
}

/* sanity_check_tables() exits on a bad entry, so run it over a one-entry
 * table in a child and return the child's exit status.  The child's
 * stderr goes to /dev/null: the refusals are expected.  Shared with
 * arg_coupling_test.c. */
int entry_check_status(struct syscallentry *entry);
int entry_check_status(struct syscallentry *entry)
{
	struct syscalltable table = { .entry = entry };
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

	return entry_check_status(&entry);
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

/* The real entries that set the mask and the slots each is expected to
 * own, one bit per slot.  A sanitiser that skips an owned slot on any
 * path sends the zero generic_sanitise() left there to the kernel, so
 * the sanitiser runs below and must write every one.  An entry can be
 * listed once its TU is linked into the test binary; one with a .cleanup
 * has it run after each draw, as the dispatcher does, so whatever its
 * sanitiser made for the call goes with it. */
static struct syscallentry *const owner_entry[] = {
	&syscall_prctl, &syscall_keyctl, &syscall_socket, &syscall_socketpair,
	&syscall_futex_wake, &syscall_quotactl, &syscall_nice,
	&syscall_personality, &syscall_mseal,
};
static const uint8_t owner_slots[] = {
	1u << 0, 1u << 0, 0x07, 0x0f, 0x0a, 1u << 0, 1u << 0, 1u << 0, 0x07,
};

#define OWNER_RUNS	2048
#define OWNER_MARK(k)	(0x5a5a00UL + (k))

/* No pools, so a sanitiser that draws from one takes its empty-pool arm. */
static struct objhead *no_pools(enum obj_scope scope, enum objecttype type)
{
	(void)scope; (void)type;
	return NULL;
}

static void real_entries_own_what_they_write(void)
{
	static struct syscallrecord rec;
	unsigned long *const slot[6] = {
		&rec.a1, &rec.a2, &rec.a3, &rec.a4, &rec.a5, &rec.a6,
	};
	unsigned int e, i, k;

	fake_get_objhead = no_pools;

	for (e = 0; e < ARRAY_SIZE(owner_entry); e++) {
		struct syscallentry *entry = owner_entry[e];
		unsigned int owned = owner_slots[e];

		if (entry->sanitiser_owned_mask != owned)
			BUG("sanitiser_owned_mask: a real entry owns other slots than the test lists");
		if (entry_check_status(entry) != 0)
			BUG("sanity_check_tables: refused a real entry");

		filled = 0;
		generic_sanitise(entry, &rec);
		if (filled != (((1u << entry->num_args) - 1) & ~owned))
			BUG("generic_sanitise: a real entry's owned slots were generated or an unowned one skipped");

		for (i = 0; i < OWNER_RUNS; i++) {
			memset(&rec, 0, sizeof(rec));
			for (k = 0; k < entry->num_args; k++) {
				if ((owned >> k) & 1)
					*slot[k] = OWNER_MARK(k);
			}
			entry->sanitise(&rec);
			for (k = 0; k < entry->num_args; k++) {
				if (((owned >> k) & 1) && *slot[k] == OWNER_MARK(k))
					BUG("a sanitiser left a slot it owns unwritten");
			}
			if (entry->cleanup != NULL)
				entry->cleanup(&rec);
			free((void *) rec.post_state);
		}
	}

	fake_get_objhead = NULL;
}

void sanitiser_owned_mask_self_check(void);
void sanitiser_owned_mask_self_check(void)
{
	owned_slot_not_generated();
	owned_slot_labelled();
	bad_mask_refused();
	real_entries_own_what_they_write();
	sanitiser_sees_its_entry();
}

/* The pass above runs before any suite has made the writable pool, so a
 * sanitiser that fills a slot from it takes its empty-pool arm.  Run
 * again once a later suite has made it, taking it as that suite left
 * it, so the pool arm is covered too. */
void sanitiser_owned_mask_pool_self_check(void);
void sanitiser_owned_mask_pool_self_check(void)
{
	if (get_writable_address(sizeof(unsigned long)) == NULL)
		writable_pool_init();
	real_entries_own_what_they_write();
}
