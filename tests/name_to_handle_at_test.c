/*
 * Self-check for name_to_handle_at's sanitiser: the lookup gets the
 * pathname its generator built, and the empty-path arm empties that
 * buffer in place and asks for AT_EMPTY_PATH, without the
 * AT_HANDLE_CONNECTABLE bit the kernel refuses beside it.
 */

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "arch.h"		/* page_size */
#include "debug.h"		/* BUG */
#include "kernel/fcntl.h"	/* AT_EMPTY_PATH, AT_HANDLE_* */
#include "sanitise.h"		/* get_writable_address */
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_name_to_handle_at */

static unsigned int failed;

static void check(const char *what, bool ok)
{
	if (ok)
		return;
	fprintf(stderr, "name_to_handle_at: %s\n", what);
	failed++;
}

/* Calls per case: the empty-path arm takes one call in eight. */
#define NTH_CALLS	512

static const char path[] = "/proc/self/status";

/* The pathname buffer ARG_PATHNAME would have handed the sanitiser. */
static char name[256];

/* Runs the sanitiser on a call whose generated pathname is path and whose
 * drawn flags are @flags; release() drops the snapshot it installs. */
static void sanitise(struct syscallrecord *rec, unsigned long flags)
{
	memset(rec, 0, sizeof(*rec));
	strcpy(name, path);
	rec->a1 = (unsigned long)(long) AT_FDCWD;
	rec->a2 = (unsigned long) name;
	rec->a5 = flags;
	syscall_name_to_handle_at.sanitise(rec);
}

static void release(struct syscallrecord *rec)
{
	rec->retval = -1UL;
	syscall_name_to_handle_at.post(rec);
}

static void lookup_names_generated_path(void)
{
	static struct syscallrecord rec;
	unsigned int i, emptied = 0;

	for (i = 0; i < NTH_CALLS; i++) {
		sanitise(&rec, AT_HANDLE_CONNECTABLE);
		check("the lookup was handed another buffer than the generated pathname",
		      rec.a2 == (unsigned long) name);
		if (name[0] == '\0') {
			emptied++;
			check("an emptied pathname went out without AT_EMPTY_PATH",
			      (rec.a5 & AT_EMPTY_PATH) != 0);
			check("AT_EMPTY_PATH went out beside AT_HANDLE_CONNECTABLE",
			      (rec.a5 & AT_HANDLE_CONNECTABLE) == 0);
		} else {
			check("the generated pathname was rewritten",
			      strcmp(name, path) == 0);
		}
		release(&rec);
	}
	check("the empty-path arm never fired", emptied > 0);
	check("the empty-path arm took more than one call in four",
	      emptied <= NTH_CALLS / 4);
}

void name_to_handle_at_self_check(void);
void name_to_handle_at_self_check(void)
{
	/* The pool is made once per process: take it as an earlier suite
	 * left it. */
	if (get_writable_address(page_size) == NULL)
		writable_pool_init();

	lookup_names_generated_path();

	if (failed != 0)
		BUG("name_to_handle_at built a call the kernel turns away");
}
