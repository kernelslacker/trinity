/*
 * Self-check for random_syscall_step_biased() (random_syscall/
 * dispatch-wrappers.c): the consumer the chain executor steers the next
 * link to runs on fresh args, which generate_syscall_args() builds
 * through the consumer's sanitiser as for any call, so a sanitiser is no
 * reason to fall back to a random pick.  The dispatch_step() it ends in
 * is a stand-in that records the entry.
 */

#include <stdbool.h>
#include <string.h>

#include "child.h"			/* struct childdata */
#include "child-api.h"			/* random_syscall_step_biased */
#include "debug.h"			/* BUG */
#include "random-syscall-internal.h"	/* dispatch_step */
#include "syscall.h"			/* struct syscallentry */
#include "tables.h"			/* syscalls, max_nr_syscalls */

static const struct syscallentry *dispatched;

bool __wrap_dispatch_step(struct childdata *child, struct syscallentry *entry,
			  bool *found_new, unsigned long *new_cmp_out,
			  unsigned long *new_transition_out);
bool __wrap_dispatch_step(struct childdata *child, struct syscallentry *entry,
			  bool *found_new, unsigned long *new_cmp_out,
			  unsigned long *new_transition_out)
{
	(void) child;
	(void) found_new;
	(void) new_cmp_out;
	(void) new_transition_out;
	dispatched = entry;
	return true;
}

static bool sanitised;

static void note_sanitise(struct syscallrecord *rec)
{
	(void) rec;
	sanitised = true;
}

void chain_bias_self_check(void);
void chain_bias_self_check(void)
{
	static struct childdata child;
	struct syscallentry consumer = {
		.name = "consumer",
		.sanitise = note_sanitise,
	};
	struct syscalltable table = { .entry = &consumer };
	unsigned long new_transition = 0, new_cmp = 0;
	bool found_new = false, ok;

	syscalls = syscalls_32bit = syscalls_64bit = &table;
	max_nr_syscalls = max_nr_32bit_syscalls = max_nr_64bit_syscalls = 1;

	ok = random_syscall_step_biased(&child, 0, false, false, 0, &found_new,
					&new_transition, &new_cmp);

	/* Back to the empty tables fake_parent.c provides. */
	syscalls = syscalls_32bit = syscalls_64bit = NULL;
	max_nr_syscalls = max_nr_32bit_syscalls = max_nr_64bit_syscalls = 0;

	if (!ok || dispatched != &consumer)
		BUG("chain bias: a consumer with a sanitiser was not dispatched");
	if (!sanitised)
		BUG("chain bias: the consumer's args were not built through its sanitiser");
}
