/*
 * cred_class_for_entry() (child/cred_throttle.c), whose answer
 * copy_syscall_table() stamps into each entry: a credential call maps to
 * its class, and so does the 16-bit-id twin a 32-bit table carries, which
 * reaches the same kernel core (kernel/uid16.c); anything else maps to
 * CRED_CLASS_NR.
 */

#include <stdbool.h>
#include <stdio.h>

#include "cred_throttle.h"
#include "debug.h"		/* BUG */
#include "syscall.h"		/* struct syscallentry */
#include "utils.h"		/* ARRAY_SIZE */

/* Owned by main/params/state.c in production; the throttle reads it. */
bool cred_throttle;

static int classify(const char *name)
{
	struct syscallentry entry = { .name = name };

	return cred_class_for_entry(&entry);
}

void cred_class_self_check(void);
void cred_class_self_check(void)
{
	static const char *const outside[] = {
		"getuid", "setuid1", "setuid161", "setuid32", "setresuid16x",
		"capset", "",
	};
	char twin[32];
	unsigned int i;

	for (i = 0; i < CRED_CLASS_NR; i++) {
		if (classify(cred_class_name[i]) != (int) i)
			BUG("cred class: a credential call is not its own class");
		snprintf(twin, sizeof(twin), "%s16", cred_class_name[i]);
		if (classify(twin) != (int) i)
			BUG("cred class: a 16-bit-id twin is not its namesake's class");
	}
	for (i = 0; i < ARRAY_SIZE(outside); i++) {
		if (classify(outside[i]) != CRED_CLASS_NR)
			BUG("cred class: a call outside the set has a class");
	}
}
