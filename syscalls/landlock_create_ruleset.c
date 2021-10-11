/*
 * SYSCALL_DEFINE3(landlock_create_ruleset,
 *                const struct landlock_ruleset_attr __user *const, attr,
 *                const size_t, size, const __u32, flags)
 */
#include "sanitise.h"

#define LANDLOCK_CREATE_RULESET_VERSION                 (1U << 0)

static unsigned long landlock_create_ruleset_flags[] = {
	LANDLOCK_CREATE_RULESET_VERSION,
};

struct syscallentry syscall_landlock_create_ruleset = {
	.name = "landlock_create_ruleset",
	.num_args = 3,
	.arg1name = "attr",
	.arg2name = "size",
	.arg2type = ARG_LEN,
	.arg3name = "flags",
	.arg3type = ARG_LIST,
	.arg3list = ARGLIST(landlock_create_ruleset_flags),
};
