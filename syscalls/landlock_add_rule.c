/*
 * SYSCALL_DEFINE4(landlock_add_rule,
 *                const int, ruleset_fd, const enum landlock_rule_type, rule_type,
 *                const void __user *const, rule_attr, const __u32, flags)
 */
#include "sanitise.h"

enum landlock_rule_type {
	LANDLOCK_RULE_PATH_BENEATH = 1,
};

static unsigned long landlock_ruletypes[] = {
	LANDLOCK_RULE_PATH_BENEATH,
};

// no flags for now
//static unsigned long landlock_add_rule_flags[] = {
//	,
//};

struct syscallentry syscall_landlock_add_rule = {
	.name = "landlock_add_rule",
	.num_args = 4,
	.arg1name = "ruleset_fd",
	.arg1type = ARG_FD,
	.arg2name = "rule_type",
	.arg2type = ARG_LIST,
	.arg2list = ARGLIST(landlock_ruletypes),
	.arg3name = "rule_attr",
	.arg4name = "flags",
//	.arg4type = ARG_LIST,
//	.arg4list = ARGLIST(landlock_add_rule_flags),
};
