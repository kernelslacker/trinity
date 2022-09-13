/*
 * SYSCALL_DEFINE4(set_mempolicy_home_node, unsigned long, start, unsigned long, len, unsigned long, home_node, unsigned long, flags)
 */
#include "sanitise.h"

static void sanitise_set_mempolicy_home_node(struct syscallrecord *rec)
{
	rec->a4 = 0;	// no flags right now
}

struct syscallentry syscall_set_mempolicy_home_node = {
	.name = "set_mempolicy_home_node",
	.num_args = 4,
	.arg1name = "start",
	.arg2name = "len",
	.arg2type = ARG_LEN,
	.arg3name = "home_node",
	.arg4name = "flags",
	.sanitise = sanitise_set_mempolicy_home_node,
};
