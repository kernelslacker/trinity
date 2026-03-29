/*
 * SYSCALL_DEFINE3(map_shadow_stack, unsigned long, addr, unsigned long, size, unsigned int, flags)
 */
#include "sanitise.h"

#ifndef SHADOW_STACK_SET_TOKEN
#define SHADOW_STACK_SET_TOKEN	0x1
#endif

static unsigned long map_shadow_stack_flags[] = {
	SHADOW_STACK_SET_TOKEN,
};

struct syscallentry syscall_map_shadow_stack = {
	.name = "map_shadow_stack",
	.num_args = 3,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_LEN, [2] = ARG_LIST },
	.argname = { [0] = "addr", [1] = "size", [2] = "flags" },
	.arg3list = ARGLIST(map_shadow_stack_flags),
	.group = GROUP_VM,
};
