/*
 * SYSCALL_DEFINE3(map_shadow_stack, unsigned long, addr, unsigned long, size, unsigned int, flags)
 */
#include <sys/mman.h>
#include "sanitise.h"

#ifndef SHADOW_STACK_SET_TOKEN
#define SHADOW_STACK_SET_TOKEN	0x1
#endif

#ifndef SHADOW_STACK_SET_MARKER
#define SHADOW_STACK_SET_MARKER	0x2
#endif

static unsigned long map_shadow_stack_flags[] = {
	SHADOW_STACK_SET_TOKEN,
	SHADOW_STACK_SET_MARKER,
};

static void sanitise_map_shadow_stack(struct syscallrecord *rec)
{
	/* Pass addr=0 to let the kernel choose the location. */
	rec->a1 = 0;
}

static void post_map_shadow_stack(struct syscallrecord *rec)
{
	void *p = (void *)rec->retval;

	if (p == MAP_FAILED)
		return;

	munmap(p, rec->a2);
}

struct syscallentry syscall_map_shadow_stack = {
	.name = "map_shadow_stack",
	.num_args = 3,
	.argtype = { [1] = ARG_LEN, [2] = ARG_LIST },
	.argname = { [0] = "addr", [1] = "size", [2] = "flags" },
	.arg_params[2].list = ARGLIST(map_shadow_stack_flags),
	.sanitise = sanitise_map_shadow_stack,
	.post = post_map_shadow_stack,
	.group = GROUP_VM,
	.rettype = RET_ADDRESS,
};
