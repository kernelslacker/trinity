/*
 * SYSCALL_DEFINE0(uprobe)
 *
 * Out-of-trampoline invocation returns -ENXIO with no side effects.
 */
#include "sanitise.h"

struct syscallentry syscall_uprobe = {
	.name = "uprobe",
	.num_args = 0,
	.group = GROUP_PROCESS,
};
