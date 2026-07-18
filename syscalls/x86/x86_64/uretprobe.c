/*
 * SYSCALL_DEFINE0(uretprobe)
 *
 * Out-of-trampoline invocation returns -ENXIO with no side effects.
 */
#include "sanitise.h"

struct syscallentry syscall_uretprobe = {
	.name = "uretprobe",
	.num_args = 0,
	.group = GROUP_PROCESS,
};
