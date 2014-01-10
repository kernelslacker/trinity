/*
 * SYSCALL_DEFINE0(getuid)
 */
#include "sanitise.h"

struct syscallentry syscall_getuid = {
	.name = "getuid",
	.num_args = 0,
};
