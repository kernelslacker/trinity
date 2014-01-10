/*
 * SYSCALL_DEFINE0(getuid16)
 */
#include "sanitise.h"

struct syscallentry syscall_getuid16 = {
	.name = "getuid16",
	.num_args = 0,
};
