/*
 * SYSCALL_DEFINE0(getuid)
 */
#include "sanitise.h"

struct syscallentry syscall_getuid = {
	.name = "getuid",
	.num_args = 0,
};


/*
 * SYSCALL_DEFINE0(getuid16)
 */

struct syscallentry syscall_getuid16 = {
	.name = "getuid16",
	.num_args = 0,
};
