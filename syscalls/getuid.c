/*
 * SYSCALL_DEFINE0(getuid)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_getuid = {
	.name = "getuid",
	.num_args = 0,
};
