/*
 * SYSCALL_DEFINE0(geteuid)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_geteuid = {
	.name = "geteuid",
	.num_args = 0,
};
