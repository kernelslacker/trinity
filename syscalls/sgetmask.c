/*
 * SYSCALL_DEFINE0(sgetmask)
 */
#include "sanitise.h"

struct syscallentry syscall_sgetmask = {
	.name = "sgetmask",
	.num_args = 0,
};
