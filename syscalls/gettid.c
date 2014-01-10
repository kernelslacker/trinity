/*
 * SYSCALL_DEFINE0(gettid)
 */
#include "sanitise.h"

struct syscallentry syscall_gettid = {
	.name = "gettid",
	.num_args = 0,
};
