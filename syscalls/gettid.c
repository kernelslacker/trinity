/*
 * SYSCALL_DEFINE0(gettid)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_gettid = {
	.name = "gettid",
	.num_args = 0,
};
