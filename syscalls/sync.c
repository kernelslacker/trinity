/*
 * SYSCALL_DEFINE0(sync)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_sync = {
	.name = "sync",
	.num_args = 0,
};
