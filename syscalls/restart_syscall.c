/*
 * SYSCALL_DEFINE0(restart_syscall)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_restart_syscall = {
	.name = "restart_syscall",
	.num_args = 0,
};
