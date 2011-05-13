/*
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_create_module = {
	.name = "ni_syscall (create_module)",
	.num_args = 0,
	.flags = NI_SYSCALL,
};
