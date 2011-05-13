/*
   
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_old_idle = {
	.name = "ni_syscall (old idle syscall)",
	.num_args = 0,
	.flags = NI_SYSCALL,
};
