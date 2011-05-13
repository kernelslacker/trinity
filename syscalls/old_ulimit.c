/*
   
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_old_ulimit = {
	.name = "ni_syscall (old ulimit syscall)",
	.num_args = 0,
	.flags = NI_SYSCALL,
};
