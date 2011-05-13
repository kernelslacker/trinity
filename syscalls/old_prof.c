/*
   
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_old_prof = {
	.name = "ni_syscall (old prof syscall)",
	.num_args = 0,
	.flags = NI_SYSCALL,
};
