/*
   
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_old_mpx = {
	.name = "ni_syscall (old mpx syscall)",
	.num_args = 0,
	.flags = NI_SYSCALL,
};
