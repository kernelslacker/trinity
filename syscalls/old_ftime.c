/*
   
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_old_ftime = {
	.name = "ni_syscall (old ftime syscall)",
	.num_args = 0,
	.flags = NI_SYSCALL,
};
