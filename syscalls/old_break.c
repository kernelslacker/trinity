/*
   
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_old_break = {
	.name = "ni_syscall (old break syscall)",
	.num_args = 0,
	.flags = NI_SYSCALL,
};
