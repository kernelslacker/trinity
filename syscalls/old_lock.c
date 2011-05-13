/*
   
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_old_lock = {
	.name = "ni_syscall (old lock syscall)",
	.num_args = 0,
	.flags = NI_SYSCALL,
};
