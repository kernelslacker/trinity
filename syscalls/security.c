/*
   
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_security = {
	.name = "ni_syscall (security)",
	.num_args = 0,
	.flags = NI_SYSCALL,
};
