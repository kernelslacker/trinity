/*
   
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_stty = {
	.name = "ni_syscall (old stty syscall)",
	.num_args = 0,
	.flags = NI_SYSCALL,
};
