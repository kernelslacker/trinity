/*
   
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_gtty = {
	.name = "ni_syscall (old gtty syscall)",
	.num_args = 0,
	.flags = NI_SYSCALL,
};
