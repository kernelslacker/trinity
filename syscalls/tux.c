/*
   
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_tux = {
	.name = "ni_syscall (tux)",
	.num_args = 6,
	.flags = NI_SYSCALL,
};
