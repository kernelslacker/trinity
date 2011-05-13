/*
   
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_vserver = {
	.name = "ni_syscall (vserver)",
	.num_args = 0,
	.flags = NI_SYSCALL,
};
