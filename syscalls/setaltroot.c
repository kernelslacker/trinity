/*
   
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_setaltroot = {
	.name = "ni_syscall (setaltroot)",
	.num_args = 0,
	.flags = NI_SYSCALL,
};
