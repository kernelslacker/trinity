/*
   
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_get_kernel_syms = {
	.name = "ni_syscall (get_kernel_syms)",
	.num_args = 0,
	.flags = NI_SYSCALL,
};
