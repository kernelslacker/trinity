/*
   
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_set_thread_area = {
	.name = "ni_syscall (set_thread_area)",
	.num_args = 0,
	.flags = NI_SYSCALL,
};
