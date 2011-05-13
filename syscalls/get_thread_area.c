/*
   
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_get_thread_area = {
	.name = "ni_syscall (get_thread_area)",
	.num_args = 0,
	.flags = NI_SYSCALL,
};
