/*
   
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_query_module = {
	.name = "ni_syscall (query_module)",
	.num_args = 0,
	.flags = NI_SYSCALL,
};
