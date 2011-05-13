/*
   
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_set_zone_reclaim = {
	.name = "ni_syscall (was briefly sys_set_zone_reclaim)",
	.num_args = 0,
	.flags = NI_SYSCALL,
};
