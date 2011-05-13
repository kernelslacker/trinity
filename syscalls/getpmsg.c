/*
   
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_getpmsg = {
	.name = "ni_syscall (getpmsg)",
	.num_args = 0,
	.flags = NI_SYSCALL,
};
