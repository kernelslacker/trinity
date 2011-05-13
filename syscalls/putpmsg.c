/*
   
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_putpmsg = {
	.name = "ni_syscall (putpmsg)",
	.num_args = 0,
	.flags = NI_SYSCALL,
};
