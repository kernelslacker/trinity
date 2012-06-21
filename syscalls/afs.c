/*
 * 
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_afs = {
	.name = "ni_syscall (afs)",
	.num_args = 0,
	.flags = NI_SYSCALL,
};
