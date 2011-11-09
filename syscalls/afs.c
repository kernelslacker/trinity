/*
 * 
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_afs = {
	.name = "ni_syscall (afs)",
	.num_args = 6,
	.flags = NI_SYSCALL,
};
