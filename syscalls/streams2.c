/*
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_streams2 = {
	.name = "ni_syscall (streams2)",
	.num_args = 6,
	.flags = NI_SYSCALL,
};
