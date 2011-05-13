/*
 * SYSCALL_DEFINE1(dup, unsigned int, fildes)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_dup = {
	.name = "dup",
	.num_args = 1,
	.arg1name = "fildes",
	.arg1type = ARG_FD,
};
