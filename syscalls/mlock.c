/*
 * SYSCALL_DEFINE2(mlock, unsigned long, start, size_t, len)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_mlock = {
	.name = "mlock",
	.num_args = 2,
	.arg1name = "start",
	.arg2name = "len",
	.arg2type = ARG_LEN,
	.group = GROUP_VM,
};
