/*
 * SYSCALL_DEFINE2(mlock, unsigned long, start, size_t, len)
 */
#include <stdlib.h>
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_mlock = {
	.name = "mlock",
	.num_args = 2,
	.arg1name = "addr",
	.arg1type = ARG_ADDRESS,
	.arg2name = "len",
	.arg2type = ARG_LEN,
	.group = GROUP_VM,
};
