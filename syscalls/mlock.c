/*
 * SYSCALL_DEFINE2(mlock, unsigned long, start, size_t, len)
 */
#include <stdlib.h>
#include "trinity.h"
#include "sanitise.h"

#define MCL_CURRENT	1
#define MCL_FUTURE	2

static void sanitise_mlock(unsigned long *flags,
		__unused__ unsigned long *a2,
		__unused__ unsigned long *a3,
		__unused__ unsigned long *a4,
		__unused__ unsigned long *a5,
		__unused__ unsigned long *a6)
{
	if (*flags != 0)
		return;

	if ((rand() % 2) == 0)
		*flags = MCL_CURRENT;
	else
		*flags = MCL_FUTURE;
}

struct syscall syscall_mlock = {
	.name = "mlock",
	.num_args = 2,
	.arg1name = "addr",
	.arg1type = ARG_ADDRESS,
	.arg2name = "len",
	.arg2type = ARG_LEN,
	.group = GROUP_VM,
	.sanitise = sanitise_mlock,
};
