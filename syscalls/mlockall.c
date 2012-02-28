/*
 * SYSCALL_DEFINE1(mlockall, int, flags)
 */

#define MCL_CURRENT     1
#define MCL_FUTURE      2

#include <stdlib.h>
#include "trinity.h"
#include "sanitise.h"

static void sanitise_mlockall(unsigned long *flags,
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


struct syscall syscall_mlockall = {
	.name = "mlockall",
	.num_args = 1,
	.arg1name = "flags",
	.arg1type = ARG_LIST,
	.arg1list = {
		.num = 2,
		.values = { MCL_CURRENT, MCL_FUTURE },
	},
	.group = GROUP_VM,
	.sanitise = sanitise_mlockall,
};
