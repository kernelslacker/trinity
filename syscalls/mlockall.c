/*
 * SYSCALL_DEFINE1(mlockall, int, flags)
 */

#define MCL_CURRENT     1
#define MCL_FUTURE      2

#include "trinity.h"
#include "sanitise.h"

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
};
