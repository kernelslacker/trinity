/*
 * SYSCALL_DEFINE1(mlockall, int, flags)
 */
#include <stdlib.h>
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "trinity.h"

#define MCL_CURRENT     1
#define MCL_FUTURE      2

static void sanitise_mlockall(struct syscallrecord *rec)
{
	if (rec->a1 != 0)
		return;

	if (RAND_BOOL())
		rec->a1 = MCL_CURRENT;
	else
		rec->a1 = MCL_FUTURE;
}


struct syscallentry syscall_mlockall = {
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
