/*
 * SYSCALL_DEFINE2(getrusage, int, who, struct rusage __user *, ru)
 */
#include <sys/resource.h>
#include "sanitise.h"

static unsigned long getrusage_who[] = {
	RUSAGE_SELF, RUSAGE_CHILDREN, RUSAGE_THREAD,
};

static void sanitise_getrusage(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a2, sizeof(struct rusage));
}

struct syscallentry syscall_getrusage = {
	.name = "getrusage",
	.num_args = 2,
	.argtype = { [0] = ARG_OP, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "who", [1] = "ru" },
	.arg_params[0].list = ARGLIST(getrusage_who),
	.sanitise = sanitise_getrusage,
	.group = GROUP_PROCESS,
	.rettype = RET_ZERO_SUCCESS,
};
