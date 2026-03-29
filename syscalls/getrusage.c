/*
 * SYSCALL_DEFINE2(getrusage, int, who, struct rusage __user *, ru)
 */
#include <sys/resource.h>
#include "sanitise.h"

static unsigned long getrusage_who[] = {
	RUSAGE_SELF, RUSAGE_CHILDREN, RUSAGE_THREAD,
};

struct syscallentry syscall_getrusage = {
	.name = "getrusage",
	.num_args = 2,
	.argtype = { [0] = ARG_OP, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "who", [1] = "ru" },
	.arg1list = ARGLIST(getrusage_who),
	.group = GROUP_PROCESS,
};
