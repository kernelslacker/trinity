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
	.arg1name = "who",
	.arg1type = ARG_OP,
	.arg1list = ARGLIST(getrusage_who),
	.arg2name = "ru",
	.arg2type = ARG_ADDRESS,
};
