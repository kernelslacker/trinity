/*
 * SYSCALL_DEFINE2(process_mrelease, int, pidfd, unsigned int, flags)
 */
#include "sanitise.h"

static unsigned long process_mrelease_flags[] = {
	0,	// currently no flags defined, mbz
};

struct syscallentry syscall_process_mrelease = {
	.name = "process_mrelease",
	.group = GROUP_PROCESS,
	.num_args = 2,
	.argtype = { [0] = ARG_FD_PIDFD, [1] = ARG_LIST },
	.argname = { [0] = "pidfd", [1] = "flags" },
	.arg_params[1].list = ARGLIST(process_mrelease_flags),
};
