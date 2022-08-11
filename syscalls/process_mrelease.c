/*
 * SYSCALL_DEFINE2(process_mrelease, int, pidfd, unsigned int, flags)
 */
#include "sanitise.h"

static unsigned long process_mrelease_flags[] = {
	0,	// currently no flags defined, mbz
};

struct syscallentry syscall_process_mrelease = {
	.name = "process_mrelease",
	.num_args = 2,
	.arg1name = "pidfd",
	.arg2name = "flags",
	.arg2type = ARG_LIST,
	.arg2list = ARGLIST(process_mrelease_flags),
};
