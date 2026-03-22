/*
 * SYSCALL_DEFINE2(setrlimit, unsigned int, resource, struct rlimit __user *, rlim)
 */
#include <sys/resource.h>
#include "sanitise.h"

static unsigned long rlimit_resources[] = {
	RLIMIT_CPU, RLIMIT_FSIZE, RLIMIT_DATA, RLIMIT_STACK,
	RLIMIT_CORE, RLIMIT_RSS, RLIMIT_NPROC, RLIMIT_NOFILE,
	RLIMIT_MEMLOCK, RLIMIT_AS, RLIMIT_LOCKS, RLIMIT_SIGPENDING,
	RLIMIT_MSGQUEUE, RLIMIT_NICE, RLIMIT_RTPRIO,
};

struct syscallentry syscall_setrlimit = {
	.name = "setrlimit",
	.num_args = 2,
	.arg1name = "resource",
	.arg1type = ARG_OP,
	.arg1list = ARGLIST(rlimit_resources),
	.arg2name = "rlim",
	.arg2type = ARG_ADDRESS,
	.group = GROUP_PROCESS,
};
