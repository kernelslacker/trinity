/*
 * SYSCALL_DEFINE2(getrlimit, unsigned int, resource, struct rlimit __user *, rlim)
 */
#include <stdlib.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "sanitise.h"
#include "shm.h"
#include "compat.h"

static unsigned long getrlimit_resources[] = {
	RLIMIT_AS, RLIMIT_CORE, RLIMIT_CPU, RLIMIT_DATA,
	RLIMIT_FSIZE, RLIMIT_LOCKS, RLIMIT_MEMLOCK, RLIMIT_MSGQUEUE,
	RLIMIT_NICE, RLIMIT_NOFILE, RLIMIT_NPROC, RLIMIT_RSS,
	RLIMIT_RTPRIO, RLIMIT_RTTIME, RLIMIT_SIGPENDING, RLIMIT_STACK,
};

static void sanitise_getrlimit(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a2, sizeof(struct rlimit));
}

struct syscallentry syscall_getrlimit = {
	.name = "getrlimit",
	.num_args = 2,
	.argtype = { [0] = ARG_OP, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "resource", [1] = "rlim" },
	.arg_params[0].list = ARGLIST(getrlimit_resources),
	.sanitise = sanitise_getrlimit,
	.group = GROUP_PROCESS,
	.rettype = RET_ZERO_SUCCESS,
};
