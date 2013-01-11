/*
 * SYSCALL_DEFINE2(getrlimit, unsigned int, resource, struct rlimit __user *, rlim)
 */
#include "trinity.h"
#include "sanitise.h"
#include "shm.h"

#include <stdlib.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "compat.h"

static void sanitise_getrlimit(int childno)
{
	if (rand() % 2 == 0)
		return;

	/* set "resource" some random value half the time. */
	shm->a1[childno] = get_interesting_32bit_value();
}

struct syscall syscall_getrlimit = {
	.name = "getrlimit",
	.num_args = 2,
	.sanitise = sanitise_getrlimit,
	.arg1name = "resource",
	.arg1type = ARG_OP,
	.arg1list = {
		.num = 16,
		.values = {
			RLIMIT_AS,
			RLIMIT_CORE,
			RLIMIT_CPU,
			RLIMIT_DATA,
			RLIMIT_FSIZE,
			RLIMIT_LOCKS,
			RLIMIT_MEMLOCK,
			RLIMIT_MSGQUEUE,
			RLIMIT_NICE,
			RLIMIT_NOFILE,
			RLIMIT_NPROC,
			RLIMIT_RSS,
			RLIMIT_RTPRIO,
			RLIMIT_RTTIME,
			RLIMIT_SIGPENDING,
			RLIMIT_STACK,
		},
	},
	.arg2name = "rlim",
	.arg2type = ARG_ADDRESS,
};
