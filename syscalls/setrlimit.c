/*
 * SYSCALL_DEFINE2(setrlimit, unsigned int, resource, struct rlimit __user *, rlim)
 */
#include <sys/resource.h>
#include "arch.h"
#include "random.h"
#include "sanitise.h"

static unsigned long rlimit_resources[] = {
	RLIMIT_CPU, RLIMIT_FSIZE, RLIMIT_DATA, RLIMIT_STACK,
	RLIMIT_CORE, RLIMIT_RSS, RLIMIT_NPROC, RLIMIT_NOFILE,
	RLIMIT_MEMLOCK, RLIMIT_AS, RLIMIT_LOCKS, RLIMIT_SIGPENDING,
	RLIMIT_MSGQUEUE, RLIMIT_NICE, RLIMIT_RTPRIO,
};

static rlim_t random_rlim(void)
{
	switch (rand() % 5) {
	case 0: return RLIM_INFINITY;
	case 1: return 0;
	case 2: return 1 + (rand() % 1024);
	case 3: return (rlim_t) page_size * (1 + (rand() % 256));
	default: return rand32();
	}
}

/* Fill struct rlimit with interesting boundary values. */
static void sanitise_setrlimit(struct syscallrecord *rec)
{
	struct rlimit *rlim;

	rlim = (struct rlimit *) get_writable_address(sizeof(*rlim));
	rlim->rlim_cur = random_rlim();
	rlim->rlim_max = random_rlim();

	/* Half the time, enforce cur <= max for valid calls. */
	if (RAND_BOOL() && rlim->rlim_cur > rlim->rlim_max)
		rlim->rlim_cur = rlim->rlim_max;

	rec->a2 = (unsigned long) rlim;
}

struct syscallentry syscall_setrlimit = {
	.name = "setrlimit",
	.num_args = 2,
	.argtype = { [0] = ARG_OP },
	.argname = { [0] = "resource", [1] = "rlim" },
	.arg_params[0].list = ARGLIST(rlimit_resources),
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_PROCESS,
	.sanitise = sanitise_setrlimit,
};
