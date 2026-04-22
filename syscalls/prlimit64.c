/*
 * SYSCALL_DEFINE4(prlimit64, pid_t, pid, unsigned int, resource,
	 const struct rlimit64 __user *, new_rlim,
	 struct rlimit64 __user *, old_rlim)
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

static rlim64_t random_rlim64(void)
{
	switch (rand() % 5) {
	case 0: return RLIM64_INFINITY;
	case 1: return 0;
	case 2: return 1 + (rand() % 1024);
	case 3: return (rlim64_t) page_size * (1 + (rand() % 256));
	default: return rand32();
	}
}

/* Fill struct rlimit64 with interesting boundary values. */
static void sanitise_prlimit64(struct syscallrecord *rec)
{
	struct rlimit64 *rlim;

	rlim = (struct rlimit64 *) get_writable_address(sizeof(*rlim));
	rlim->rlim_cur = random_rlim64();
	rlim->rlim_max = random_rlim64();

	/* Half the time, enforce cur <= max for valid calls. */
	if (RAND_BOOL() && rlim->rlim_cur > rlim->rlim_max)
		rlim->rlim_cur = rlim->rlim_max;

	rec->a3 = (unsigned long) rlim;

	/*
	 * old_rlim (a4) is the kernel's writeback target for the previous
	 * limit values: ARG_ADDRESS draws from the random pool, so a fuzzed
	 * pointer can land inside an alloc_shared region.  Scrub it.
	 */
	avoid_shared_buffer(&rec->a4, sizeof(struct rlimit64));
}

struct syscallentry syscall_prlimit64 = {
	.name = "prlimit64",
	.num_args = 4,
	.argtype = { [0] = ARG_PID, [1] = ARG_OP, [3] = ARG_ADDRESS },
	.argname = { [0] = "pid", [1] = "resource", [2] = "new_rlim", [3] = "old_rlim" },
	.arg_params[1].list = ARGLIST(rlimit_resources),
	.group = GROUP_PROCESS,
	.sanitise = sanitise_prlimit64,
};
