/*
 * SYSCALL_DEFINE3(membarrier, int, cmd, unsigned int, flags, int, cpu_id)
 */
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "random.h"
#include "sanitise.h"
#include "compat.h"

#ifndef MEMBARRIER_CMD_FLAG_CPU
#define MEMBARRIER_CMD_FLAG_CPU				(1 << 0)
#endif

#ifndef MEMBARRIER_CMD_QUERY
#define MEMBARRIER_CMD_QUERY				0
#define MEMBARRIER_CMD_GLOBAL				(1 << 0)
#define MEMBARRIER_CMD_GLOBAL_EXPEDITED			(1 << 1)
#define MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED	(1 << 2)
#define MEMBARRIER_CMD_PRIVATE_EXPEDITED		(1 << 3)
#define MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED	(1 << 4)
#define MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE	(1 << 5)
#define MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE (1 << 6)
#endif

#ifndef MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ
#define MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ		(1 << 7)
#define MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ	(1 << 8)
#endif

#ifndef MEMBARRIER_CMD_GET_REGISTRATIONS
#define MEMBARRIER_CMD_GET_REGISTRATIONS		(1 << 9)
#endif

static unsigned long membarrier_cmds[] = {
	MEMBARRIER_CMD_QUERY,
	MEMBARRIER_CMD_GLOBAL,
	MEMBARRIER_CMD_GLOBAL_EXPEDITED,
	MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED,
	MEMBARRIER_CMD_PRIVATE_EXPEDITED,
	MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED,
	MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE,
	MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE,
	MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ,
	MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ,
	MEMBARRIER_CMD_GET_REGISTRATIONS,
};

/*
 * Cache the kernel's MEMBARRIER_CMD_QUERY supported-cmd bitmask once
 * per child.  ARG_OP picks uniformly from membarrier_cmds[], but on
 * most kernels several of those cmds are unsupported and the syscall
 * rejects them before reaching any interesting arm.  Biasing toward
 * supported cmds reduces wasted iterations.
 */
static __thread int membarrier_initialised;
static __thread unsigned int membarrier_supported_mask;

static void init_membarrier_supported(void)
{
	long ret;

	if (membarrier_initialised)
		return;
	membarrier_initialised = 1;

	ret = syscall(__NR_membarrier, MEMBARRIER_CMD_QUERY, 0, 0);
	if (ret > 0)
		membarrier_supported_mask = (unsigned int) ret;
}

/* Pick one random set bit from mask and return its bit value. */
static unsigned long pick_supported_cmd(unsigned int mask)
{
	unsigned int bits[32];
	unsigned int n = 0;
	unsigned int i;

	for (i = 0; i < 32; i++) {
		if (mask & (1U << i))
			bits[n++] = i;
	}
	if (n == 0)
		return 0;
	return 1UL << bits[rnd_modulo_u32(n)];
}

static void sanitise_membarrier(struct syscallrecord *rec)
{
	unsigned int pick;

	init_membarrier_supported();

	pick = rnd_modulo_u32(100);

	if (pick < 70 && membarrier_supported_mask != 0) {
		/* ~70%: supported cmd, no flag. */
		rec->a1 = pick_supported_cmd(membarrier_supported_mask);
		rec->a2 = 0;
	} else if (pick < 85) {
		/* ~15%: leave ARG_OP cmd untouched. */
		rec->a2 = 0;
	} else if (pick < 95) {
		/* ~10%: explicitly-unsupported cmd -- reject path. */
		rec->a1 = 1UL << 20;
		rec->a2 = 0;
	} else if (pick < 99) {
		/*
		 * ~5% (minus the invalid-flag slot): supported cmd with
		 * MEMBARRIER_CMD_FLAG_CPU.  rec->a3 already holds an
		 * ARG_CPU pick from the argtype dispatch.
		 */
		if (membarrier_supported_mask != 0)
			rec->a1 = pick_supported_cmd(membarrier_supported_mask);
		rec->a2 = MEMBARRIER_CMD_FLAG_CPU;
	} else {
		/* ~1%: invalid flag bit -- reject path. */
		rec->a2 = 0x2;
	}
}

struct syscallentry syscall_membarrier = {
	.name = "membarrier",
	.num_args = 3,
	.argtype = { [0] = ARG_OP, [2] = ARG_CPU },
	.argname = { [0] = "cmd", [1] = "flags", [2] = "cpu_id" },
	.arg_params[0].list = ARGLIST(membarrier_cmds),
	.sanitise = sanitise_membarrier,
	.group = GROUP_SCHED,
	.rettype = RET_ZERO_SUCCESS,
	.flags = REEXEC_SANITISE_OK,
};
