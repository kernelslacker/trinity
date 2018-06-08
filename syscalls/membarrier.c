/*
 * SYSCALL_DEFINE2(membarrier, int, cmd, int, flags)
 */
#include <stdlib.h>
#include "random.h"
#include "sanitise.h"

static void sanitise_membarrier(struct syscallrecord *rec)
{
	// for now, there are no flags, but for future
	// proofing, we'll leak something random occasionally.
	// 0 the rest of the time, or we just EINVAL
	if (ONE_IN(1000))
		rec->a2 = 1 << (rnd() % 4);
	else
		rec->a2 = 0;
}

enum membarrier_cmd {
	MEMBARRIER_CMD_QUERY = 0,
	MEMBARRIER_CMD_SHARED = (1 << 0),
};

static unsigned long membarrier_cmds[] = {
	MEMBARRIER_CMD_QUERY, MEMBARRIER_CMD_SHARED,
};

struct syscallentry syscall_membarrier = {
	.name = "membarrier",
	.num_args = 2,
	.arg1type = ARG_OP,
	.arg1name = "cmd",
	.arg1list = ARGLIST(membarrier_cmds),
	.arg2name = "flags",
	.sanitise = sanitise_membarrier,
};
