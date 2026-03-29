/*
 * SYSCALL_DEFINE2(membarrier, int, cmd, int, flags)
 */
#include <stdlib.h>
#include "random.h"
#include "sanitise.h"
#include "compat.h"

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
};

static void sanitise_membarrier(struct syscallrecord *rec)
{
	rec->a2 = 0;	/* flags must be zero */
}

struct syscallentry syscall_membarrier = {
	.name = "membarrier",
	.num_args = 2,
	.argtype = { [0] = ARG_OP },
	.argname = { [0] = "cmd", [1] = "flags" },
	.arg_params[0].list = ARGLIST(membarrier_cmds),
	.sanitise = sanitise_membarrier,
	.group = GROUP_SCHED,
};
