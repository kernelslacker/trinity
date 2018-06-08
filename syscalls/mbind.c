/*
 * SYSCALL_DEFINE6(mbind, unsigned long, start, unsigned long, len,
	unsigned long, mode, unsigned long __user *, nmask,
	unsigned long, maxnode, unsigned, flags)
 */

#include <linux/mempolicy.h>
#include "arch.h"
#include "maps.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "trinity.h"

#define MPOL_F_STATIC_NODES     (1 << 15)
#define MPOL_F_RELATIVE_NODES   (1 << 14)

static void sanitise_mbind(struct syscallrecord *rec)
{
	unsigned long maxnode;

	(void) common_set_mmap_ptr_len();

retry_maxnode:
	rec->a5 &= ~((page_size * 8) - 1);

	maxnode = rec->a5;

	if (maxnode < 2 || maxnode > (page_size * 8)) {
		rec->a5 = rand32();
		goto retry_maxnode;
	}
}

static unsigned long mbind_modes[] = {
	MPOL_DEFAULT, MPOL_BIND, MPOL_INTERLEAVE, MPOL_PREFERRED,
	MPOL_F_STATIC_NODES, MPOL_F_RELATIVE_NODES,
};

static unsigned long mbind_flags[] = {
	MPOL_MF_STRICT, MPOL_MF_MOVE, MPOL_MF_MOVE_ALL,
};

struct syscallentry syscall_mbind = {
	.name = "mbind",
	.num_args = 6,
	.arg1name = "start",
	.arg1type = ARG_MMAP,

	.arg2name = "len",

	.arg3name = "mode",
	.arg3type = ARG_LIST,
	.arg3list = ARGLIST(mbind_modes),

	.arg4name = "nmask",
	.arg4type = ARG_ADDRESS,

	.arg5name = "maxnode",
	.arg5type = ARG_RANGE,
	.low5range = 0,
	.hi5range = 32,

	.arg6name = "flags",
	.arg6type = ARG_LIST,
	.arg6list = ARGLIST(mbind_flags),

	.sanitise = sanitise_mbind,
	.group = GROUP_VM,
};
