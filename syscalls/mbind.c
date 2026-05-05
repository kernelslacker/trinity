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
#include "trinity.h"

#define MPOL_F_STATIC_NODES     (1 << 15)
#define MPOL_F_RELATIVE_NODES   (1 << 14)

#ifndef MPOL_PREFERRED_MANY
#define MPOL_PREFERRED_MANY	5	/* 5.15+ */
#endif
#ifndef MPOL_WEIGHTED_INTERLEAVE
#define MPOL_WEIGHTED_INTERLEAVE 6	/* 6.9+ */
#endif

#ifndef MPOL_MF_LAZY
#define MPOL_MF_LAZY (1 << 3)	/* lazy migrate-on-fault */
#endif

static void sanitise_mbind(struct syscallrecord *rec)
{
	unsigned long *mask;
	unsigned long maxnode;

	(void) common_set_mmap_ptr_len();

	if (range_overlaps_shared(rec->a1, rec->a2)) {
		rec->a1 = 0;
		rec->a2 = 0;
	}

retry_maxnode:
	rec->a5 &= ~((page_size * 8) - 1);

	maxnode = rec->a5;

	if (maxnode < 2 || maxnode > (page_size * 8)) {
		rec->a5 = rand32();
		goto retry_maxnode;
	}

	/* Generate a valid nodemask bitmap instead of a random address. */
	mask = (unsigned long *) get_writable_address(sizeof(unsigned long) * 2);
	mask[0] = 0;
	mask[1] = 0;
	switch (rand() % 3) {
	case 0: /* node 0 only (most common on non-NUMA) */
		mask[0] = 1;
		break;
	case 1: /* first few nodes */
		mask[0] = (1UL << (1 + (rand() % 4))) - 1;
		break;
	default: /* random bits */
		mask[0] = rand32();
		break;
	}
	rec->a4 = (unsigned long) mask;
}

static unsigned long mbind_modes[] = {
	MPOL_DEFAULT, MPOL_BIND, MPOL_INTERLEAVE, MPOL_PREFERRED,
	MPOL_LOCAL, MPOL_PREFERRED_MANY, MPOL_WEIGHTED_INTERLEAVE,
};

static unsigned long mbind_flags[] = {
	MPOL_MF_STRICT, MPOL_MF_MOVE, MPOL_MF_MOVE_ALL, MPOL_MF_LAZY,
	MPOL_F_STATIC_NODES, MPOL_F_RELATIVE_NODES,
};

struct syscallentry syscall_mbind = {
	.name = "mbind",
	.num_args = 6,
	.argtype = { [0] = ARG_MMAP, [1] = ARG_LEN, [2] = ARG_LIST, [3] = ARG_ADDRESS, [4] = ARG_RANGE, [5] = ARG_LIST },
	.argname = { [0] = "start", [1] = "len", [2] = "mode", [3] = "nmask", [4] = "maxnode", [5] = "flags" },


	.arg_params[2].list = ARGLIST(mbind_modes),


	.arg_params[4].range.low = 0,
	.arg_params[4].range.hi = 32,

	.arg_params[5].list = ARGLIST(mbind_flags),

	.sanitise = sanitise_mbind,
	.group = GROUP_VM,
};
