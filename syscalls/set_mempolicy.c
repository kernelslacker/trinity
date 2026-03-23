/*
 * SYSCALL_DEFINE3(set_mempolicy, int, mode, unsigned long __user *, nmask, unsigned long, maxnode)
 */
#include "random.h"
#include "sanitise.h"
#include "compat.h"

#ifndef MPOL_DEFAULT
#define MPOL_DEFAULT	0
#define MPOL_PREFERRED	1
#define MPOL_BIND	2
#define MPOL_INTERLEAVE	3
#define MPOL_LOCAL	4
#define MPOL_PREFERRED_MANY 5
#define MPOL_WEIGHTED_INTERLEAVE 6
#endif

static unsigned long mempolicy_modes[] = {
	MPOL_DEFAULT, MPOL_PREFERRED, MPOL_BIND,
	MPOL_INTERLEAVE, MPOL_LOCAL, MPOL_PREFERRED_MANY,
	MPOL_WEIGHTED_INTERLEAVE,
};

#define MAX_NUMNODES 64

static void sanitise_set_mempolicy(struct syscallrecord *rec)
{
	unsigned long *mask;
	unsigned int maxnode;

	/* Nodemask is a bitmap, one bit per NUMA node. */
	maxnode = 1 + (rand() % MAX_NUMNODES);
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

	rec->a2 = (unsigned long) mask;
	rec->a3 = maxnode;
}

struct syscallentry syscall_set_mempolicy = {
	.name = "set_mempolicy",
	.num_args = 3,
	.arg1name = "mode",
	.arg1type = ARG_OP,
	.arg1list = ARGLIST(mempolicy_modes),
	.arg2name = "nmask",
	.arg3name = "maxnode",
	.group = GROUP_VM,
	.sanitise = sanitise_set_mempolicy,
};
