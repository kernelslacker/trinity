/*
 * SYSCALL_DEFINE3(set_mempolicy, int, mode, unsigned long __user *, nmask, unsigned long, maxnode)
 */
#include "kernel/mempolicy.h"
#include "nodemask.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"

static unsigned long mempolicy_modes[] = {
	MPOL_DEFAULT, MPOL_PREFERRED, MPOL_BIND,
	MPOL_INTERLEAVE, MPOL_LOCAL, MPOL_PREFERRED_MANY,
	MPOL_WEIGHTED_INTERLEAVE,
};

static void sanitise_set_mempolicy(struct syscallrecord *rec)
{
	/* maxnode is the bit count the kernel uses to size its
	 * copy_from_user(ceil(maxnode/8)) of the nodemask.  Cap at
	 * NODEMASK_POOL_BITS so the copy stays inside the ARG_NODEMASK
	 * pool buffer the foundation generator hands to a2. */
	rec->a3 = 1 + rnd_modulo_u32(NODEMASK_POOL_BITS);

	/* Mode flags live in the high bits of the mode arg.  OR in
	 * MPOL_F_NUMA_BALANCING occasionally; only valid with MPOL_BIND
	 * but the kernel rejects it cleanly elsewhere, which is also
	 * worth exercising. */
	if (ONE_IN(8))
		rec->a1 |= MPOL_F_NUMA_BALANCING;

	/* MPOL_F_STATIC_NODES and MPOL_F_RELATIVE_NODES are mutually
	 * exclusive nodemask-interpretation flags; OR one in occasionally
	 * to exercise both the accepted and EINVAL paths. */
	if (ONE_IN(8))
		rec->a1 |= MPOL_F_STATIC_NODES;
	if (ONE_IN(8))
		rec->a1 |= MPOL_F_RELATIVE_NODES;
}

struct syscallentry syscall_set_mempolicy = {
	.name = "set_mempolicy",
	.num_args = 3,
	.argtype = { [0] = ARG_OP, [1] = ARG_NODEMASK, [2] = ARG_LEN },
	.argname = { [0] = "mode", [1] = "nmask", [2] = "maxnode" },
	.arg_params[0].list = ARGLIST(mempolicy_modes),
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VM,
	.sanitise = sanitise_set_mempolicy,
};
