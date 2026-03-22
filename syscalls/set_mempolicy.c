/*
 * SYSCALL_DEFINE3(set_mempolicy, int, mode, unsigned long __user *, nmask, unsigned long, maxnode)
 */
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

struct syscallentry syscall_set_mempolicy = {
	.name = "set_mempolicy",
	.num_args = 3,
	.arg1name = "mode",
	.arg1type = ARG_OP,
	.arg1list = ARGLIST(mempolicy_modes),
	.arg2name = "nmask",
	.arg2type = ARG_ADDRESS,
	.arg3name = "maxnode",
	.arg3type = ARG_LEN,
	.group = GROUP_VM,
};
