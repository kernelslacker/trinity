/*
 * SYSCALL_DEFINE4(lsm_get_self_attr, unsigned int, attr,
 *		struct lsm_ctx __user *, ctx, u32 __user *, size, u32, flags)
 */
#include "sanitise.h"

#ifndef LSM_ATTR_CURRENT
#define LSM_ATTR_CURRENT	100
#define LSM_ATTR_EXEC		101
#define LSM_ATTR_FSCREATE	102
#define LSM_ATTR_KEYCREATE	103
#define LSM_ATTR_PREV		104
#define LSM_ATTR_SOCKCREATE	105
#endif

#ifndef LSM_FLAG_SINGLE
#define LSM_FLAG_SINGLE		0x0001
#endif

static unsigned long lsm_attrs[] = {
	LSM_ATTR_CURRENT, LSM_ATTR_EXEC, LSM_ATTR_FSCREATE,
	LSM_ATTR_KEYCREATE, LSM_ATTR_PREV, LSM_ATTR_SOCKCREATE,
};

static unsigned long lsm_get_flags[] = {
	LSM_FLAG_SINGLE,
};

struct syscallentry syscall_lsm_get_self_attr = {
	.name = "lsm_get_self_attr",
	.num_args = 4,
	.argtype = { [0] = ARG_OP, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_NON_NULL_ADDRESS, [3] = ARG_LIST },
	.argname = { [0] = "attr", [1] = "ctx", [2] = "size", [3] = "flags" },
	.arg_params[0].list = ARGLIST(lsm_attrs),
	.arg_params[3].list = ARGLIST(lsm_get_flags),
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_PROCESS,
};
