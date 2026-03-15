/*
 * SYSCALL_DEFINE4(lsm_set_self_attr, unsigned int, attr,
 *		struct lsm_ctx __user *, ctx, u32, size, u32, flags)
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

static unsigned long lsm_attrs[] = {
	LSM_ATTR_CURRENT, LSM_ATTR_EXEC, LSM_ATTR_FSCREATE,
	LSM_ATTR_KEYCREATE, LSM_ATTR_PREV, LSM_ATTR_SOCKCREATE,
};

static void sanitise_lsm_set_self_attr(struct syscallrecord *rec)
{
	rec->a4 = 0;	/* flags must be zero */
}

struct syscallentry syscall_lsm_set_self_attr = {
	.name = "lsm_set_self_attr",
	.num_args = 4,
	.arg1name = "attr",
	.arg1type = ARG_OP,
	.arg1list = ARGLIST(lsm_attrs),
	.arg2name = "ctx",
	.arg2type = ARG_ADDRESS,
	.arg3name = "size",
	.arg3type = ARG_LEN,
	.arg4name = "flags",
	.rettype = RET_ZERO_SUCCESS,
	.sanitise = sanitise_lsm_set_self_attr,
};
