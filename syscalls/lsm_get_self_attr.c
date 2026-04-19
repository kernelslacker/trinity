/*
 * SYSCALL_DEFINE4(lsm_get_self_attr, unsigned int, attr,
 *		struct lsm_ctx __user *, ctx, u32 __user *, size, u32, flags)
 */
#include "arch.h"
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

static void sanitise_lsm_get_self_attr(struct syscallrecord *rec)
{
	u32 *size;
	void *buf;

	/*
	 * The kernel reads *size to find how much space the caller provided.
	 * A zero value causes an immediate E2BIG before any attribute retrieval
	 * happens. Provide a page-sized buffer and tell the kernel about it.
	 */
	buf = get_writable_address(page_size);
	size = (u32 *) get_writable_address(sizeof(*size));
	if (!buf || !size)
		return;
	*size = page_size;
	rec->a2 = (unsigned long) buf;
	rec->a3 = (unsigned long) size;
}

struct syscallentry syscall_lsm_get_self_attr = {
	.name = "lsm_get_self_attr",
	.num_args = 4,
	.argtype = { [0] = ARG_OP, [3] = ARG_LIST },
	.argname = { [0] = "attr", [1] = "ctx", [2] = "size", [3] = "flags" },
	.arg_params[0].list = ARGLIST(lsm_attrs),
	.arg_params[3].list = ARGLIST(lsm_get_flags),
	.rettype = RET_ZERO_SUCCESS,
	.sanitise = sanitise_lsm_get_self_attr,
	.group = GROUP_PROCESS,
};
