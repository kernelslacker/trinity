/*
 * SYSCALL_DEFINE3(lsm_list_modules, u64 __user *, ids, u32 __user *, size,
 *		u32, flags)
 */
#include "arch.h"
#include "sanitise.h"

static void sanitise_lsm_list_modules(struct syscallrecord *rec)
{
	u32 *size;
	void *buf;

	/*
	 * The kernel reads *size to find how much space is available for the
	 * u64 LSM ID array. A zero causes immediate E2BIG. Provide a
	 * page-sized buffer and initialize the size accordingly.
	 */
	buf = get_writable_address(page_size);
	size = (u32 *) get_writable_address(sizeof(*size));
	if (!buf || !size)
		return;
	*size = page_size;
	rec->a1 = (unsigned long) buf;
	rec->a2 = (unsigned long) size;
	rec->a3 = 0;	/* flags must be zero */
}

struct syscallentry syscall_lsm_list_modules = {
	.name = "lsm_list_modules",
	.num_args = 3,
	.argname = { [0] = "ids", [1] = "size", [2] = "flags" },
	.rettype = RET_ZERO_SUCCESS,
	.sanitise = sanitise_lsm_list_modules,
	.group = GROUP_PROCESS,
};
