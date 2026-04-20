/*
 * SYSCALL_DEFINE2(statfs, const char __user *, pathname, struct statfs __user *, buf)
 */
#include "arch.h"
#include "sanitise.h"

static void sanitise_statfs(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a2, page_size);
}

struct syscallentry syscall_statfs = {
	.name = "statfs",
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "pathname", [1] = "buf" },
	.sanitise = sanitise_statfs,
	.group = GROUP_VFS,
	.rettype = RET_ZERO_SUCCESS,
};

/*
 * SYSCALL_DEFINE3(statfs64, const char __user *, pathname, size_t, sz, struct statfs64 __user *, buf)
 */

static void sanitise_statfs64(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a3, rec->a2 ? rec->a2 : page_size);
}

struct syscallentry syscall_statfs64 = {
	.name = "statfs64",
	.num_args = 3,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_LEN, [2] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "pathname", [1] = "sz", [2] = "buf" },
	.sanitise = sanitise_statfs64,
	.group = GROUP_VFS,
	.rettype = RET_ZERO_SUCCESS,
};
