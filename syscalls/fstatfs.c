/*
 * SYSCALL_DEFINE2(fstatfs, unsigned int, fd, struct statfs __user *, buf)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include "arch.h"
#include "sanitise.h"

static void sanitise_fstatfs(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a2, page_size);
}

struct syscallentry syscall_fstatfs = {
	.name = "fstatfs",
	.num_args = 2,
	.argtype = { [0] = ARG_FD, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "fd", [1] = "buf" },
	.sanitise = sanitise_fstatfs,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};


/*
 * SYSCALL_DEFINE3(fstatfs64, unsigned int, fd, size_t, sz, struct statfs64 __user *, buf)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */

static void sanitise_fstatfs64(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a3, rec->a2 ? rec->a2 : page_size);
}

struct syscallentry syscall_fstatfs64 = {
	.name = "fstatfs64",
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_LEN, [2] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "fd", [1] = "sz", [2] = "buf" },
	.sanitise = sanitise_fstatfs64,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
