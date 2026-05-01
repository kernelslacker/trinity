/*
 * SYSCALL_DEFINE3(getresgid, gid_t __user *, rgid, gid_t __user *, egid, gid_t __user *, sgid)
 */
#include <sys/types.h>
#include "sanitise.h"

static void sanitise_getresgid(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a1, sizeof(gid_t));
	avoid_shared_buffer(&rec->a2, sizeof(gid_t));
	avoid_shared_buffer(&rec->a3, sizeof(gid_t));
}

struct syscallentry syscall_getresgid = {
	.name = "getresgid",
	.num_args = 3,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "rgid", [1] = "egid", [2] = "sgid" },
	.sanitise = sanitise_getresgid,
	.group = GROUP_PROCESS,
};


/*
 * SYSCALL_DEFINE3(getresgid16, old_gid_t __user *, rgid, old_gid_t __user *, egid, old_gid_t __user *, sgid)
 */

struct syscallentry syscall_getresgid16 = {
	.name = "getresgid16",
	.num_args = 3,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "rgid", [1] = "egid", [2] = "sgid" },
	.sanitise = sanitise_getresgid,
	.group = GROUP_PROCESS,
};
