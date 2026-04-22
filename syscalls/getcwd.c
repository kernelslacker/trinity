/*
 * SYSCALL_DEFINE2(getcwd, char __user *, buf, unsigned long, size)
 */
#include "arch.h"
#include "sanitise.h"

static void sanitise_getcwd(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a1, rec->a2 ? rec->a2 : page_size);
}

struct syscallentry syscall_getcwd = {
	.name = "getcwd",
	.num_args = 2,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS, [1] = ARG_LEN },
	.argname = { [0] = "buf", [1] = "size" },
	.sanitise = sanitise_getcwd,
	.rettype = RET_PATH,
	.group = GROUP_VFS,
};
