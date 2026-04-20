/*
 * SYSCALL_DEFINE2(newlstat, const char __user *, filename, struct stat __user *, statbuf)
 */
#include "arch.h"
#include "sanitise.h"

static void sanitise_newlstat(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a2, page_size);
}

struct syscallentry syscall_newlstat = {
	.name = "newlstat",
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "filename", [1] = "statbuf" },
	.sanitise = sanitise_newlstat,
	.group = GROUP_VFS,
	.rettype = RET_ZERO_SUCCESS,
};
