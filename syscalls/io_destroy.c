/*
 * SYSCALL_DEFINE1(io_destroy, aio_context_t, ctx)
 */
#include "sanitise.h"

struct syscallentry syscall_io_destroy = {
	.name = "io_destroy",
	.num_args = 1,
	.argtype = { [0] = ARG_ADDRESS },
	.argname = { [0] = "ctx" },
	.group = GROUP_VFS,
};
