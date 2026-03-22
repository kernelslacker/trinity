/*
 * SYSCALL_DEFINE2(io_setup, unsigned, nr_events, aio_context_t __user *, ctxp)
 */
#include "sanitise.h"

struct syscallentry syscall_io_setup = {
	.name = "io_setup",
	.num_args = 2,
	.arg1name = "nr_events",
	.arg1type = ARG_RANGE,
	.low1range = 1,
	.hi1range = 256,
	.arg2name = "ctxp",
	.arg2type = ARG_ADDRESS,
	.group = GROUP_VFS,
};
