/*
 * SYSCALL_DEFINE2(io_setup, unsigned, nr_events, aio_context_t __user *, ctxp)
 */
#include <string.h>
#include "sanitise.h"

static void sanitise_io_setup(struct syscallrecord *rec)
{
	unsigned long *ctxp;

	/* ctxp must point to a zero-initialized aio_context_t */
	ctxp = (unsigned long *) get_writable_address(sizeof(*ctxp));
	*ctxp = 0;
	rec->a2 = (unsigned long) ctxp;
}

struct syscallentry syscall_io_setup = {
	.name = "io_setup",
	.num_args = 2,
	.argtype = { [0] = ARG_RANGE },
	.argname = { [0] = "nr_events", [1] = "ctxp" },
	.low1range = 1,
	.hi1range = 256,
	.group = GROUP_VFS,
	.sanitise = sanitise_io_setup,
};
