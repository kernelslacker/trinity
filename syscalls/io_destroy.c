/*
 * SYSCALL_DEFINE1(io_destroy, aio_context_t, ctx)
 */
#include "objects.h"
#include "sanitise.h"

static void sanitise_io_destroy(struct syscallrecord *rec)
{
	rec->a1 = get_random_aio_ctx();
}

struct syscallentry syscall_io_destroy = {
	.name = "io_destroy",
	.num_args = 1,
	.argname = { [0] = "ctx" },
	.group = GROUP_VFS,
	.sanitise = sanitise_io_destroy,
};
