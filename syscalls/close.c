/*
 * SYSCALL_DEFINE1(close, unsigned int, fd)
 *
 * returns zero on success.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include "objects.h"
#include "sanitise.h"

static void post_close(struct syscallrecord *rec)
{
	/* If close succeeded, remove the fd from object pools */
	if (rec->retval == 0)
		remove_object_by_fd((int) rec->a1);
}

struct syscallentry syscall_close = {
	.name = "close",
	.num_args = 1,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.flags = AVOID_SYSCALL,
	.post = post_close,
	.rettype = RET_ZERO_SUCCESS,
};
