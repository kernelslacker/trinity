/*
 * SYSCALL_DEFINE2(creat, const char __user *, pathname, int, mode)
 *
 * returns the new file descriptor on success.
 * returns -1 if an error occurred (in which case, errno is set appropriately).
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_creat = {
	.name = "creat",
	.num_args = 2,
	.arg1name = "pathname",
	.arg1type = ARG_PATHNAME,
	.arg2name = "mode",
	.rettype = RET_FD,
};
