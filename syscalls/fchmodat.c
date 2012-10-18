/*
 * SYSCALL_DEFINE3(fchmodat, int, dfd, const char __user *, filename, mode_t, mode)
 *
 * On success, fchmodat() returns 0.
 * On error, -1 is returned and errno is set to indicate the error.
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_fchmodat = {
	.name = "fchmodat",
	.num_args = 3,
	.arg1name = "dfd",
	.arg1type = ARG_FD,
	.arg2name = "filename",
	.arg2type = ARG_PATHNAME,
	.arg3name = "mode",
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
};
