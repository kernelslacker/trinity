/*
 * SYSCALL_DEFINE2(access, const char __user *, filename, int, mode)
 *
 * On  success  (all requested permissions granted), zero is returned.
 * On error (at least one bit in mode asked for a permission that is denied,
 *  or some other error occurred), -1 is returned, and errno is set appropriately.
 */
#include <unistd.h>
#include "sanitise.h"

static unsigned long access_modes[] = {
	F_OK, R_OK, W_OK, X_OK,
};

struct syscallentry syscall_access = {
	.name = "access",
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_LIST },
	.argname = { [0] = "filename", [1] = "mode" },
	.arg_params[1].list = ARGLIST(access_modes),
	.group = GROUP_VFS,
};
