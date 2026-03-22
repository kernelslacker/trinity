/*
 * SYSCALL_DEFINE2(capget, cap_user_header_t, header, cap_user_data_t, dataptr)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include "sanitise.h"

struct syscallentry syscall_capget = {
	.name = "capget",
	.num_args = 2,
	.arg1name = "header",
	.arg1type = ARG_ADDRESS,
	.arg2name = "dataptr",
	.arg2type = ARG_ADDRESS,
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_PROCESS,
};
