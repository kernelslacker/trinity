/*
 *   SYSCALL_DEFINE2(io_uring_setup, u32, entries, struct io_uring_params __user *, params)
 */
#include "sanitise.h"

struct syscallentry syscall_io_uring_setup = {
	.name = "io_uring_setup",
	.num_args = 2,
	.arg1name = "entries",
	.arg2name = "params",
	.arg2type = ARG_ADDRESS,
};
