/*
 * int ppc_rtas(struct rtas_args __user *uargs)
 */
#include "sanitise.h"

struct syscallentry syscall_rtas = {
	.name = "rtas",
	.num_args = 1,
	.argtype = { [0] = ARG_ADDRESS },
	.argname = { [0] = "uargs" },
};
