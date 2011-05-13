/*
 * int ppc_rtas(struct rtas_args __user *uargs)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_rtas = {
	.name = "rtas",
	.num_args = 1,
	.arg1name = "uargs",
	.arg1type = ARG_ADDRESS,
};
