/*
 * SYSCALL_DEFINE1(acct, const char __user *, name)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_acct = {
	.name = "acct",
	.num_args = 1,
	.arg1name = "name",
	.arg1type = ARG_ADDRESS,
};
