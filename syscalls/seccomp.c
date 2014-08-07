/*
 * SYSCALL_DEFINE3(seccomp, unsigned int, op, unsigned int, flags,
 *                          const char __user *, uargs)
 */
#include <errno.h>
#include "sanitise.h"

#define SECCOMP_SET_MODE_STRICT 0
#define SECCOMP_SET_MODE_FILTER 1

struct syscallentry syscall_seccomp = {
	.name = "seccomp",
	.num_args = 3,
	.arg1name = "op",
	.arg1type = ARG_OP,
	.arg1list = {
		.num = 2,
		.values = { SECCOMP_SET_MODE_STRICT, SECCOMP_SET_MODE_FILTER },
	},
	.arg2name = "flags",
	.arg3name = "uargs",
	.arg3type = ARG_ADDRESS,
};
