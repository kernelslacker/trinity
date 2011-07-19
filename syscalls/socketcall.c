/*
 * SYSCALL_DEFINE2(socketcall, int, call, unsigned long __user *, args)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_socketcall = {
	.name = "socketcall",
	.num_args = 2,
	.arg1name = "call",
	.arg1type = ARG_RANGE,
	.low1range= 1,
	.hi1range = 20,	/* SYS_SENDMMSG */
	.arg2name = "args",
	.arg2type = ARG_ADDRESS,
};
