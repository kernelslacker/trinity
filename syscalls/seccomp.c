/*
 * SYSCALL_DEFINE3(seccomp, unsigned int, op, unsigned int, flags,
 *                          const char __user *, uargs)
 */
#include <errno.h>
#include "sanitise.h"

#define SECCOMP_SET_MODE_STRICT 0
#define SECCOMP_SET_MODE_FILTER 1

#define SECCOMP_FILTER_FLAG_TSYNC 1

static void sanitise_seccomp(struct syscallrecord *rec)
{
	if (rec->a1 == SECCOMP_SET_MODE_STRICT) {
		rec->a2 = 0;
		rec->a3 = 0;
	}
}

static unsigned long seccomp_ops[] = {
	SECCOMP_SET_MODE_STRICT, SECCOMP_SET_MODE_FILTER,
};

static unsigned long seccomp_flags[] = {
	SECCOMP_FILTER_FLAG_TSYNC,
};

struct syscallentry syscall_seccomp = {
	.name = "seccomp",
	.num_args = 3,
	.arg1name = "op",
	.arg1type = ARG_OP,
	.arg1list = ARGLIST(seccomp_ops),
	.arg2name = "flags",
	.arg2type = ARG_LIST,
	.arg2list = ARGLIST(seccomp_flags),
	.arg3name = "uargs",
	.arg3type = ARG_ADDRESS,
	.sanitise = sanitise_seccomp,
};
