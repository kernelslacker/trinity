/*
 * SYSCALL_DEFINE3(seccomp, unsigned int, op, unsigned int, flags,
 *                          const char __user *, uargs)
 */
#include <errno.h>
#include "sanitise.h"

#define SECCOMP_SET_MODE_STRICT		0
#define SECCOMP_SET_MODE_FILTER		1
#define SECCOMP_GET_ACTION_AVAIL	2
#define SECCOMP_GET_NOTIF_SIZES		3

#define SECCOMP_FILTER_FLAG_TSYNC		(1UL << 0)
#define SECCOMP_FILTER_FLAG_LOG			(1UL << 1)
#define SECCOMP_FILTER_FLAG_SPEC_ALLOW		(1UL << 2)
#define SECCOMP_FILTER_FLAG_NEW_LISTENER	(1UL << 3)
#define SECCOMP_FILTER_FLAG_TSYNC_ESRCH		(1UL << 4)
#define SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV	(1UL << 5)

static void sanitise_seccomp(struct syscallrecord *rec)
{
	if (rec->a1 == SECCOMP_SET_MODE_STRICT) {
		rec->a2 = 0;
		rec->a3 = 0;
	}
}

static unsigned long seccomp_ops[] = {
	SECCOMP_SET_MODE_STRICT, SECCOMP_SET_MODE_FILTER,
	SECCOMP_GET_ACTION_AVAIL, SECCOMP_GET_NOTIF_SIZES,
};

static unsigned long seccomp_flags[] = {
	SECCOMP_FILTER_FLAG_TSYNC,
	SECCOMP_FILTER_FLAG_LOG,
	SECCOMP_FILTER_FLAG_SPEC_ALLOW,
	SECCOMP_FILTER_FLAG_NEW_LISTENER,
	SECCOMP_FILTER_FLAG_TSYNC_ESRCH,
	SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV,
};

struct syscallentry syscall_seccomp = {
	.name = "seccomp",
	.num_args = 3,
	.argtype = { [0] = ARG_OP, [1] = ARG_LIST, [2] = ARG_ADDRESS },
	.argname = { [0] = "op", [1] = "flags", [2] = "uargs" },
	.arg1list = ARGLIST(seccomp_ops),
	.arg2list = ARGLIST(seccomp_flags),
	.sanitise = sanitise_seccomp,
	.group = GROUP_PROCESS,
};
