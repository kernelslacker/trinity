/*
 * SYSCALL_DEFINE5(futex_waitv, struct futex_waitv __user *, waiters,
                   unsigned int, nr_futexes, unsigned int, flags,
                   struct __kernel_timespec __user *, timeout, clockid_t, clockid)
 */
#include <linux/futex.h>
#include <limits.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <inttypes.h>
#include "sanitise.h"

static void sanitise_futex_waitv(struct syscallrecord *rec)
{
	rec->a3 = 0;	// no flags right now
}

struct syscallentry syscall_futex_waitv = {
	.name = "futex_waitv",
	.num_args = 5,
	.arg1name = "waiters",
	.arg2name = "nr_futexes",
	.arg3name = "flags",
	.arg4name = "timeout",
	.arg5name = "clockid",
	.flags = NEED_ALARM | IGNORE_ENOSYS,
	.sanitise = sanitise_futex_waitv,
};
