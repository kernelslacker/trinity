/*
 * SYSCALL_DEFINE(pwrite64)(unsigned int fd, const char __user *buf, size_t count, loff_t po>
 */
#include "trinity.h"
#include "sanitise.h"

static void sanitise_pwrite64(
		__unused__ unsigned long *a1,
		__unused__ unsigned long *a2,
		__unused__ unsigned long *a3,
		unsigned long *a4,
		__unused__ unsigned long *a5,
		__unused__ unsigned long *a6)
{

retry_pos:
	if ((int)*a4 < 0) {
		*a4 = rand64();
		goto retry_pos;
	}
}

struct syscall syscall_pwrite64 = {
	.name = "pwrite64",
	.num_args = 4,
	.sanitise = sanitise_pwrite64,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "buf",
	.arg2type = ARG_ADDRESS,
	.arg3name = "count",
	.arg4name = "pos",
};
