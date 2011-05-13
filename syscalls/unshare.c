/*
 * SYSCALL_DEFINE1(unshare, unsigned long, unshare_flags)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_unshare = {
	.name = "unshare",
	.num_args = 1,
	.arg1name = "unshare_flags",
};
