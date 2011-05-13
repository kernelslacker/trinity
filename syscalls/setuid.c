/*
 * SYSCALL_DEFINE1(setuid, uid_t, uid)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_setuid = {
	.name = "setuid",
	.num_args = 1,
	.arg1name = "uid",
};
