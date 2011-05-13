/*
 * SYSCALL_DEFINE1(setfsuid16, old_uid_t, uid)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_setfsuid16 = {
	.name = "setfsuid16",
	.num_args = 1,
	.arg1name = "uid",
};
