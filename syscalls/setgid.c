/*
 * SYSCALL_DEFINE1(setgid, gid_t, gid)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_setgid = {
	.name = "setgid",
	.num_args = 1,
	.arg1name = "gid",
};
