/*
 * SYSCALL_DEFINE1(setfsgid, gid_t, gid)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_setfsgid = {
	.name = "setfsgid",
	.num_args = 1,
	.arg1name = "gid",
};
