/*
 *  SYSCALL_DEFINE2(fsopen, const char __user *, _fs_name, unsigned int, flags)
 */
#include "sanitise.h"

// TODO: construct arg1 from /proc/filesystems

#define FSOPEN_CLOEXEC 0x00000001
static unsigned long fsopen_flags[] = {
	FSOPEN_CLOEXEC
};

struct syscallentry syscall_fsopen = {
	.name = "fsopen",
	.num_args = 2,
	.arg1name = "_fs_name",
	.arg2name = "flags",
	.arg2type = ARG_OP,
	.arg2list = ARGLIST(fsopen_flags),
};
