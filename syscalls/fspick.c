/*
 *  SYSCALL_DEFINE3(fspick, int, dfd, const char __user *, path, unsigned int, flags)
 */
#include "sanitise.h"

#define FSPICK_CLOEXEC          0x00000001
#define FSPICK_SYMLINK_NOFOLLOW 0x00000002
#define FSPICK_NO_AUTOMOUNT     0x00000004
#define FSPICK_EMPTY_PATH       0x00000008

static unsigned long fspick_flags[] = {
	FSPICK_CLOEXEC,
	FSPICK_SYMLINK_NOFOLLOW,
	FSPICK_NO_AUTOMOUNT,
	FSPICK_EMPTY_PATH,
};

struct syscallentry syscall_fspick = {
	.name = "fspick",
	.num_args = 3,
	.arg1name = "dfd",
	.arg1type = ARG_FD,
	.arg2name = "path",
	.arg2type = ARG_PATHNAME,
	.arg3name = "flags",
	.arg3type = ARG_OP,
	.arg3list = ARGLIST(fspick_flags),
};
