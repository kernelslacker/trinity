/*
 *  SYSCALL_DEFINE3(fspick, int, dfd, const char __user *, path, unsigned int, flags)
 */
#include <unistd.h>
#include "object-types.h"
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
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_OP },
	.argname = { [0] = "dfd", [1] = "path", [2] = "flags" },
	.arg_params[2].list = ARGLIST(fspick_flags),
	.rettype = RET_FD,
	.ret_objtype = OBJ_FD_FS_CTX,
	.group = GROUP_VFS,
	.flags = NEEDS_ROOT,
};
