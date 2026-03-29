/*
 * SYSCALL_DEFINE4(tee, int, fdin, int, fdout, size_t, len, unsigned int, flags)
 */
#include <fcntl.h>
#include "sanitise.h"
#include "compat.h"

static unsigned long tee_flags[] = {
	SPLICE_F_MOVE, SPLICE_F_NONBLOCK, SPLICE_F_MORE, SPLICE_F_GIFT,
};

struct syscallentry syscall_tee = {
	.name = "tee",
	.num_args = 4,
	.argtype = { [0] = ARG_FD_PIPE, [1] = ARG_FD_PIPE, [2] = ARG_LEN, [3] = ARG_LIST },
	.argname = { [0] = "fdin", [1] = "fdout", [2] = "len", [3] = "flags" },
	.arg_params[3].list = ARGLIST(tee_flags),
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
