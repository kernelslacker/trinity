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
	.arg1name = "fdin",
	.arg1type = ARG_FD_PIPE,
	.arg2name = "fdout",
	.arg2type = ARG_FD_PIPE,
	.arg3name = "len",
	.arg3type = ARG_LEN,
	.arg4name = "flags",
	.arg4type = ARG_LIST,
	.arg4list = ARGLIST(tee_flags),
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
