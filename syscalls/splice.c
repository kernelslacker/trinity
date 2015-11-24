/*
 * SYSCALL_DEFINE6(splice, int, fd_in, loff_t __user *, off_in,
	int, fd_out, loff_t __user *, off_out,
	size_t, len, unsigned int, flags)
 */
#include <fcntl.h>
#include <stdlib.h>
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "trinity.h"
#include "compat.h"

static unsigned long splice_flags[] = {
	SPLICE_F_MOVE, SPLICE_F_NONBLOCK, SPLICE_F_MORE, SPLICE_F_GIFT,
};

struct syscallentry syscall_splice = {
	.name = "splice",
	.num_args = 6,
	.arg1name = "fd_in",
	.arg1type = ARG_FD,
	.arg2name = "off_in",
	.arg2type = ARG_ADDRESS,
	.arg3name = "fd_out",
	.arg3type = ARG_FD,
	.arg4name = "off_out",
	.arg4type = ARG_ADDRESS,
	.arg5name = "len",
	.arg5type = ARG_LEN,
	.arg6name = "flags",
	.arg6type = ARG_LIST,
	.arg6list = ARGLIST(splice_flags),
	.flags = NEED_ALARM,
};
