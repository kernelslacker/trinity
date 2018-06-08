/*
 * SYSCALL_DEFINE6(copy_file_range, int, fd_in, loff_t __user *, off_in,
 * int, fd_out, loff_t __user *, off_out,
 * size_t, len, unsigned int, flags)
 */
#include <linux/fs.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include "arch.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"

static unsigned long copy_file_range_flags[] = {
	0,	// so far, no flags, MBZ.
};

struct syscallentry syscall_copy_file_range = {
	.name = "copy_file_range",
	.num_args = 6,
	.arg1name = "fd_in",
	.arg1type = ARG_FD,
	.arg2name = "off_in",
	.arg2type = ARG_LEN,
	.arg3name = "fd_out",
	.arg3type = ARG_FD,
	.arg4name = "off_out",
	.arg4type = ARG_LEN,
	.arg5name = "len",
	.arg5type = ARG_LEN,
	.arg6name = "flags",
	.arg6type = ARG_LIST,
	.arg6list = ARGLIST(copy_file_range_flags),
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
