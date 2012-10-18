/*
 * SYSCALL_DEFINE(fallocate)(int fd, int mode, loff_t offset, loff_t len)
 *
 * fallocate() returns zero on success, and -1 on failure.
 */
#include "trinity.h"
#include "sanitise.h"

#define FALLOC_FL_KEEP_SIZE	0x01
#define FALLOC_FL_PUNCH_HOLE	0x02

struct syscall syscall_fallocate = {
	.name = "fallocate",
	.num_args = 4,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "mode",
	.arg2type = ARG_LIST,
	.arg2list = {
		.num = 2,
		.values = { FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE },
	},
	.arg3name = "offset",
	.arg3type = ARG_LEN,
	.arg4name = "len",
	.arg4type = ARG_LEN,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
};
