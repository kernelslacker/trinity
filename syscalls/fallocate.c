/*
 * SYSCALL_DEFINE(fallocate)(int fd, int mode, loff_t offset, loff_t len)
 *
 * fallocate() returns zero on success, and -1 on failure.
 */
#include "sanitise.h"

#define FALLOC_FL_KEEP_SIZE	0x01
#define FALLOC_FL_PUNCH_HOLE	0x02
#define FALLOC_FL_NO_HIDE_STALE 0x04
#define FALLOC_FL_COLLAPSE_RANGE 0x08
#define FALLOC_FL_ZERO_RANGE 0x10
#define FALLOC_FL_INSERT_RANGE 0x20
#define FALLOC_FL_UNSHARE_RANGE 0x40

static unsigned long fallocate_modes[] = {
	FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE,
	FALLOC_FL_NO_HIDE_STALE, FALLOC_FL_COLLAPSE_RANGE,
	FALLOC_FL_ZERO_RANGE, FALLOC_FL_INSERT_RANGE,
	FALLOC_FL_UNSHARE_RANGE,
};

struct syscallentry syscall_fallocate = {
	.name = "fallocate",
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [1] = ARG_LIST, [2] = ARG_LEN, [3] = ARG_LEN },
	.argname = { [0] = "fd", [1] = "mode", [2] = "offset", [3] = "len" },
	.arg2list = ARGLIST(fallocate_modes),
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
