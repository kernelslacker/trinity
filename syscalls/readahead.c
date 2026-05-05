/*
 * SYSCALL_DEFINE(readahead)(int fd, loff_t offset, size_t count)
 */
#include "random.h"
#include "sanitise.h"

static void sanitise_readahead(struct syscallrecord *rec)
{
	/* Negative offsets produce EINVAL; mask to non-negative loff_t. */
	rec->a2 = rand64() & 0x7fffffffffffffffULL;
}

struct syscallentry syscall_readahead = {
	.name = "readahead",
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [2] = ARG_LEN },
	.argname = { [0] = "fd", [1] = "offset", [2] = "count" },
	.sanitise = sanitise_readahead,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
