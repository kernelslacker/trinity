/**
 * close_range() - Close all file descriptors in a given range.
 *
 * @fd:     starting file descriptor to close
 * @max_fd: last file descriptor to close
 * @flags:  reserved for future extensions
 *
 * This closes a range of file descriptors. All file descriptors
 * from @fd up to and including @max_fd are closed.
 * Currently, errors to close a given file descriptor are ignored.
 */ 
#include "sanitise.h"
#include "syscall.h"

#define CLOSE_RANGE_UNSHARE     (1U << 1)
#define CLOSE_RANGE_CLOEXEC     (1U << 2)


static unsigned long close_range_flags[] = {
	CLOSE_RANGE_UNSHARE, CLOSE_RANGE_CLOEXEC,
};

struct syscallentry syscall_close_range = {
	.name = "close_range",
	.num_args = 3,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "max_fd",
	.arg2type = ARG_FD,
	.arg3name = "flags",
	.arg3type = ARG_LIST,
	.arg3list = ARGLIST(close_range_flags),

	.flags = AVOID_SYSCALL,
	.rettype = RET_ZERO_SUCCESS,
};
