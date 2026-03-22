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
#include "objects.h"
#include "sanitise.h"

#define CLOSE_RANGE_UNSHARE     (1U << 1)
#define CLOSE_RANGE_CLOEXEC     (1U << 2)

static unsigned long close_range_flags[] = {
	CLOSE_RANGE_UNSHARE, CLOSE_RANGE_CLOEXEC,
};

/*
 * If close_range succeeded without CLOEXEC flag, the fds in the range
 * are actually closed.  Scan object pools and remove any matching fds.
 */
static void post_close_range(struct syscallrecord *rec)
{
	unsigned int fd, max_fd;

	if (rec->retval != 0)
		return;

	/* CLOEXEC just marks fds, doesn't close them yet */
	if (rec->a3 & CLOSE_RANGE_CLOEXEC)
		return;

	fd = (unsigned int) rec->a1;
	max_fd = (unsigned int) rec->a2;

	/* Sanity: don't scan billions of fds */
	if (max_fd - fd > 1024)
		max_fd = fd + 1024;

	for (; fd <= max_fd; fd++)
		remove_object_by_fd((int) fd);
}

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
	.post = post_close_range,
	.flags = AVOID_SYSCALL,
	.rettype = RET_ZERO_SUCCESS,
};
