/*
 * SYSCALL_DEFINE2(creat, const char __user *, pathname, int, mode)
 *
 * returns the new file descriptor on success.
 * returns -1 if an error occurred (in which case, errno is set appropriately).
 */
#include <unistd.h>
#include "sanitise.h"

static void post_creat(struct syscallrecord *rec)
{
	int fd = rec->retval;

	if (fd < 0 || fd >= (1 << 20))
		return;
	close(fd);
}

struct syscallentry syscall_creat = {
	.name = "creat",
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_MODE_T },
	.argname = { [0] = "pathname", [1] = "mode" },
	.rettype = RET_FD,
	.flags = NEED_ALARM,
	.post = post_creat,
	.group = GROUP_VFS,
};
