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

static void sanitise_splice(struct syscallrecord *rec)
{
	if (ONE_IN(3))
		return;

	if (RAND_BOOL()) {
		rec->a1 = shm->pipe_fds[rand() % MAX_PIPE_FDS];
		rec->a2 = 0;
	}

	if (RAND_BOOL()) {
		rec->a3 = shm->pipe_fds[rand() % MAX_PIPE_FDS];
		rec->a4 = 0;
	}
}

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
	.arg6list = {
		.num = 4,
		.values = { SPLICE_F_MOVE, SPLICE_F_NONBLOCK, SPLICE_F_MORE, SPLICE_F_GIFT },
	},
	.sanitise = sanitise_splice,
	.flags = NEED_ALARM,
};
