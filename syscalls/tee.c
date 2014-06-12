/*
 * SYSCALL_DEFINE4(tee, int, fdin, int, fdout, size_t, len, unsigned int, flags)
 */
#include <fcntl.h>
#include <stdlib.h>
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "trinity.h"
#include "compat.h"

static void sanitise_tee(struct syscallrecord *rec)
{
	if ((rand() % 10) > 0) {
		rec->a1 = shm->pipe_fds[rand() % MAX_PIPE_FDS];
		rec->a2 = shm->pipe_fds[rand() % MAX_PIPE_FDS];
	}
}

struct syscallentry syscall_tee = {
	.name = "tee",
	.num_args = 4,
	.arg1name = "fdin",
	.arg1type = ARG_FD,
	.arg2name = "fdout",
	.arg2type = ARG_FD,
	.arg3name = "len",
	.arg3type = ARG_LEN,
	.arg4name = "flags",
	.arg4type = ARG_LIST,
	.arg4list = {
		.num = 4,
		.values = { SPLICE_F_MOVE, SPLICE_F_NONBLOCK, SPLICE_F_MORE, SPLICE_F_GIFT },
	},
	.sanitise = sanitise_tee,
	.flags = NEED_ALARM,
};
