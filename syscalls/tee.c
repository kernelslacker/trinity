/*
 * SYSCALL_DEFINE4(tee, int, fdin, int, fdout, size_t, len, unsigned int, flags)
 */
#include <fcntl.h>
#include <stdlib.h>
#include "pipes.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "trinity.h"
#include "compat.h"

static void sanitise_tee(struct syscallrecord *rec)
{
	if ((rnd() % 10) > 0) {
		rec->a1 = get_rand_pipe_fd();
		rec->a2 = get_rand_pipe_fd();
	}
}

static unsigned long tee_flags[] = {
	SPLICE_F_MOVE, SPLICE_F_NONBLOCK, SPLICE_F_MORE, SPLICE_F_GIFT,
};

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
	.arg4list = ARGLIST(tee_flags),
	.sanitise = sanitise_tee,
	.flags = NEED_ALARM,
};
