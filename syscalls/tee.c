/*
 * SYSCALL_DEFINE4(tee, int, fdin, int, fdout, size_t, len, unsigned int, flags)
 */
#include <fcntl.h>
#include "sanitise.h"
#include "trinity.h"
#include "compat.h"
#include "utils.h"

static unsigned long tee_flags[] = {
	SPLICE_F_MOVE, SPLICE_F_NONBLOCK, SPLICE_F_MORE, SPLICE_F_GIFT,
};

static void post_tee(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	if (ret == -1L)
		return;
	if (ret < 0 || (size_t) ret > (size_t) rec->a3)
		post_handler_corrupt_ptr_bump(rec, NULL);
}

struct syscallentry syscall_tee = {
	.name = "tee",
	.num_args = 4,
	.argtype = { [0] = ARG_FD_PIPE, [1] = ARG_FD_PIPE, [2] = ARG_LEN, [3] = ARG_LIST },
	.argname = { [0] = "fdin", [1] = "fdout", [2] = "len", [3] = "flags" },
	.arg_params[3].list = ARGLIST(tee_flags),
	.post = post_tee,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
