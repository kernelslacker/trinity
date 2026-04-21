/*
 * SYSCALL_DEFINE6(splice, int, fd_in, loff_t __user *, off_in,
	int, fd_out, loff_t __user *, off_out,
	size_t, len, unsigned int, flags)
 */
#include <fcntl.h>
#include "random.h"
#include "sanitise.h"
#include "trinity.h"
#include "compat.h"

static unsigned long splice_flags[] = {
	SPLICE_F_MOVE, SPLICE_F_NONBLOCK, SPLICE_F_MORE, SPLICE_F_GIFT,
};

static void sanitise_splice(struct syscallrecord *rec)
{
	loff_t *off_in = (loff_t *) get_writable_address(sizeof(loff_t));
	loff_t *off_out = (loff_t *) get_writable_address(sizeof(loff_t));

	*off_in = RAND_RANGE(0, 1ULL << 30);
	*off_out = RAND_RANGE(0, 1ULL << 30);
	rec->a2 = (unsigned long) off_in;
	rec->a4 = (unsigned long) off_out;
}

struct syscallentry syscall_splice = {
	.name = "splice",
	.num_args = 6,
	.argtype = { [0] = ARG_FD_PIPE, [1] = ARG_ADDRESS, [2] = ARG_FD_PIPE, [3] = ARG_ADDRESS, [4] = ARG_LEN, [5] = ARG_LIST },
	.argname = { [0] = "fd_in", [1] = "off_in", [2] = "fd_out", [3] = "off_out", [4] = "len", [5] = "flags" },
	.arg_params[5].list = ARGLIST(splice_flags),
	.sanitise = sanitise_splice,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
