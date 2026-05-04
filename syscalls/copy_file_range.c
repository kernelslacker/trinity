/*
 * SYSCALL_DEFINE6(copy_file_range, int, fd_in, loff_t __user *, off_in,
 * int, fd_out, loff_t __user *, off_out,
 * size_t, len, unsigned int, flags)
 */
#include <linux/fs.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include "arch.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

static unsigned long copy_file_range_flags[] = {
	0,	// so far, no flags, MBZ.
};

static void sanitise_copy_file_range(struct syscallrecord *rec)
{
	loff_t *off_in = (loff_t *) get_writable_address(sizeof(loff_t));
	loff_t *off_out = (loff_t *) get_writable_address(sizeof(loff_t));
	*off_in = RAND_RANGE(0, 1ULL << 30);
	*off_out = RAND_RANGE(0, 1ULL << 30);
	rec->a2 = (unsigned long) off_in;
	rec->a4 = (unsigned long) off_out;
}

static void post_copy_file_range(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	if (ret == -1L)
		return;
	if (ret < 0 || (size_t) ret > (size_t) rec->a5)
		post_handler_corrupt_ptr_bump(rec, NULL);
}

struct syscallentry syscall_copy_file_range = {
	.name = "copy_file_range",
	.num_args = 6,
	.argtype = { [0] = ARG_FD, [1] = ARG_ADDRESS, [2] = ARG_FD, [3] = ARG_ADDRESS, [4] = ARG_LEN, [5] = ARG_LIST },
	.argname = { [0] = "fd_in", [1] = "off_in", [2] = "fd_out", [3] = "off_out", [4] = "len", [5] = "flags" },
	.arg_params[5].list = ARGLIST(copy_file_range_flags),
	.sanitise = sanitise_copy_file_range,
	.post = post_copy_file_range,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
