/*
 * SYSCALL_DEFINE3(lseek, unsigned int, fd, off_t, offset, unsigned int, whence)
 */
#include <sys/types.h>
#include <unistd.h>
#include "random.h"
#include "sanitise.h"
#include "compat.h"
#include "utils.h"

static unsigned long lseek_whences[] = {
	SEEK_SET, SEEK_CUR, SEEK_END, SEEK_DATA,
	SEEK_HOLE,
};

static void sanitise_lseek(struct syscallrecord *rec)
{
	/* Negative offsets produce EINVAL on most filesystems. */
	rec->a2 = rand64() & 0x7fffffff;
}

static void post_lseek(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	if (ret == -1L)
		return;

	/*
	 * lseek returns a non-negative loff_t on success. A negative value
	 * that isn't -1 indicates a sign-extension or 32-on-64 compat tear
	 * in the return path.
	 */
	if (ret < 0)
		post_handler_corrupt_ptr_bump(rec, NULL);
}

struct syscallentry syscall_lseek = {
	.name = "lseek",
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [2] = ARG_OP },
	.argname = { [0] = "fd", [1] = "offset", [2] = "whence" },
	.arg_params[2].list = ARGLIST(lseek_whences),
	.sanitise = sanitise_lseek,
	.post = post_lseek,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
