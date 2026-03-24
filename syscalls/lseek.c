/*
 * SYSCALL_DEFINE3(lseek, unsigned int, fd, off_t, offset, unsigned int, whence)
 */
#include <sys/types.h>
#include <unistd.h>
#include "random.h"
#include "sanitise.h"
#include "compat.h"

static unsigned long lseek_whences[] = {
	SEEK_SET, SEEK_CUR, SEEK_END, SEEK_DATA,
	SEEK_HOLE,
};

static void sanitise_lseek(struct syscallrecord *rec)
{
	/* Negative offsets produce EINVAL on most filesystems. */
	rec->a2 = rand64() & 0x7fffffff;
}

struct syscallentry syscall_lseek = {
	.name = "lseek",
	.num_args = 3,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "offset",
	.arg3name = "whence",
	.arg3type = ARG_OP,
	.arg3list = ARGLIST(lseek_whences),
	.sanitise = sanitise_lseek,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
