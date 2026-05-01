/*
 * SYSCALL_DEFINE2(newfstat, unsigned int, fd, struct stat __user *, statbuf)
 */
#include "arch.h"
#include "sanitise.h"

static void sanitise_newfstat(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a2, page_size);
}

struct syscallentry syscall_newfstat = {
	.name = "newfstat",
	.num_args = 2,
	.argtype = { [0] = ARG_FD, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "fd", [1] = "statbuf" },
	.sanitise = sanitise_newfstat,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	.rettype = RET_ZERO_SUCCESS,
};


/*
 * SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,
                   struct stat __user *, statbuf, int, flag)
 */
#include <fcntl.h>

static unsigned long newfstatat_flags[] = {
	0,	/* no flags — follow symlinks (default behavior) */
	AT_SYMLINK_NOFOLLOW,
	AT_EMPTY_PATH,
	AT_NO_AUTOMOUNT,
};

static void sanitise_newfstatat(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a3, page_size);
}

struct syscallentry syscall_newfstatat = {
	.name = "newfstatat",
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_NON_NULL_ADDRESS, [3] = ARG_LIST },
	.argname = { [0] = "dfd", [1] = "filename", [2] = "statbuf", [3] = "flag" },
	.arg_params[3].list = ARGLIST(newfstatat_flags),
	.sanitise = sanitise_newfstatat,
	.group = GROUP_VFS,
	.rettype = RET_ZERO_SUCCESS,
};
