#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include "files.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "trinity.h"
#include "utils.h"
#include "compat.h"

static unsigned long open_o_flags_base[] = {
	O_RDONLY, O_WRONLY, O_RDWR, O_CREAT,
};

static const unsigned long o_flags[] = {
	O_EXCL, O_NOCTTY, O_TRUNC, O_APPEND,
	O_NONBLOCK, O_SYNC, O_ASYNC, O_DIRECTORY,
	O_NOFOLLOW, O_CLOEXEC, O_DIRECT, O_NOATIME,
	O_PATH, O_DSYNC, O_LARGEFILE, O_TMPFILE,
};

/*
 * Choose a random number of file flags to OR into the mask.
 * also used in files.c:open_file()
 */
unsigned long get_o_flags(void)
{
	unsigned long mask;

	mask = set_rand_bitmask(ARRAY_SIZE(o_flags), o_flags);

	return mask;
}

static void sanitise_open(struct syscallrecord *rec)
{
	unsigned long flags;

	flags = get_o_flags();

	rec->a2 |= flags;

	if (rec->a2 & O_CREAT)
		rec->a3 = 0666;

	if (rec->a2 & O_TMPFILE)
		rec->a3 = 0666;
}

static void sanitise_openat(struct syscallrecord *rec)
{
	unsigned long flags;

	flags = get_o_flags();

	rec->a3 |= flags;

	if (rec->a3 & O_CREAT)
		rec->a4 = 0666;

	if (rec->a3 & O_TMPFILE)
		rec->a4 = 0666;
}

/*
 * SYSCALL_DEFINE3(open, const char __user *, filename, int, flags, int, mode)
 */
struct syscallentry syscall_open = {
	.name = "open",
	.num_args = 3,
	.arg1name = "filename",
	.arg1type = ARG_PATHNAME,
	.arg2name = "flags",
	.arg2type = ARG_OP,
	.arg2list = ARGLIST(open_o_flags_base),
	.arg3name = "mode",
	.arg3type = ARG_MODE_T,
	.sanitise = sanitise_open,
};

/*
 * SYSCALL_DEFINE4(openat, int, dfd, const char __user *, filename, int, flags, int, mode)
 */
struct syscallentry syscall_openat = {
	.name = "openat",
	.num_args = 4,
	.arg1name = "dfd",
	.arg1type = ARG_FD,
	.arg2name = "filename",
	.arg2type = ARG_PATHNAME,
	.arg3name = "flags",
	.arg3type = ARG_OP,
	.arg3list = ARGLIST(open_o_flags_base),
	.arg4name = "mode",
	.arg4type = ARG_MODE_T,
	.flags = NEED_ALARM,
	.sanitise = sanitise_openat,
};

/*
 * SYSCALL_DEFINE4(openat2, int, dfd, const char __user *, filename,
                 struct open_how __user *, how, size_t, usize)
 */
struct syscallentry syscall_openat2 = {
	.name = "openat2",
	.num_args = 4,
	.arg1name = "dfd",
	.arg1type = ARG_FD,
	.arg2name = "filename",
	.arg2type = ARG_PATHNAME,
	.arg3name = "how",
	.arg4name = "usize",
	.arg4type = ARG_LEN,
	.flags = NEED_ALARM,
};

/*
 * SYSCALL_DEFINE3(open_by_handle_at, int, mountdirfd,
 *               struct file_handle __user *, handle,
 *               int, flags)
 */
struct syscallentry syscall_open_by_handle_at = {
	.name = "open_by_handle_at",
	.num_args = 3,
	.arg1name = "mountdirfd",
	.arg1type = ARG_FD,
	.arg2name = "handle",
	.arg2type = ARG_ADDRESS,
	.arg3name = "flags",
	.arg3type = ARG_OP,
	.arg3list = ARGLIST(open_o_flags_base),
	.flags = NEED_ALARM,
	.sanitise = sanitise_openat,	// For now we only sanitise .flags, which is also arg3
};
