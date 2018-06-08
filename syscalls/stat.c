/*
 * SYSCALL_DEFINE2(newstat, const char __user *, filename, struct stat __user *, statbuf)
 */
#include "sanitise.h"

struct syscallentry syscall_stat = {
	.name = "stat",
	.num_args = 2,
	.arg1name = "filename",
	.arg1type = ARG_PATHNAME,
	.arg2name = "statbuf",
	.arg2type = ARG_ADDRESS,
};


/*
 * SYSCALL_DEFINE2(stat64, const char __user *, filename, struct stat64 __user *, statbuf)
 */

struct syscallentry syscall_stat64 = {
	.name = "stat64",
	.num_args = 2,
	.arg1name = "filename",
	.arg1type = ARG_PATHNAME,
	.arg2name = "statbuf",
	.arg2type = ARG_ADDRESS,
};

/*
 * SYSCALL_DEFINE5(statx, int, dfd, const char __user *, filename, unsigned, flags, unsigned int, mask, struct statx __user *, buffer)
 */

#define AT_STATX_SYNC_TYPE      0x6000  /* Type of synchronisation required from statx() */
#define AT_STATX_SYNC_AS_STAT   0x0000  /* - Do whatever stat() does */
#define AT_STATX_FORCE_SYNC     0x2000  /* - Force the attributes to be sync'd with the server */
#define AT_STATX_DONT_SYNC      0x4000  /* - Don't sync attributes with the server */

static unsigned long statx_flags[] = {
	AT_STATX_SYNC_TYPE, AT_STATX_SYNC_AS_STAT, AT_STATX_FORCE_SYNC, AT_STATX_DONT_SYNC,
};

struct syscallentry syscall_statx = {
	.name = "statx",
	.num_args = 5,
	.arg1name = "dfd",
	.arg1type = ARG_FD,
	.arg2name = "filename",
	.arg2type = ARG_PATHNAME,
	.arg3name = "flags",
	.arg3type = ARG_LIST,
	.arg3list = ARGLIST(statx_flags),
	.arg4name = "mask",
	.arg5name = "buffer",
	.arg5type = ARG_ADDRESS,
};
