/*
 * SYSCALL_DEFINE2(newstat, const char __user *, filename, struct stat __user *, statbuf)
 */
#include "arch.h"
#include "sanitise.h"

static void sanitise_statbuf_a2(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a2, page_size);
}

struct syscallentry syscall_stat = {
	.name = "stat",
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "filename", [1] = "statbuf" },
	.sanitise = sanitise_statbuf_a2,
	.group = GROUP_VFS,
};


/*
 * SYSCALL_DEFINE2(stat64, const char __user *, filename, struct stat64 __user *, statbuf)
 */

struct syscallentry syscall_stat64 = {
	.name = "stat64",
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "filename", [1] = "statbuf" },
	.sanitise = sanitise_statbuf_a2,
	.group = GROUP_VFS,
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

#ifndef STATX_TYPE
#define STATX_TYPE		0x00000001
#define STATX_MODE		0x00000002
#define STATX_NLINK		0x00000004
#define STATX_UID		0x00000008
#define STATX_GID		0x00000010
#define STATX_ATIME		0x00000020
#define STATX_MTIME		0x00000040
#define STATX_CTIME		0x00000080
#define STATX_INO		0x00000100
#define STATX_SIZE		0x00000200
#define STATX_BLOCKS		0x00000400
#define STATX_BTIME		0x00000800
#define STATX_MNT_ID		0x00001000
#define STATX_DIOALIGN		0x00002000
#define STATX_MNT_ID_UNIQUE	0x00004000
#define STATX_SUBVOL		0x00008000
#endif

static unsigned long statx_mask[] = {
	STATX_TYPE, STATX_MODE, STATX_NLINK, STATX_UID, STATX_GID,
	STATX_ATIME, STATX_MTIME, STATX_CTIME, STATX_INO, STATX_SIZE,
	STATX_BLOCKS, STATX_BTIME, STATX_MNT_ID, STATX_DIOALIGN,
	STATX_MNT_ID_UNIQUE, STATX_SUBVOL,
};

static void sanitise_statx(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a5, page_size);
}

struct syscallentry syscall_statx = {
	.name = "statx",
	.num_args = 5,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_LIST, [3] = ARG_LIST, [4] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "dfd", [1] = "filename", [2] = "flags", [3] = "mask", [4] = "buffer" },
	.arg_params[2].list = ARGLIST(statx_flags),
	.arg_params[3].list = ARGLIST(statx_mask),
	.sanitise = sanitise_statx,
	.group = GROUP_VFS,
};
