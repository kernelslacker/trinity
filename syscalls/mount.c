/*
 * SYSCALL_DEFINE5(mount, char __user *, dev_name, char __user *, dir_name,
	 char __user *, type, unsigned long, flags, void __user *, data)
 */

#include <linux/fs.h>
#include "sanitise.h"
#include "compat.h"

//TODO: fill out 'type' with something random from /proc/filesystems

static unsigned long mount_flags[] = {
	MS_RDONLY, MS_NOSUID, MS_NODEV, MS_NOEXEC,
	MS_SYNCHRONOUS, MS_REMOUNT, MS_MANDLOCK, MS_DIRSYNC,
	MS_NOATIME, MS_NODIRATIME, MS_BIND, MS_MOVE,
	MS_REC, MS_VERBOSE, MS_SILENT, MS_POSIXACL,
	MS_UNBINDABLE, MS_PRIVATE, MS_SLAVE, MS_SHARED,
	MS_RELATIME, MS_KERNMOUNT, MS_I_VERSION, MS_STRICTATIME,
	MS_SNAP_STABLE, MS_NOSEC, MS_BORN, MS_ACTIVE,
	MS_NOUSER,
};

struct syscallentry syscall_mount = {
	.name = "mount",
	.num_args = 5,
	.arg1name = "dev_name",
	.arg1type = ARG_PATHNAME,
	.arg2name = "dir_name",
	.arg2type = ARG_PATHNAME,
	.arg3name = "type",
	.arg3type = ARG_ADDRESS,
	.arg4name = "flags",
	.arg4type = ARG_LIST,
	.arg4list = ARGLIST(mount_flags),
	.arg5name = "data",
	.arg5type = ARG_ADDRESS,
	.group = GROUP_VFS,
};

#define AT_EMPTY_PATH           0x1000  /* Allow empty relative pathname */

#define AT_STATX_SYNC_TYPE      0x6000  /* Type of synchronisation required from statx() */
#define AT_STATX_SYNC_AS_STAT   0x0000  /* - Do whatever stat() does */
#define AT_STATX_FORCE_SYNC     0x2000  /* - Force the attributes to be sync'd with the server */
#define AT_STATX_DONT_SYNC      0x4000  /* - Don't sync attributes with the server */
    
#define AT_RECURSIVE            0x8000  /* Apply to the entire subtree */

static unsigned long mount_setattr_flags[] = {
	AT_EMPTY_PATH, AT_STATX_SYNC_TYPE, AT_STATX_SYNC_AS_STAT, AT_STATX_FORCE_SYNC, AT_STATX_DONT_SYNC, AT_RECURSIVE,
};

struct syscallentry syscall_mount_setattr = {
	.name = "mount_setattr",
	.num_args = 5,
	.arg1name = "dfd",
	.arg1type = ARG_FD,
	.arg2name = "path",
	.arg2type = ARG_PATHNAME,
	.arg3name = "flags",
	.arg3type = ARG_LIST,
	.arg3list = ARGLIST(mount_setattr_flags),
	.arg4name = "uattr",
	.arg4type = ARG_ADDRESS,
	.arg5name = "usize",
	.arg5type = ARG_LEN,
	.group = GROUP_VFS,
};
