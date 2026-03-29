/*
 * SYSCALL_DEFINE5(mount, char __user *, dev_name, char __user *, dir_name,
	 char __user *, type, unsigned long, flags, void __user *, data)
 */

#include <linux/fs.h>
#include <linux/mount.h>
#include <string.h>
#include "random.h"
#include "sanitise.h"
#include "compat.h"

static const char *fs_types[] = {
	"ext4", "btrfs", "xfs", "tmpfs", "proc", "sysfs",
	"devtmpfs", "devpts", "cgroup2", "overlay", "nfs",
	"fuse", "hugetlbfs", "mqueue", "debugfs", "tracefs",
	"securityfs", "pstore", "efivarfs", "bpf", "ramfs",
};

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

static void sanitise_mount(struct syscallrecord *rec)
{
	const char *fstype;
	char *type;

	fstype = fs_types[rand() % ARRAY_SIZE(fs_types)];
	type = (char *) get_writable_address(32);
	strncpy(type, fstype, 31);
	type[31] = '\0';

	rec->a3 = (unsigned long) type;
}

struct syscallentry syscall_mount = {
	.name = "mount",
	.num_args = 5,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_PATHNAME, [3] = ARG_LIST, [4] = ARG_ADDRESS },
	.argname = { [0] = "dev_name", [1] = "dir_name", [2] = "type", [3] = "flags", [4] = "data" },
	.arg4list = ARGLIST(mount_flags),
	.group = GROUP_VFS,
	.flags = NEEDS_ROOT,
	.sanitise = sanitise_mount,
};

#ifndef MOUNT_ATTR_RDONLY
#define MOUNT_ATTR_RDONLY	0x00000001
#define MOUNT_ATTR_NOSUID	0x00000002
#define MOUNT_ATTR_NODEV	0x00000004
#define MOUNT_ATTR_NOEXEC	0x00000008
#define MOUNT_ATTR_NOATIME	0x00000010
#define MOUNT_ATTR_STRICTATIME	0x00000020
#define MOUNT_ATTR_NODIRATIME	0x00000080
#define MOUNT_ATTR_NOSYMFOLLOW	0x00200000
#endif

static unsigned long mount_attrs[] = {
	MOUNT_ATTR_RDONLY, MOUNT_ATTR_NOSUID, MOUNT_ATTR_NODEV,
	MOUNT_ATTR_NOEXEC, MOUNT_ATTR_NOATIME, MOUNT_ATTR_STRICTATIME,
	MOUNT_ATTR_NODIRATIME, MOUNT_ATTR_NOSYMFOLLOW,
};

static void sanitise_mount_setattr(struct syscallrecord *rec)
{
	struct mount_attr *ma;
	unsigned int i, nbits;
	__u64 attrs;

	ma = (struct mount_attr *) get_writable_address(sizeof(*ma));
	memset(ma, 0, sizeof(*ma));

	/* Build random attr_set (things to turn on). */
	attrs = 0;
	nbits = 1 + (rand() % ARRAY_SIZE(mount_attrs));
	for (i = 0; i < nbits; i++)
		attrs |= mount_attrs[rand() % ARRAY_SIZE(mount_attrs)];
	ma->attr_set = attrs;

	/* Build random attr_clr (things to turn off) — non-overlapping with attr_set. */
	attrs = 0;
	nbits = rand() % ARRAY_SIZE(mount_attrs);
	for (i = 0; i < nbits; i++)
		attrs |= mount_attrs[rand() % ARRAY_SIZE(mount_attrs)];
	ma->attr_clr = attrs & ~ma->attr_set;

	rec->a4 = (unsigned long) ma;
	rec->a5 = MOUNT_ATTR_SIZE_VER0;
}

#define AT_STATX_SYNC_TYPE      0x6000
#define AT_STATX_SYNC_AS_STAT   0x0000
#define AT_STATX_FORCE_SYNC     0x2000
#define AT_STATX_DONT_SYNC      0x4000
#define AT_RECURSIVE_LOCAL       0x8000

static unsigned long mount_setattr_flags[] = {
	AT_EMPTY_PATH, AT_STATX_SYNC_TYPE, AT_STATX_SYNC_AS_STAT,
	AT_STATX_FORCE_SYNC, AT_STATX_DONT_SYNC, AT_RECURSIVE_LOCAL,
};

struct syscallentry syscall_mount_setattr = {
	.name = "mount_setattr",
	.num_args = 5,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_LIST },
	.argname = { [0] = "dfd", [1] = "path", [2] = "flags", [3] = "uattr", [4] = "usize" },
	.arg3list = ARGLIST(mount_setattr_flags),
	.group = GROUP_VFS,
	.sanitise = sanitise_mount_setattr,
};
