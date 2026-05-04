/*
 * SYSCALL_DEFINE5(mount, char __user *, dev_name, char __user *, dir_name,
 *	 char __user *, type, unsigned long, flags, void __user *, data)
 */

#include <linux/fs.h>
#include <linux/mount.h>
#include <stdio.h>
#include <string.h>
#include "random.h"
#include "sanitise.h"
#include "compat.h"
#include "trinity.h"

/* Filesystem types read from /proc/filesystems at startup. */
const char **filesystem_types;
unsigned int nr_filesystem_types;

static const char *builtin_fs_types[] = {
	"ext4", "btrfs", "xfs", "tmpfs", "proc", "sysfs",
	"devtmpfs", "devpts", "cgroup2", "overlay", "nfs",
	"fuse", "hugetlbfs", "mqueue", "debugfs", "tracefs",
	"securityfs", "pstore", "efivarfs", "bpf", "ramfs",
};

static void __attribute__((constructor)) read_filesystem_types(void)
{
	FILE *fp;
	char line[256];
	unsigned int count = 0, alloc = 64;

	fp = fopen("/proc/filesystems", "r");
	if (!fp) {
		filesystem_types = builtin_fs_types;
		nr_filesystem_types = ARRAY_SIZE(builtin_fs_types);
		return;
	}

	filesystem_types = malloc(alloc * sizeof(char *));
	if (!filesystem_types) {
		fclose(fp);
		filesystem_types = builtin_fs_types;
		nr_filesystem_types = ARRAY_SIZE(builtin_fs_types);
		return;
	}

	while (fgets(line, sizeof(line), fp)) {
		char *name;
		size_t len;

		/* Format: optional "nodev\t" prefix, then filesystem name */
		name = line;
		if (strncmp(name, "nodev", 5) == 0)
			name += 5;
		while (*name == '\t' || *name == ' ')
			name++;

		len = strlen(name);
		if (len > 0 && name[len - 1] == '\n')
			name[--len] = '\0';
		if (len == 0)
			continue;

		if (count >= alloc) {
			char **tmp;

			alloc *= 2;
			tmp = realloc(filesystem_types, alloc * sizeof(char *));
			if (!tmp)
				break;
			filesystem_types = (const char **)tmp;
		}

		filesystem_types[count] = strdup(name);
		if (!filesystem_types[count])
			break;
		count++;
	}

	fclose(fp);

	if (count == 0) {
		free(filesystem_types);
		filesystem_types = builtin_fs_types;
		nr_filesystem_types = ARRAY_SIZE(builtin_fs_types);
		return;
	}

	nr_filesystem_types = count;
}

static unsigned long mount_flags[] = {
	MS_RDONLY, MS_NOSUID, MS_NODEV, MS_NOEXEC,
	MS_SYNCHRONOUS, MS_REMOUNT, MS_MANDLOCK, MS_DIRSYNC,
	MS_NOATIME, MS_NODIRATIME, MS_BIND, MS_MOVE,
	MS_REC, MS_VERBOSE, MS_SILENT, MS_POSIXACL,
	MS_UNBINDABLE, MS_PRIVATE, MS_SLAVE, MS_SHARED,
	MS_RELATIME, MS_KERNMOUNT, MS_I_VERSION, MS_STRICTATIME,
	MS_NOSEC, MS_BORN, MS_ACTIVE,
	MS_NOUSER,
	MS_NOSYMFOLLOW,		/* v5.10 */
	MS_LAZYTIME,		/* v4.0 */
};

static void sanitise_mount(struct syscallrecord *rec)
{
	const char *fstype;
	char *type;

	fstype = filesystem_types[rand() % nr_filesystem_types];
	type = (char *) get_writable_struct(32);
	if (!type)
		return;
	strncpy(type, fstype, 31);
	type[31] = '\0';

	rec->a3 = (unsigned long) type;
}

struct syscallentry syscall_mount = {
	.name = "mount",
	.num_args = 5,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_PATHNAME, [3] = ARG_LIST, [4] = ARG_ADDRESS },
	.argname = { [0] = "dev_name", [1] = "dir_name", [2] = "type", [3] = "flags", [4] = "data" },
	.arg_params[3].list = ARGLIST(mount_flags),
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
#define MOUNT_ATTR_IDMAP	0x00100000
#define MOUNT_ATTR_NOSYMFOLLOW	0x00200000
#endif

static unsigned long mount_attrs[] = {
	MOUNT_ATTR_RDONLY, MOUNT_ATTR_NOSUID, MOUNT_ATTR_NODEV,
	MOUNT_ATTR_NOEXEC, MOUNT_ATTR_NOATIME, MOUNT_ATTR_STRICTATIME,
	MOUNT_ATTR_NODIRATIME, MOUNT_ATTR_IDMAP, MOUNT_ATTR_NOSYMFOLLOW,
};

static void sanitise_mount_setattr(struct syscallrecord *rec)
{
	struct mount_attr *ma;
	unsigned int i, nbits;
	__u64 attrs;

	ma = (struct mount_attr *) get_writable_struct(sizeof(*ma));
	if (!ma)
		return;
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
	.arg_params[2].list = ARGLIST(mount_setattr_flags),
	.group = GROUP_VFS,
	.sanitise = sanitise_mount_setattr,
};
