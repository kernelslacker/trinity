/*
 *  SYSCALL_DEFINE2(fsopen, const char __user *, _fs_name, unsigned int, flags)
 */
#include <string.h>
#include "random.h"
#include "sanitise.h"

#define FSOPEN_CLOEXEC 0x00000001
static unsigned long fsopen_flags[] = {
	FSOPEN_CLOEXEC
};

static const char *fs_types[] = {
	"ext4", "btrfs", "xfs", "tmpfs", "proc", "sysfs",
	"devtmpfs", "devpts", "cgroup2", "overlay", "nfs",
	"fuse", "hugetlbfs", "mqueue", "debugfs", "tracefs",
	"securityfs", "pstore", "efivarfs", "bpf", "ramfs",
};

static void sanitise_fsopen(struct syscallrecord *rec)
{
	const char *fstype;
	char *name;

	fstype = fs_types[rand() % ARRAY_SIZE(fs_types)];
	name = (char *) get_writable_address(32);
	strncpy(name, fstype, 31);
	name[31] = '\0';

	rec->a1 = (unsigned long) name;
}

struct syscallentry syscall_fsopen = {
	.name = "fsopen",
	.num_args = 2,
	.arg1name = "_fs_name",
	.arg2name = "flags",
	.arg2type = ARG_OP,
	.arg2list = ARGLIST(fsopen_flags),
	.rettype = RET_FD,
	.group = GROUP_VFS,
	.flags = NEEDS_ROOT,
	.sanitise = sanitise_fsopen,
};
