/*
 * SYSCALL_DEFINE5(open_tree_attr, int, dfd, const char __user *, filename,
 *		unsigned, flags, struct mount_attr __user *, uattr, size_t, usize)
 */
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <linux/mount.h>
#include "object-types.h"
#include "sanitise.h"

#ifndef OPEN_TREE_CLONE
#define OPEN_TREE_CLONE		1
#define OPEN_TREE_CLOEXEC	O_CLOEXEC
#endif

#ifndef AT_RECURSIVE
#define AT_RECURSIVE		0x8000
#endif

static unsigned long open_tree_attr_flags[] = {
	AT_EMPTY_PATH, AT_NO_AUTOMOUNT, AT_RECURSIVE, AT_SYMLINK_NOFOLLOW,
	OPEN_TREE_CLONE, OPEN_TREE_CLOEXEC,
};

static unsigned long mount_attr_bits[] = {
	MOUNT_ATTR_RDONLY, MOUNT_ATTR_NOSUID, MOUNT_ATTR_NODEV,
	MOUNT_ATTR_NOEXEC, MOUNT_ATTR_NOATIME, MOUNT_ATTR_STRICTATIME,
	MOUNT_ATTR_NODIRATIME, MOUNT_ATTR_IDMAP, MOUNT_ATTR_NOSYMFOLLOW,
};

static void sanitise_open_tree_attr(struct syscallrecord *rec)
{
	struct mount_attr *ma;
	unsigned int i, nbits;
	unsigned long attrs;

	/*
	 * The kernel requires usize >= MOUNT_ATTR_SIZE_VER0 (32 bytes).
	 * ARG_LEN often produces values smaller than that, causing EINVAL
	 * before any mount attribute processing happens.
	 */
	ma = (struct mount_attr *) get_writable_struct(sizeof(*ma));
	if (!ma)
		return;
	memset(ma, 0, sizeof(*ma));

	attrs = 0;
	nbits = 1 + (rand() % ARRAY_SIZE(mount_attr_bits));
	for (i = 0; i < nbits; i++)
		attrs |= mount_attr_bits[rand() % ARRAY_SIZE(mount_attr_bits)];
	ma->attr_set = attrs;

	rec->a4 = (unsigned long) ma;
	rec->a5 = MOUNT_ATTR_SIZE_VER0;
}

struct syscallentry syscall_open_tree_attr = {
	.name = "open_tree_attr",
	.num_args = 5,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_LIST },
	.argname = { [0] = "dfd", [1] = "filename", [2] = "flags", [3] = "uattr", [4] = "usize" },
	.arg_params[2].list = ARGLIST(open_tree_attr_flags),
	.rettype = RET_FD,
	.ret_objtype = OBJ_FD_MOUNT,
	.group = GROUP_VFS,
	.flags = NEEDS_ROOT,
	.sanitise = sanitise_open_tree_attr,
	.post = post_mount_fd,
};
