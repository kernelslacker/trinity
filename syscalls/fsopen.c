/*
 *  SYSCALL_DEFINE2(fsopen, const char __user *, _fs_name, unsigned int, flags)
 */
#include <string.h>
#include <unistd.h>
#include "object-types.h"
#include "random.h"
#include "sanitise.h"

/* Populated by mount.c constructor from /proc/filesystems. */
extern const char **filesystem_types;
extern unsigned int nr_filesystem_types;

#define FSOPEN_CLOEXEC 0x00000001
static unsigned long fsopen_flags[] = {
	FSOPEN_CLOEXEC
};

static void sanitise_fsopen(struct syscallrecord *rec)
{
	const char *fstype;
	char *name;

	if (nr_filesystem_types == 0)
		return;

	fstype = filesystem_types[rand() % nr_filesystem_types];
	name = (char *) get_writable_struct(32);
	if (!name)
		return;
	strncpy(name, fstype, 31);
	name[31] = '\0';

	rec->a1 = (unsigned long) name;
}

struct syscallentry syscall_fsopen = {
	.name = "fsopen",
	.num_args = 2,
	.argtype = { [1] = ARG_OP },
	.argname = { [0] = "_fs_name", [1] = "flags" },
	.arg_params[1].list = ARGLIST(fsopen_flags),
	.rettype = RET_FD,
	.ret_objtype = OBJ_FD_FS_CTX,
	.group = GROUP_VFS,
	.flags = NEEDS_ROOT,
	.sanitise = sanitise_fsopen,
};
