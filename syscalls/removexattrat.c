/*
 * SYSCALL_DEFINE4(removexattrat, int, dfd, const char __user *, pathname,
 *		unsigned int, at_flags, const char __user *, name)
 */
#include <fcntl.h>
#include "sanitise.h"
#include "xattr.h"
#include "compat.h"

static unsigned long removexattrat_at_flags[] = {
	AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH,
};

static void sanitise_removexattrat(struct syscallrecord *rec)
{
	char *name = (char *) get_writable_address(256);
	gen_xattr_name(name, 256);
	rec->a4 = (unsigned long) name;
}

struct syscallentry syscall_removexattrat = {
	.name = "removexattrat",
	.num_args = 4,
	.arg1name = "dfd",
	.arg1type = ARG_FD,
	.arg2name = "pathname",
	.arg2type = ARG_PATHNAME,
	.arg3name = "at_flags",
	.arg3type = ARG_LIST,
	.arg3list = ARGLIST(removexattrat_at_flags),
	.arg4name = "name",
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
	.sanitise = sanitise_removexattrat,
};
