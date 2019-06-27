/*
 *  SYSCALL_DEFINE3(open_tree, int, dfd, const char *, filename, unsigned, flags)
 */
#include "sanitise.h"
#include <fcntl.h>

#ifndef OPEN_TREE_CLONE
#define OPEN_TREE_CLONE         1               /* Clone the target tree and attach the clone */
#define OPEN_TREE_CLOEXEC       O_CLOEXEC       /* Close the file on execve() */
#endif

#ifndef AT_RECURSIVE
#define AT_RECURSIVE            0x8000  /* Apply to the entire subtree */
#endif

static unsigned long open_tree_flags[] = {
	AT_EMPTY_PATH, AT_NO_AUTOMOUNT, AT_RECURSIVE, AT_SYMLINK_NOFOLLOW,
	OPEN_TREE_CLONE, OPEN_TREE_CLOEXEC,
};

struct syscallentry syscall_open_tree = {
	.name = "open_tree",
	.num_args = 3,
	.arg1name = "dfd",
	.arg1type = ARG_FD,
	.arg2name = "filename",
	.arg2type = ARG_PATHNAME,
	.arg3name = "flags",
	.arg3type = ARG_OP,
	.arg3list = ARGLIST(open_tree_flags),
};
