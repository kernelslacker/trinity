/*
 * SYSCALL_DEFINE2(truncate, const char __user *, path, long, length)
 */
#include "sanitise.h"

struct syscallentry syscall_truncate = {
	.name = "truncate",
	.num_args = 2,
	.arg1name = "path",
	.arg1type = ARG_PATHNAME,
	.arg2name = "length",
	.arg2type = ARG_LEN,
	.group = GROUP_VFS,
};

/*
 * SYSCALL_DEFINE(truncate64)(const char __user * path, loff_t length)
 */

struct syscallentry syscall_truncate64 = {
	.name = "truncate64",
	.num_args = 2,
	.arg1name = "path",
	.arg1type = ARG_PATHNAME,
	.arg2name = "length",
	.arg2type = ARG_LEN,
	.group = GROUP_VFS,
};
