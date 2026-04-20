/*
 * SYSCALL_DEFINE2(lstat, const char __user *, filename,
                   struct __old_kernel_stat __user *, statbuf)
 */
#include "arch.h"
#include "sanitise.h"

static void sanitise_lstat_buf(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a2, page_size);
}

struct syscallentry syscall_lstat = {
	.name = "lstat",
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "filename", [1] = "statbuf" },
	.sanitise = sanitise_lstat_buf,
	.group = GROUP_VFS,
};


/*
 * SYSCALL_DEFINE2(lstat64, const char __user *, filename,
                 struct stat64 __user *, statbuf)
 */

struct syscallentry syscall_lstat64 = {
	.name = "lstat64",
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "filename", [1] = "statbuf" },
	.sanitise = sanitise_lstat_buf,
	.group = GROUP_VFS,
};
