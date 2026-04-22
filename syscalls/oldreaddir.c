/*
 * SYSCALL_DEFINE3(old_readdir, unsigned int, fd,
                 struct old_linux_dirent __user *, dirent, unsigned int, count)
 */
#include "arch.h"
#include "sanitise.h"

static void sanitise_oldreaddir(struct syscallrecord *rec)
{
	/*
	 * old_readdir writes a single struct old_linux_dirent into a2.
	 * It ignores count beyond a non-zero check, so use a page as the
	 * conservative upper bound (matches what getdents/readlink fall
	 * back to when the fuzzer hands them a zero count).
	 */
	avoid_shared_buffer(&rec->a2, page_size);
}

struct syscallentry syscall_oldreaddir = {
	.name = "old_readdir",
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_LEN },
	.argname = { [0] = "fd", [1] = "dirent", [2] = "count" },
	.sanitise = sanitise_oldreaddir,
	.group = GROUP_VFS,
};
