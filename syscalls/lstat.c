/*
 * SYSCALL_DEFINE2(lstat, const char __user *, filename,
                   struct __old_kernel_stat __user *, statbuf)
 */
#include "arch.h"
#include "pathnames.h"
#include "rnd.h"
#include "sanitise.h"
#include "trinity.h"

/*
 * Mirrors the MAX_TESTFILES bound in fds/testfiles.c so we land inside
 * the same trinity-testfile<N> inodes the rest of the path-pinned
 * sanitisers (chmod, utime, stat, ...) touch; cross-process contention
 * concentrates on the same per-inode i_rwsem / getattr path.
 */
#define NR_TESTFILES 4

static void sanitise_lstat_buf(struct syscallrecord *rec)
{
	char *path;

	avoid_shared_buffer_out(&rec->a2, page_size);

	/*
	 * ARG_PATHNAME plumbed a random pathname into rec->a1, but the
	 * random path is most often not a real file at all -- lstat
	 * returns ENOENT at the path walk before ever reaching the
	 * per-fs inode_operations->getattr path under i_rwsem.  Same
	 * "high calls, low edges" cold-syscall shape stat was in before
	 * its testfile-pin fix.
	 *
	 * Half the draws now repoint at one of the trinity-testfile<N>
	 * absolute paths so the subsequent lstat lands on a real
	 * trinity-owned inode and penetrates the VFS path -- the namei
	 * walk to a real dentry, the permission check (trinity owns
	 * these inodes so the ownership/permission gates pass), and the
	 * per-fs getattr that the i_rwsem guards.  The other half
	 * preserves the slot exactly as the generic draw left it, so the
	 * ENOENT reject arm stays exercised.
	 *
	 * Pin lives in the shared sanitiser so both syscall_lstat and
	 * syscall_lstat64 inherit the same behaviour.
	 */
	if (rnd_modulo_u32(2) != 0)
		return;

	path = (char *) rec->a1;
	if (path == NULL)
		return;

	/*
	 * Overwrite the ARG_PATHNAME buffer in place.  generate_pathname()
	 * zmallocs MAX_PATH_LEN (4096) bytes, so the snprintf cap below
	 * cannot overflow.
	 */
	snprintf(path, MAX_PATH_LEN, "%s/trinity-testfile%u",
		 trinity_tmpdir_abs(), 1 + rnd_modulo_u32(NR_TESTFILES));
}

struct syscallentry syscall_lstat = {
	.name = "lstat",
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "filename", [1] = "statbuf" },
	.sanitise = sanitise_lstat_buf,
	.group = GROUP_VFS,
	.rettype = RET_ZERO_SUCCESS,
	.flags = REEXEC_SANITISE_OK,
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
	.rettype = RET_ZERO_SUCCESS,
	.flags = REEXEC_SANITISE_OK,
};
