/*
 * SYSCALL_DEFINE3(lchown, const char __user *, filename, uid_t, user, gid_t, group)
 */
#include <stdio.h>
#include "pathnames.h"
#include "rnd.h"
#include "sanitise.h"
#include "trinity.h"

/*
 * Mirrors the MAX_TESTFILES bound in fds/testfiles.c so we land inside
 * the same trinity-testfile<N> inodes the rest of the path-pinned
 * sanitisers (chmod, chown, utime, utimensat, xattr-thrash,
 * flock-thrash, ...) touch; cross-process contention concentrates on
 * the same per-inode i_rwsem / notify_change / setattr path.
 */
#define NR_TESTFILES 4

static void sanitise_lchown(struct syscallrecord *rec)
{
	char *path;

	/*
	 * ARG_PATHNAME plumbed a random pathname into rec->a1, but the
	 * random path is most often not a real file at all -- lchown
	 * returns ENOENT at the path walk before ever reaching
	 * chown_common / notify_change / inode_operations->setattr and
	 * the i_rwsem-guarded per-inode ownership-update path.  Classic
	 * "high calls, low edges" cold-syscall shape the chown/xattr and
	 * utime families were in before their testfile-pin fixes.
	 *
	 * Half the draws now repoint at one of the trinity-testfile<N>
	 * absolute paths so the subsequent lchown lands on a real
	 * trinity-owned inode and penetrates the VFS path -- the
	 * permission check (trinity owns these inodes so the
	 * ownership/permission gates pass), notify_change, and the
	 * per-fs setattr that the i_rwsem guards.  Unlike chown, lchown
	 * does NOT dereference a final symlink, so the setattr lands on
	 * the named inode itself; the trinity-testfile<N> targets are
	 * regular files so the path walk reaches them either way.
	 * The other half preserves the slot exactly as the generic draw
	 * left it, so the ENOENT reject arm stays exercised.
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

struct syscallentry syscall_lchown = {
	.name = "lchown",
	.num_args = 3,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_RANGE, [2] = ARG_RANGE },
	.argname = { [0] = "filename", [1] = "user", [2] = "group" },
	.arg_params[1].range.low = 0,
	.arg_params[1].range.hi = 65535,
	.arg_params[2].range.low = 0,
	.arg_params[2].range.hi = 65535,
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
	/*
	 * REEXEC_SANITISE_OK: lchown had no sanitise before this change so
	 * it was eligible for the CMP RedQueen re-exec step.  This
	 * sanitiser only rewrites an input pathname buffer in place --
	 * no nested pointer chains, no INOUT / output buffers, no
	 * shared-buffer relocation, no post_state oracle -- so opt back
	 * in explicitly and preserve the re-exec coverage that the
	 * blanket sanitise-bearing exclusion in redqueen_reexec_step()
	 * would otherwise drop.
	 */
	.flags = REEXEC_SANITISE_OK,
	.sanitise = sanitise_lchown,
};

/*
 * SYSCALL_DEFINE3(lchown16, const char __user *, filename, old_uid_t, user, old_gid_t, group)
 */

struct syscallentry syscall_lchown16 = {
	.name = "lchown16",
	.num_args = 3,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_RANGE, [2] = ARG_RANGE },
	.argname = { [0] = "filename", [1] = "user", [2] = "group" },
	.arg_params[1].range.low = 0,
	.arg_params[1].range.hi = 65535,
	.arg_params[2].range.low = 0,
	.arg_params[2].range.hi = 65535,
	.group = GROUP_VFS,
	.flags = REEXEC_SANITISE_OK,
	.sanitise = sanitise_lchown,
};
