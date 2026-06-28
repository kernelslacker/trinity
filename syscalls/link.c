/*
 * SYSCALL_DEFINE2(link, const char __user *, oldname, const char __user *, newname)
 */
#include <stdio.h>
#include "pathnames.h"
#include "rnd.h"
#include "sanitise.h"
#include "trinity.h"

/*
 * Mirrors the MAX_TESTFILES bound in fds/testfiles.c so we land inside
 * the same trinity-testfile<N> inodes the rest of the path-pinned
 * sanitisers (chmod, utime, utimensat, xattr-thrash, flock-thrash, ...)
 * touch; cross-process contention concentrates on the same per-inode
 * i_rwsem / vfs_link path.
 */
#define NR_TESTFILES 4

static void sanitise_link(struct syscallrecord *rec)
{
	char *path;

	/*
	 * ARG_PATHNAME plumbed a random pathname into rec->a1 (oldname),
	 * but the random path is most often not a real file at all --
	 * link() returns ENOENT at the source path walk before ever
	 * reaching vfs_link / inode_operations->link and the i_rwsem-
	 * guarded per-inode hardlink path.  Classic "high calls, low
	 * edges" cold-syscall shape the chmod / xattr / utime families
	 * were in before their testfile-pin fixes.
	 *
	 * Half the draws now repoint rec->a1 at one of the trinity-
	 * testfile<N> absolute paths so the subsequent link() source
	 * walk lands on a real trinity-owned inode and penetrates the
	 * VFS path -- may_linkat, vfs_link, the per-fs ->link operation,
	 * and the directory i_rwsem the target newname will hash into.
	 * The other half preserves the slot exactly as the generic draw
	 * left it, so the ENOENT reject arm stays exercised.
	 *
	 * rec->a2 (newname) is left untouched: it stays random so the
	 * target directory walk and dentry-creation paths see a wide
	 * spread of names (EEXIST, ENOENT-on-parent, EXDEV, EPERM-on-
	 * sticky, ...).  A hardlink does NOT consume the source inode,
	 * so the testfile pool survives; a stray newname left in the
	 * tmpdir is benign and recycled by trinity_tmpdir cleanup.
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

struct syscallentry syscall_link = {
	.name = "link",
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_PATHNAME },
	.argname = { [0] = "oldname", [1] = "newname" },
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
	/*
	 * REEXEC_SANITISE_OK: link had no sanitise before this change so
	 * it was eligible for the CMP RedQueen re-exec step.  This
	 * sanitiser only rewrites an input pathname buffer in place --
	 * no nested pointer chains, no INOUT / output buffers, no
	 * shared-buffer relocation, no post_state oracle -- so opt back
	 * in explicitly and preserve the re-exec coverage that the
	 * blanket sanitise-bearing exclusion in redqueen_reexec_step()
	 * would otherwise drop.
	 */
	.flags = REEXEC_SANITISE_OK,
	.sanitise = sanitise_link,
};
