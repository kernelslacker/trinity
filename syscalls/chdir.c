/*
 * SYSCALL_DEFINE1(chdir, const char __user *, filename)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include <stdio.h>
#include "pathnames.h"
#include "rnd.h"
#include "sanitise.h"
#include "trinity.h"

static void sanitise_chdir(struct syscallrecord *rec)
{
	char *path;

	/*
	 * ARG_PATHNAME plumbed a random pathname into rec->a1, but the
	 * random path is most often not a real directory -- chdir
	 * returns ENOENT (or ENOTDIR) at the path walk before ever
	 * reaching set_fs_pwd / inode_permission and the per-inode
	 * MAY_EXEC permission check that guards the cwd update.
	 * Classic "high calls, low edges" cold-syscall shape.
	 *
	 * Half the draws now repoint at the trinity tmpdir itself --
	 * an actual directory we own -- so the subsequent chdir lands
	 * on a real inode and penetrates the VFS path: the path walk
	 * succeeds, inode_permission's MAY_EXEC check runs, and
	 * set_fs_pwd swaps the task's fs->pwd under fs->lock.  The
	 * other half preserves the slot exactly as the generic draw
	 * left it, so the ENOENT/ENOTDIR reject arm stays exercised.
	 *
	 * Pin to the tmpdir directory itself (not a trinity-testfile<N>
	 * regular file as chmod/chown do); a regular file would just
	 * make chdir return ENOTDIR and defeat the point of the pin.
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
	snprintf(path, MAX_PATH_LEN, "%s", trinity_tmpdir_abs());
}

struct syscallentry syscall_chdir = {
	.name = "chdir",
	.num_args = 1,
	.argtype = { [0] = ARG_PATHNAME },
	.argname = { [0] = "filename" },
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
	/*
	 * REEXEC_SANITISE_OK: chdir had no sanitise before this change so
	 * it was eligible for the CMP RedQueen re-exec step.  This
	 * sanitiser only rewrites an input pathname buffer in place --
	 * no nested pointer chains, no INOUT / output buffers, no
	 * shared-buffer relocation, no post_state oracle -- so opt back
	 * in explicitly and preserve the re-exec coverage that the
	 * blanket sanitise-bearing exclusion in redqueen_reexec_step()
	 * would otherwise drop.
	 */
	.flags = REEXEC_SANITISE_OK,
	.sanitise = sanitise_chdir,
};
