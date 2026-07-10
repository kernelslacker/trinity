/*
 * SYSCALL_DEFINE1(chroot, const char __user *, filename)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include <stdio.h>
#include "pathnames.h"
#include "rnd.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

static void sanitise_chroot(struct syscallrecord *rec)
{
	char *path;

	/*
	 * ARG_PATHNAME plumbed a random pathname into rec->a1, but the
	 * random path is most often not a real directory -- chroot
	 * returns ENOTDIR at the path walk before ever reaching
	 * set_fs_root / inode_permission and the MAY_EXEC check that
	 * guards the root swap.  Classic "high calls, low edges"
	 * cold-syscall shape.
	 *
	 * Half the draws now repoint at the trinity tmpdir itself --
	 * an actual directory we own -- so the subsequent chroot lands
	 * on a real inode and penetrates the VFS path: the path walk
	 * succeeds, inode_permission's MAY_EXEC check runs, and
	 * set_fs_root swaps the task's fs->root under fs->lock.  The
	 * other half preserves the slot exactly as the generic draw
	 * left it, so the ENOENT/ENOTDIR reject arm stays exercised.
	 *
	 * Pin to the tmpdir directory itself; a regular file would just
	 * make chroot return ENOTDIR and defeat the point of the pin.
	 */
	if (rnd_modulo_u32(2) != 0)
		return;

	/*
	 * Allocate a fresh MAX_PATH_LEN buffer and repoint rec->a1 at it
	 * instead of snprintf'ing into the slot in place.  ARG_PATHNAME
	 * does not guarantee a >=MAX_PATH_LEN backing chunk for every
	 * source (corpus/mutation paths can be much smaller), so an
	 * in-place write would overrun a small heap chunk and corrupt
	 * glibc metadata.
	 */
	path = zmalloc_tracked(MAX_PATH_LEN);
	if (path == NULL)
		return;

	snprintf(path, MAX_PATH_LEN, "%s", trinity_tmpdir_abs());
	rec->a1 = (unsigned long) path;
}

struct syscallentry syscall_chroot = {
	.name = "chroot",
	.num_args = 1,
	.argtype = { [0] = ARG_PATHNAME },
	.argname = { [0] = "filename" },
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
	/*
	 * REEXEC_SANITISE_OK: chroot had no sanitise before this change
	 * so it was eligible for the CMP RedQueen re-exec step.  This
	 * sanitiser only rewrites an input pathname buffer -- no nested
	 * pointer chains, no INOUT / output buffers, no shared-buffer
	 * relocation, no post_state oracle -- so opt back in explicitly
	 * and preserve the re-exec coverage that the blanket
	 * sanitise-bearing exclusion in redqueen_reexec_step() would
	 * otherwise drop.
	 */
	.flags = NEEDS_ROOT | REEXEC_SANITISE_OK,
	.sanitise = sanitise_chroot,
};
