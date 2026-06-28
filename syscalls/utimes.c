/*
 * SYSCALL_DEFINE2(utimes, char __user *, filename, struct timeval __user *, utimes)
 */
#include <stdio.h>
#include "pathnames.h"
#include "rnd.h"
#include "sanitise.h"
#include "trinity.h"

/*
 * Mirrors the MAX_TESTFILES bound in fds/testfiles.c so we land inside
 * the same trinity-testfile<N> inodes the rest of the path-pinned
 * sanitisers (xattr-thrash, flock-thrash, utime, utimensat, chown, ...)
 * touch; cross-process contention concentrates on the same per-inode
 * i_rwsem / timestamp-update path.
 */
#define NR_TESTFILES 4

static void sanitise_utimes(struct syscallrecord *rec)
{
	char *path;

	/*
	 * ARG_PATHNAME plumbed a random pathname into rec->a1, but the
	 * random path is most often not a real file at all -- utimes
	 * returns ENOENT at the path walk before ever reaching
	 * notify_change / inode_operations->setattr and the per-fs
	 * timestamp-update path.  The timeval pair at rec->a2 is auto-
	 * filled with arbitrary values that the kernel accepts
	 * unconditionally, so the struct is not the limiter -- the path
	 * is.  Same "high calls, low edges" cold-syscall shape the xattr,
	 * utime, utimensat, and chmod/chown families were in before their
	 * testfile-pin fixes.
	 *
	 * Half the draws now repoint at one of the trinity-testfile<N>
	 * absolute paths so the subsequent utimes lands on a real
	 * trinity-owned inode and penetrates the VFS path -- the
	 * permission check, notify_change, and the per-fs setattr that
	 * the i_rwsem guards.  The other half preserves the slot exactly
	 * as the generic draw left it, so the ENOENT reject arm stays
	 * exercised.
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

struct syscallentry syscall_utimes = {
	.name = "utimes",
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_TIME,
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_ADDRESS },
	.argname = { [0] = "filename", [1] = "utimes" },
	/*
	 * REEXEC_SANITISE_OK: utimes had no sanitise before this change so
	 * it was eligible for the CMP RedQueen re-exec step.  This
	 * sanitiser only rewrites an input pathname buffer in place --
	 * no nested pointer chains, no INOUT / output buffers, no
	 * shared-buffer relocation, no post_state oracle -- so opt back
	 * in explicitly and preserve the re-exec coverage that the
	 * blanket sanitise-bearing exclusion in redqueen_reexec_step()
	 * would otherwise drop.
	 */
	.flags = REEXEC_SANITISE_OK,
	.sanitise = sanitise_utimes,
};
