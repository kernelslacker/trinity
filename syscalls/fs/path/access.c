/*
 * SYSCALL_DEFINE2(access, const char __user *, filename, int, mode)
 *
 * On  success  (all requested permissions granted), zero is returned.
 * On error (at least one bit in mode asked for a permission that is denied,
 *  or some other error occurred), -1 is returned, and errno is set appropriately.
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
 * the same per-inode i_rwsem / inode_permission / ->permission path.
 */
#define NR_TESTFILES 4

static unsigned long access_modes[] = {
	F_OK, R_OK, W_OK, X_OK,
	R_OK | W_OK,
	R_OK | X_OK,
	W_OK | X_OK,
	R_OK | W_OK | X_OK,
	F_OK | X_OK,
};

static void sanitise_access(struct syscallrecord *rec)
{
	char *path;

	/*
	 * ARG_PATHNAME plumbed a random pathname into rec->a1, but the
	 * random path is most often not a real file at all -- access
	 * returns ENOENT at the path walk before ever reaching
	 * do_faccessat / inode_permission / inode_operations->permission
	 * on a real inode.  Classic "high calls, low edges" cold-syscall
	 * shape the chmod/chown/utime families were in before their
	 * testfile-pin fixes.
	 *
	 * Half the draws now repoint at one of the trinity-testfile<N>
	 * absolute paths so the subsequent access lands on a real
	 * trinity-owned inode and penetrates the VFS path -- the
	 * generic_permission check and the per-fs ->permission hook
	 * (which the mode bits R_OK/W_OK/X_OK from a2 actually exercise).
	 * The other half preserves the slot exactly as the generic draw
	 * left it, so the ENOENT reject arm stays exercised.
	 */
	if (rnd_modulo_u32(2) != 0)
		return;

	path = get_testfile_path();
	if (path == NULL)
		return;

	rec->a1 = (unsigned long) path;
}

struct syscallentry syscall_access = {
	.name = "access",
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_LIST },
	.argname = { [0] = "filename", [1] = "mode" },
	.arg_params[1].list = ARGLIST(access_modes),
	.group = GROUP_VFS,
	.rettype = RET_ZERO_SUCCESS,
	/*
	 * REEXEC_SANITISE_OK: access had no sanitise before this change so
	 * it was eligible for the CMP RedQueen re-exec step.  This
	 * sanitiser only rewrites an input pathname buffer in place --
	 * no nested pointer chains, no INOUT / output buffers, no
	 * shared-buffer relocation, no post_state oracle -- so opt back
	 * in explicitly and preserve the re-exec coverage that the
	 * blanket sanitise-bearing exclusion in redqueen_reexec_step()
	 * would otherwise drop.
	 */
	.flags = REEXEC_SANITISE_OK,
	.sanitise = sanitise_access,
};
