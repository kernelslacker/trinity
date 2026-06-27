/*
 * SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)
 *
 * On success, (all requested permissions granted) faccessat() returns 0.
 * On error, -1 is returned and errno is set to indicate the error.
 */
#include <stdio.h>
#include <unistd.h>
#include "compat.h"
#include "pathnames.h"
#include "rnd.h"
#include "sanitise.h"
#include "trinity.h"

/*
 * Mirrors the MAX_TESTFILES bound in fds/testfiles.c so we land inside
 * the same trinity-testfile<N> inodes the rest of the path-pinned
 * sanitisers touch; cross-process contention concentrates on the same
 * per-inode permission / inode_permission path.
 */
#define NR_TESTFILES 4

static unsigned long access_modes[] = {
	F_OK, R_OK, W_OK, X_OK,
};

/*
 * ARG_PATHNAME plumbed a random pathname into rec->a2, but the random
 * path is most often not a real file at all -- faccessat returns ENOENT
 * at the path walk before ever reaching inode_permission and the per-fs
 * permission hook.  Pin half the draws to a trinity-owned testfile (an
 * absolute path, so the dfd at rec->a1 is irrelevant) so the call
 * actually penetrates the VFS permission path; the other half preserves
 * the slot exactly as the generic draw left it, keeping the ENOENT
 * reject arm warm.
 */
static void sanitise_faccessat(struct syscallrecord *rec)
{
	char *path;

	if (rnd_modulo_u32(2) != 0)
		return;

	path = (char *) rec->a2;
	if (path == NULL)
		return;

	/*
	 * generate_pathname() zmallocs MAX_PATH_LEN (4096) bytes, so the
	 * snprintf cap below cannot overflow.
	 */
	snprintf(path, MAX_PATH_LEN, "%s/trinity-testfile%u",
		 trinity_tmpdir_abs(), 1 + rnd_modulo_u32(NR_TESTFILES));
}

/*
 * REEXEC_SANITISE_OK: this sanitiser only rewrites an input pathname
 * buffer in place -- no nested pointer chains, no INOUT / output
 * buffers, no shared-buffer relocation, no post_state oracle -- so opt
 * back in explicitly and preserve the re-exec coverage that the blanket
 * sanitise-bearing exclusion in redqueen_reexec_step() would otherwise
 * drop.
 */
struct syscallentry syscall_faccessat = {
	.name = "faccessat",
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_LIST },
	.argname = { [0] = "dfd", [1] = "filename", [2] = "mode" },
	.arg_params[2].list = ARGLIST(access_modes),
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM | REEXEC_SANITISE_OK,
	.sanitise = sanitise_faccessat,
	.group = GROUP_VFS,
};

#define AT_FDCWD                -100    /* Special value used to indicate
                                           openat should use the current
                                           working directory. */
#define AT_EACCESS              0x200   /* Test access permitted for
                                           effective IDs, not real IDs.  */

static unsigned long faccessat2_flags[] = {
	AT_SYMLINK_NOFOLLOW, AT_EACCESS, AT_EMPTY_PATH,
};

struct syscallentry syscall_faccessat2 = {
	.name = "faccessat2",
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_LIST, [3] = ARG_LIST },
	.argname = { [0] = "dfd", [1] = "filename", [2] = "mode", [3] = "flags" },
	.arg_params[2].list = ARGLIST(access_modes),
	.arg_params[3].list = ARGLIST(faccessat2_flags),
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM | REEXEC_SANITISE_OK,
	.sanitise = sanitise_faccessat,
	.group = GROUP_VFS,
};
