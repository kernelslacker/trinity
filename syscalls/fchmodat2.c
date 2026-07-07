/*
 * SYSCALL_DEFINE4(fchmodat2, int, dfd, const char __user *, filename,
 *		umode_t, mode, unsigned int, flags)
 */
#include <fcntl.h>
#include <stdio.h>
#include "compat.h"
#include "pathnames.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

#include "kernel/fcntl.h"
#define NR_TESTFILES 4		/* mirror fds/testfiles.c */

static unsigned long fchmodat2_flags[] = {
	AT_SYMLINK_NOFOLLOW,
	AT_EMPTY_PATH,
};

static void sanitise_fchmodat2(struct syscallrecord *rec)
{
	/*
	 * filename (a2): ARG_PATHNAME plumbed a random pathname into
	 * rec->a2, but it is almost never a real file, so fchmodat2
	 * returns ENOENT at the path walk before reaching the per-fs
	 * setattr.  Half the draws pin a2 to an absolute trinity-owned
	 * testfile so the call penetrates the VFS path; an absolute path
	 * ignores the dfd in a1, so no valid dirfd is needed.  The other
	 * half preserves the random pathname so the ENOENT / -ENOTDIR
	 * reject arms stay exercised.
	 */
	if (rec->a2 && rnd_modulo_u32(2) == 0) {
		char *path = get_testfile_path();

		if (path != NULL)
			rec->a2 = (unsigned long) path;
	}

	/*
	 * flags (a4): do_fchmodat rejects any bit outside
	 * (AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) with -EINVAL before
	 * touching the lookup path.  handle_arg_list's 1/8 shift_flag_bit
	 * and 1/16 cmp-hint paths regularly OR foreign bits into the
	 * draw, so the unbiased mix is dominated by the early -EINVAL
	 * bounce.  Strip stray bits on 7/8 of draws so most calls reach
	 * user_path_at -> chmod_common while leaving the reject path
	 * exercised on the remaining 1/8.
	 */
	if (!ONE_IN(8))
		rec->a4 &= (unsigned long)(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH);

	/*
	 * dfd (a1): ARG_FD draws from the full fd pool (regular files,
	 * pipes, sockets, ...).  When filename is relative the kernel
	 * does a dir-relative lookup against dfd and a non-directory fd
	 * is rejected with -ENOTDIR before chmod_common runs.  Pin to
	 * AT_FDCWD on 1/3 of draws so the relative-path fraction lands
	 * on a usable base while leaving the random-fd path well
	 * exercised for the absolute-pathname and AT_EMPTY_PATH shapes.
	 */
	if (ONE_IN(3))
		rec->a1 = (unsigned long)(long) AT_FDCWD;
}

struct syscallentry syscall_fchmodat2 = {
	.name = "fchmodat2",
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_MODE_T, [3] = ARG_LIST },
	.argname = { [0] = "dfd", [1] = "filename", [2] = "mode", [3] = "flags" },
	.arg_params[3].list = ARGLIST(fchmodat2_flags),
	.rettype = RET_ZERO_SUCCESS,
	.flags = REEXEC_SANITISE_OK,
	.group = GROUP_VFS,
	.sanitise = sanitise_fchmodat2,
};
