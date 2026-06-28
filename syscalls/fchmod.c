/*
 * SYSCALL_DEFINE2(fchmod, unsigned int, fd, mode_t, mode)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include "pathnames.h"
#include "rnd.h"
#include "sanitise.h"
#include "trinity.h"

struct syscallentry syscall_fchmod = {
	.name = "fchmod",
	.num_args = 2,
	.argtype = { [0] = ARG_FD, [1] = ARG_MODE_T },
	.argname = { [0] = "fd", [1] = "mode" },
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};


/*
 * SYSCALL_DEFINE3(fchmodat, int, dfd, const char __user *, filename, mode_t, mode)
 *
 * On success, fchmodat() returns 0.
 * On error, -1 is returned and errno is set to indicate the error.
 */

/*
 * Mirrors the MAX_TESTFILES bound in fds/testfiles.c so we land inside
 * the same trinity-testfile<N> inodes the other path-pinned sanitisers
 * (chmod, utime, utimensat, ...) touch.
 */
#define NR_TESTFILES 4

static void sanitise_fchmodat(struct syscallrecord *rec)
{
	char *path;

	/*
	 * ARG_PATHNAME plumbed a random pathname into rec->a2, but it
	 * is almost never a real file, so fchmodat returns ENOENT at
	 * the path walk before reaching the per-fs setattr.  Half the
	 * draws pin a2 to an absolute trinity-owned testfile so the
	 * call penetrates the VFS path; an absolute path ignores the
	 * dfd in a1, so no valid dirfd is needed.  The other half
	 * preserves the random pathname so the ENOENT / -ENOTDIR
	 * reject arms stay exercised.
	 */
	if (rnd_modulo_u32(2) != 0)
		return;

	path = (char *) rec->a2;
	if (path == NULL)
		return;

	snprintf(path, MAX_PATH_LEN, "%s/trinity-testfile%u",
		 trinity_tmpdir_abs(), 1 + rnd_modulo_u32(NR_TESTFILES));
}

struct syscallentry syscall_fchmodat = {
	.name = "fchmodat",
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_MODE_T },
	.argname = { [0] = "dfd", [1] = "filename", [2] = "mode" },
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	.sanitise = sanitise_fchmodat,
};
