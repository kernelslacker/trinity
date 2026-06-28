/*
 * SYSCALL_DEFINE3(inotify_add_watch, int, fd, const char __user *, pathname, u32, mask)
 */
#include <limits.h>
#include <sys/inotify.h>
#include <stdio.h>

#include "pathnames.h"
#include "rnd.h"
#include "sanitise.h"
#include "compat.h"
#include "trinity.h"

static unsigned long inotify_add_watch_masks[] = {
	IN_ACCESS, IN_MODIFY, IN_ATTRIB, IN_CLOSE_WRITE,
	IN_CLOSE_NOWRITE, IN_OPEN, IN_MOVED_FROM, IN_MOVED_TO,
	IN_CREATE, IN_DELETE, IN_DELETE_SELF, IN_MOVE_SELF,
	IN_UNMOUNT, IN_Q_OVERFLOW, IN_IGNORED, IN_ONLYDIR,
	IN_DONT_FOLLOW, IN_EXCL_UNLINK, IN_MASK_ADD, IN_ISDIR,
	IN_ONESHOT, IN_MASK_CREATE,
};

static void post_inotify_add_watch(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	if (ret < 1 || ret > INT_MAX) {
		if (ret >= 0)
			output(0, "inotify_add_watch oracle: returned watch descriptor %ld is out of range (must be 1..INT_MAX)\n",
				ret);
		return;
	}

	inotify_rm_watch((int) rec->a1, (int) ret);
}

/*
 * Mirrors the MAX_TESTFILES bound in fds/testfiles.c so we land inside
 * the same trinity-testfile<N> inodes the rest of the path-pinned
 * sanitisers (xattr-family, utime/utimensat, ...) touch; cross-process
 * contention concentrates on the same set of real inodes.
 */
#define NR_TESTFILES 4

static void sanitise_inotify_add_watch(struct syscallrecord *rec)
{
	char *path;

	/*
	 * ARG_PATHNAME plumbed a random pathname into rec->a2, but the
	 * random path is most often not a real file -- the path walk
	 * fails with ENOENT before inotify_find_inode ever runs, so
	 * inotify_add_to_idr and the fsnotify mark-on-inode path stay
	 * cold.  Same "high calls, low edges" shape the xattr family
	 * and the utime/utimensat pair were in before their path pins.
	 *
	 * Half the draws now repoint a2 at one of the trinity-testfile<N>
	 * absolute paths so the subsequent inotify_add_watch lands on a
	 * real trinity-owned inode and reaches inotify_find_inode ->
	 * inotify_add_to_idr, installing an fsnotify mark the .post
	 * handler then removes via inotify_rm_watch.  The other half
	 * preserves a2 exactly as the generic draw left it so the
	 * ENOENT path-walk reject arm stays exercised.
	 */
	if (rnd_modulo_u32(2) != 0)
		return;

	path = (char *) rec->a2;
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

struct syscallentry syscall_inotify_add_watch = {
	.name = "inotify_add_watch",
	.num_args = 3,
	.argtype = { [0] = ARG_FD_INOTIFY, [1] = ARG_PATHNAME, [2] = ARG_LIST },
	.argname = { [0] = "fd", [1] = "pathname", [2] = "mask" },
	.arg_params[2].list = ARGLIST(inotify_add_watch_masks),
	/*
	 * REEXEC_SANITISE_OK: this sanitiser only rewrites the ARG_PATHNAME
	 * input buffer in place -- no nested pointer chains, no INOUT /
	 * output buffers, no shared-buffer relocation, no post_state oracle
	 * -- so opt back in explicitly to preserve the CMP RedQueen re-exec
	 * coverage that the blanket sanitise-bearing exclusion in
	 * redqueen_reexec_step() would otherwise drop.
	 */
	.flags = NEED_ALARM | REEXEC_SANITISE_OK,
	.group = GROUP_VFS,
	.sanitise = sanitise_inotify_add_watch,
	.post = post_inotify_add_watch,
};
