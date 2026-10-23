/*
 * SYSCALL_DEFINE1(fchdir, unsigned int, fd)
 *
 * fd == FD_FAILFS_ROOT (-10004) reaches failfs_current_chdir() with no
 * capability, no_new_privs or fs->users guard, unlike fchroot's sentinel
 * branch.  ARG_FD never draws it, so the sanitiser names it explicitly.
 */
#include <fcntl.h>
#include <unistd.h>

#include "kernel/fcntl.h"
#include "rnd.h"
#include "sanitise.h"
#include "sanitiser-fd.h"
#include "tmpdir.h"

static void sanitise_fchdir(struct syscallrecord *rec)
{
	/*
	 * Split the fd draw three ways:
	 *
	 *   FD_FAILFS_ROOT  -- the unguarded branch; only reachable by
	 *                      naming the sentinel exactly.
	 *   a real dirfd    -- opens the trinity tmpdir O_PATH|O_DIRECTORY|
	 *                      O_CLOEXEC so d_can_lookup succeeds and the
	 *                      call reaches file_permission() instead of
	 *                      dying at the fd lookup.  This sanitiser runs
	 *                      in the child, before do_extrafork() forks, so
	 *                      the descriptor is the child's: .cleanup
	 *                      closes it.
	 *   untouched       -- whatever ARG_FD drew, keeping the -EBADF and
	 *                      -ENOTDIR reject arms live.
	 */
	switch (rnd_modulo_u32(3)) {
	case 0:
		rec->a1 = (unsigned long)(long)FD_FAILFS_ROOT;
		break;
	case 1: {
		int fd = open(trinity_tmpdir_abs(), O_PATH | O_DIRECTORY | O_CLOEXEC);

		if (fd >= 0) {
			sanitiser_own_fd(rec, fd);
			rec->a1 = (unsigned long)fd;
		}
		break;
	}
	default:
		break;
	}
}

struct syscallentry syscall_fchdir = {
	.name = "fchdir",
	.num_args = 1,
	.argtype = { [0] = ARG_FD },
	.argname = { [0] = "fd" },
	.rettype = RET_ZERO_SUCCESS,
	/* A successful failfs chdir is not a crash: the child keeps running
	 * while every AT_FDCWD-relative lookup fails EOPNOTSUPP and getcwd()
	 * reports an unreachable path, silently testing nothing for the rest
	 * of its life.  EXTRA_FORK confines that to a throwaway grandchild.
	 *
	 * EXTRA_FORK spawns a helper process per dispatch, the same explicit
	 * re-exec disqualifier execve carries: a re-exec would fork another
	 * grandchild.  AVOID_REEXEC is unconditional, so no later per-call
	 * REEXEC_OK publish can reopen it. */
	.flags = NEED_ALARM | EXTRA_FORK | AVOID_REEXEC,
	.group = GROUP_VFS_PATH,
	.sanitise = sanitise_fchdir,
	.cleanup = cleanup_sanitiser_fd,
};
