/*
 * SYSCALL_DEFINE1(fchdir, unsigned int, fd)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 *
 * Linux 7.3 (same failfs series as fchroot): fchdir gained a sentinel
 * branch triggered by fd == FD_FAILFS_ROOT (-10004) that calls
 * failfs_current_chdir() with no capability test, no no_new_privs
 * check, and no fs->users or current_chrooted() guard whatsoever.
 * Any caller that supplies that exact fd value reaches it.  Compare
 * fchroot's FD_FAILFS_ROOT branch in the same series: it sits behind
 * a four-condition guard requiring either CAP_SYS_CHROOT or the
 * conjunction of no_new_privs, fs->users == 1, and
 * !current_chrooted().  Same sentinel, same series, sibling syscalls,
 * completely different permission models.  The unguarded one is the
 * one a fuzzer cannot reach by default.
 *
 * ARG_FD draws from the open-fd pool; -10004 never appears there, so
 * the failfs branch is cold by construction unless the sanitiser names
 * it explicitly.  The three-way split below keeps every arm reachable.
 *
 * EXTRA_FORK because the failure mode of a successful failfs chdir is
 * not a crash -- it is a child that keeps running while every
 * AT_FDCWD-relative lookup returns EOPNOTSUPP and getcwd() returns
 * "(unreachable)".  That child silently stops testing anything useful
 * for the rest of its life, turning coverage into noise.  Wrapping the
 * call in a throwaway grandchild confines the poisoned working
 * directory to a process that exits immediately, leaving the parent
 * unaffected.
 */
#include <fcntl.h>
#include <unistd.h>

#include "kernel/fcntl.h"
#include "rnd.h"
#include "sanitise.h"
#include "trinity.h"

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
	 *                      dying at the fd lookup.  Leaked deliberately:
	 *                      this runs in the EXTRA_FORK grandchild, which
	 *                      _exit()s straight after the call, so the
	 *                      descriptor dies with the process.
	 *   untouched       -- whatever ARG_FD drew, keeping the -EBADF and
	 *                      -ENOTDIR reject arms live.
	 */
	switch (rnd_modulo_u32(3)) {
	case 0:
		rec->a1 = (unsigned long)(long)FD_FAILFS_ROOT;
		break;
	case 1: {
		int fd = open(trinity_tmpdir_abs(), O_PATH | O_DIRECTORY | O_CLOEXEC);

		if (fd >= 0)
			rec->a1 = (unsigned long)fd;
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
	.flags = NEED_ALARM | EXTRA_FORK,
	.group = GROUP_VFS_PATH,
	.sanitise = sanitise_fchdir,
};
